use anyhow::{Context, Result};
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use std::collections::{BTreeMap, HashSet};
use std::time::SystemTime;

pub const ROOT_INODE: u64 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectMeta {
    pub key: String,
    pub size: u64,
    pub modified: SystemTime,
    pub etag: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Node {
    pub inode: u64,
    pub parent: u64,
    pub name: String,
    pub modified: SystemTime,
    pub kind: NodeKind,
}

#[derive(Clone, Debug)]
pub enum NodeKind {
    Directory {
        children: BTreeMap<String, u64>,
    },
    File {
        key: String,
        size: u64,
        etag: Option<String>,
    },
}

#[derive(Debug)]
pub struct Tree {
    nodes: BTreeMap<u64, Node>,
    next_inode: u64,
    skipped_invalid: usize,
    hidden_conflicts: usize,
}

#[derive(Clone, Debug)]
pub struct Pruner {
    denied: GlobSet,
}

impl Pruner {
    pub fn new(patterns: &[String]) -> Result<Self> {
        let mut builder = GlobSetBuilder::new();
        for pattern in patterns {
            let normalized = pattern.trim_matches('/');
            if normalized.is_empty() {
                anyhow::bail!(
                    "empty deny-directory pattern is not allowed (it would hide the root)"
                );
            }
            builder.add(directory_glob(normalized, pattern)?);
            // `foo/**` intuitively denies foo itself as well as its descendants.
            if let Some(parent) = normalized.strip_suffix("/**") {
                if !parent.is_empty() {
                    builder.add(directory_glob(parent, pattern)?);
                }
            }
        }
        Ok(Self {
            denied: builder.build()?,
        })
    }

    pub fn denies(&self, relative_directory: &str) -> bool {
        self.denied.is_match(relative_directory.trim_matches('/'))
    }
}

fn directory_glob(pattern: &str, original: &str) -> Result<globset::Glob> {
    GlobBuilder::new(pattern)
        .literal_separator(true)
        .build()
        .with_context(|| format!("invalid deny-directory glob {original:?}"))
}

impl Tree {
    pub fn from_objects(
        objects: impl IntoIterator<Item = ObjectMeta>,
        prefix: &str,
        pruner: &Pruner,
    ) -> Self {
        let objects = objects.into_iter().collect::<Vec<_>>();
        let denied_final_directories = denied_final_directories(&objects, prefix, pruner);
        let now = SystemTime::now();
        let root = Node {
            inode: ROOT_INODE,
            parent: ROOT_INODE,
            name: String::new(),
            modified: now,
            kind: NodeKind::Directory {
                children: BTreeMap::new(),
            },
        };
        let mut tree = Self {
            nodes: BTreeMap::from([(ROOT_INODE, root)]),
            next_inode: ROOT_INODE + 1,
            skipped_invalid: 0,
            hidden_conflicts: 0,
        };
        for object in objects {
            tree.insert_object(object, prefix, pruner, &denied_final_directories);
        }
        tree
    }

    fn insert_object(
        &mut self,
        object: ObjectMeta,
        prefix: &str,
        pruner: &Pruner,
        denied_final_directories: &HashSet<String>,
    ) {
        let Some(relative) = object.key.strip_prefix(prefix) else {
            return;
        };
        let relative = relative.to_string();
        if relative.is_empty() {
            return;
        }
        let is_directory_marker = relative.ends_with('/');
        let components: Vec<&str> = relative.split('/').collect();
        let meaningful_len = if is_directory_marker {
            components.len() - 1
        } else {
            components.len()
        };
        if meaningful_len == 0
            || components[..meaningful_len]
                .iter()
                .any(|part| !valid_posix_component(part))
        {
            self.skipped_invalid += 1;
            return;
        }
        if !is_directory_marker && denied_final_directories.contains(&relative) {
            // The same POSIX path is both an OSS object and a denied synthetic
            // directory. Directory semantics win, so the colliding object must
            // not leak back into the pruned view.
            self.hidden_conflicts += 1;
            return;
        }

        let dir_len = if is_directory_marker {
            meaningful_len
        } else {
            meaningful_len - 1
        };
        let mut parent = ROOT_INODE;
        let mut directory_path = String::new();
        for name in &components[..dir_len] {
            if !directory_path.is_empty() {
                directory_path.push('/');
            }
            directory_path.push_str(name);
            if pruner.denies(&directory_path) {
                return;
            }
            parent = self.ensure_directory(parent, name, object.modified);
        }

        if is_directory_marker {
            return;
        }
        let name = components[meaningful_len - 1];
        let existing = self.child(parent, name);
        if let Some(inode) = existing {
            if matches!(self.nodes[&inode].kind, NodeKind::Directory { .. }) {
                // POSIX cannot expose a file and directory with the same name. The
                // directory wins so all descendant OSS objects remain reachable.
                self.hidden_conflicts += 1;
                return;
            }
            let node = self.nodes.get_mut(&inode).expect("child inode exists");
            node.modified = object.modified;
            node.kind = NodeKind::File {
                key: object.key,
                size: object.size,
                etag: object.etag,
            };
            return;
        }
        let inode = self.allocate_inode();
        self.nodes.insert(
            inode,
            Node {
                inode,
                parent,
                name: name.to_string(),
                modified: object.modified,
                kind: NodeKind::File {
                    key: object.key,
                    size: object.size,
                    etag: object.etag,
                },
            },
        );
        self.directory_children_mut(parent)
            .insert(name.to_string(), inode);
    }

    fn ensure_directory(&mut self, parent: u64, name: &str, modified: SystemTime) -> u64 {
        if let Some(inode) = self.child(parent, name) {
            if matches!(self.nodes[&inode].kind, NodeKind::Directory { .. }) {
                return inode;
            }
            // A synthetic directory shadows the object whose key is also the prefix.
            self.hidden_conflicts += 1;
            let node = self.nodes.get_mut(&inode).expect("child inode exists");
            node.modified = modified;
            node.kind = NodeKind::Directory {
                children: BTreeMap::new(),
            };
            return inode;
        }
        let inode = self.allocate_inode();
        self.nodes.insert(
            inode,
            Node {
                inode,
                parent,
                name: name.to_string(),
                modified,
                kind: NodeKind::Directory {
                    children: BTreeMap::new(),
                },
            },
        );
        self.directory_children_mut(parent)
            .insert(name.to_string(), inode);
        inode
    }

    fn allocate_inode(&mut self) -> u64 {
        let inode = self.next_inode;
        self.next_inode += 1;
        inode
    }

    fn directory_children_mut(&mut self, inode: u64) -> &mut BTreeMap<String, u64> {
        match &mut self
            .nodes
            .get_mut(&inode)
            .expect("directory inode exists")
            .kind
        {
            NodeKind::Directory { children } => children,
            NodeKind::File { .. } => unreachable!("parent must be a directory"),
        }
    }

    pub fn child(&self, parent: u64, name: &str) -> Option<u64> {
        match &self.nodes.get(&parent)?.kind {
            NodeKind::Directory { children } => children.get(name).copied(),
            NodeKind::File { .. } => None,
        }
    }

    pub fn node(&self, inode: u64) -> Option<&Node> {
        self.nodes.get(&inode)
    }
    pub fn len(&self) -> usize {
        self.nodes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.nodes.len() == 1
    }
    pub fn skipped_invalid(&self) -> usize {
        self.skipped_invalid
    }
    pub fn hidden_conflicts(&self) -> usize {
        self.hidden_conflicts
    }

    pub fn children(&self, inode: u64) -> Option<impl Iterator<Item = (&str, u64)> + '_> {
        match &self.nodes.get(&inode)?.kind {
            NodeKind::Directory { children } => {
                Some(children.iter().map(|(name, inode)| (name.as_str(), *inode)))
            }
            NodeKind::File { .. } => None,
        }
    }
}

fn valid_posix_component(component: &str) -> bool {
    !component.is_empty()
        && component != "."
        && component != ".."
        && component.len() <= 255
        && !component.chars().any(|character| {
            character.is_control()
                || matches!(
                    character,
                    '\u{061c}'
                        | '\u{200e}'
                        | '\u{200f}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                )
        })
}

fn denied_final_directories(
    objects: &[ObjectMeta],
    prefix: &str,
    pruner: &Pruner,
) -> HashSet<String> {
    let mut denied = HashSet::new();
    for object in objects {
        let Some(relative) = object.key.strip_prefix(prefix) else {
            continue;
        };
        let components = relative.split('/').collect::<Vec<_>>();
        let meaningful_len = if relative.ends_with('/') {
            components.len().saturating_sub(1)
        } else {
            components.len()
        };
        if meaningful_len == 0
            || components[..meaningful_len]
                .iter()
                .any(|part| part.is_empty() || *part == "." || *part == "..")
        {
            continue;
        }
        let dir_len = if relative.ends_with('/') {
            meaningful_len
        } else {
            meaningful_len.saturating_sub(1)
        };
        let mut path = String::new();
        for component in &components[..dir_len] {
            if !path.is_empty() {
                path.push('/');
            }
            path.push_str(component);
            if pruner.denies(&path) {
                denied.insert(path.clone());
                break;
            }
        }
    }
    denied
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(key: &str, size: u64) -> ObjectMeta {
        ObjectMeta {
            key: key.into(),
            size,
            modified: SystemTime::UNIX_EPOCH,
            etag: None,
        }
    }

    #[test]
    fn builds_prefix_relative_tree_and_keeps_empty_directory_markers() {
        let tree = Tree::from_objects(
            [
                object("root/a/file.txt", 7),
                object("root/empty/", 0),
                object("elsewhere/no", 1),
            ],
            "root/",
            &Pruner::new(&[]).unwrap(),
        );
        let a = tree.child(ROOT_INODE, "a").unwrap();
        assert_eq!(
            tree.child(a, "file.txt")
                .and_then(|i| tree.node(i))
                .map(|n| match &n.kind {
                    NodeKind::File { size, .. } => *size,
                    _ => 0,
                }),
            Some(7)
        );
        assert!(tree.child(ROOT_INODE, "empty").is_some());
        assert!(tree.child(ROOT_INODE, "elsewhere").is_none());
    }

    #[test]
    fn denied_directory_removes_the_entire_subtree_and_not_similar_names() {
        let pruner = Pruner::new(&["private".into(), "teams/*/secret/**".into()]).unwrap();
        let tree = Tree::from_objects(
            [
                object("private/a.txt", 1),
                object("private/deep/b.txt", 1),
                object("private-copy/visible.txt", 1),
                object("teams/red/secret/x.txt", 1),
                object("teams/red/public/y.txt", 1),
            ],
            "",
            &pruner,
        );
        assert!(tree.child(ROOT_INODE, "private").is_none());
        assert!(tree.child(ROOT_INODE, "private-copy").is_some());
        let teams = tree.child(ROOT_INODE, "teams").unwrap();
        let red = tree.child(teams, "red").unwrap();
        assert!(tree.child(red, "secret").is_none());
        assert!(tree.child(red, "public").is_some());
        assert!(!pruner.denies("teams/red/nested/secret"));
    }

    #[test]
    fn directory_wins_file_directory_collision() {
        let tree = Tree::from_objects(
            [object("a", 1), object("a/b", 2)],
            "",
            &Pruner::new(&[]).unwrap(),
        );
        let a = tree.node(tree.child(ROOT_INODE, "a").unwrap()).unwrap();
        assert!(matches!(a.kind, NodeKind::Directory { .. }));
        assert_eq!(tree.hidden_conflicts(), 1);
    }

    #[test]
    fn denied_final_directory_does_not_leak_colliding_file_in_any_order() {
        let pruner = Pruner::new(&["archive".into()]).unwrap();
        for objects in [
            [object("archive", 1), object("archive/x", 2)],
            [object("archive/x", 2), object("archive", 1)],
        ] {
            let tree = Tree::from_objects(objects, "", &pruner);
            assert!(tree.child(ROOT_INODE, "archive").is_none());
        }
    }

    #[test]
    fn invalid_posix_paths_are_skipped() {
        let tree = Tree::from_objects(
            [
                object("a//b", 1),
                object("../x", 1),
                object("control/line\nbreak", 1),
                object("bidi/hidden\u{202e}name", 1),
                object(&format!("long/{}", "x".repeat(256)), 1),
            ],
            "",
            &Pruner::new(&[]).unwrap(),
        );
        assert_eq!(tree.skipped_invalid(), 5);
        assert!(tree.is_empty());
    }
}
