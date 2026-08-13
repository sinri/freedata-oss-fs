use crate::{
    oss::ObjectStore,
    tree::{Node, NodeKind, Tree},
};
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, ReplyOpen,
    Request,
};
use std::{
    ffi::OsStr,
    sync::Arc,
    time::{Duration, SystemTime},
};

pub struct ReadOnlyFs<S: ObjectStore> {
    tree: Tree,
    store: Arc<S>,
    uid: u32,
    gid: u32,
    file_mode: u16,
    dir_mode: u16,
    ttl: Duration,
}

impl<S: ObjectStore> ReadOnlyFs<S> {
    pub fn new(
        tree: Tree,
        store: Arc<S>,
        uid: u32,
        gid: u32,
        file_mode: u16,
        dir_mode: u16,
        ttl: Duration,
    ) -> Self {
        Self {
            tree,
            store,
            uid,
            gid,
            file_mode,
            dir_mode,
            ttl,
        }
    }

    fn attr(&self, node: &Node) -> FileAttr {
        let (kind, size, perm, nlink) = match &node.kind {
            NodeKind::Directory { .. } => (FileType::Directory, 0, self.dir_mode, 2),
            NodeKind::File { size, .. } => (FileType::RegularFile, *size, self.file_mode, 1),
        };
        FileAttr {
            ino: node.inode,
            size,
            blocks: size.div_ceil(512),
            atime: node.modified,
            mtime: node.modified,
            ctime: node.modified,
            crtime: SystemTime::UNIX_EPOCH,
            kind,
            perm,
            nlink,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }
}

impl<S: ObjectStore> Filesystem for ReadOnlyFs<S> {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let Some(name) = name.to_str() else {
            reply.error(libc::ENOENT);
            return;
        };
        let Some(inode) = self.tree.child(parent, name) else {
            reply.error(libc::ENOENT);
            return;
        };
        let node = self.tree.node(inode).expect("tree child must exist");
        reply.entry(&self.ttl, &self.attr(node), 0);
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        match self.tree.node(ino) {
            Some(node) => reply.attr(&self.ttl, &self.attr(node)),
            None => reply.error(libc::ENOENT),
        }
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let Some(node) = self.tree.node(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        if matches!(node.kind, NodeKind::Directory { .. }) {
            reply.error(libc::EISDIR);
        } else if flags & libc::O_ACCMODE != libc::O_RDONLY
            || flags & (libc::O_TRUNC | libc::O_APPEND) != 0
        {
            reply.error(libc::EROFS);
        } else {
            reply.opened(0, fuser::consts::FOPEN_KEEP_CACHE);
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }
        let Some(node) = self.tree.node(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        let NodeKind::File {
            key,
            size: file_size,
            etag,
        } = &node.kind
        else {
            reply.error(libc::EISDIR);
            return;
        };
        let offset = offset as u64;
        if offset >= *file_size || size == 0 {
            reply.data(&[]);
            return;
        }
        let wanted = u64::from(size).min(*file_size - offset) as u32;
        match self
            .store
            .read_range(key, etag.as_deref(), *file_size, offset, wanted)
        {
            Ok(data) => reply.data(&data),
            Err(error) => {
                log::error!(
                    "OSS read failed for key {:?}, offset {}, size {}: {:#}",
                    key,
                    offset,
                    wanted,
                    error
                );
                reply.error(libc::EIO);
            }
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }
        let Some(node) = self.tree.node(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        if !matches!(node.kind, NodeKind::Directory { .. }) {
            reply.error(libc::ENOTDIR);
            return;
        }

        let start = offset as usize;
        if start == 0 && reply.add(ino, 1, FileType::Directory, ".") {
            reply.ok();
            return;
        }
        if start <= 1 && reply.add(node.parent, 2, FileType::Directory, "..") {
            reply.ok();
            return;
        }
        if let Some(children) = self.tree.children(ino) {
            for (index, (name, child_ino)) in children.enumerate().skip(start.saturating_sub(2)) {
                let kind = match self.tree.node(child_ino).expect("child exists").kind {
                    NodeKind::Directory { .. } => FileType::Directory,
                    NodeKind::File { .. } => FileType::RegularFile,
                };
                if reply.add(child_ino, (index + 3) as i64, kind, name) {
                    break;
                }
            }
        }
        reply.ok();
    }

    fn access(&mut self, _req: &Request<'_>, ino: u64, mask: i32, reply: fuser::ReplyEmpty) {
        if self.tree.node(ino).is_none() {
            reply.error(libc::ENOENT);
        } else if mask & libc::W_OK != 0 {
            reply.error(libc::EROFS);
        } else {
            reply.ok();
        }
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: fuser::ReplyStatfs) {
        let files = self.tree.len() as u64;
        reply.statfs(0, 0, 0, files, 0, 4096, 255, 4096);
    }
}
