use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::{env, fs, path::Path};
use url::Url;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub oss: OssConfig,
    #[serde(default)]
    pub prune: PruneConfig,
    #[serde(default)]
    pub mount: MountConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OssConfig {
    pub endpoint: String,
    pub region: String,
    pub bucket_path: String,
    #[serde(default)]
    pub path_style: bool,
    #[serde(default)]
    pub anonymous: bool,
    #[serde(default = "default_access_key_id_env")]
    pub access_key_id_env: String,
    #[serde(default = "default_access_key_secret_env")]
    pub access_key_secret_env: String,
    #[serde(default = "default_session_token_env")]
    pub session_token_env: String,
    #[serde(default = "default_max_list_pages")]
    pub max_list_pages: usize,
    #[serde(default = "default_max_objects")]
    pub max_objects: usize,
    #[serde(default = "default_max_list_page_bytes")]
    pub max_list_page_bytes: u64,
    #[serde(default = "default_max_total_key_bytes")]
    pub max_total_key_bytes: usize,
    #[serde(default = "default_list_timeout_seconds")]
    pub list_timeout_seconds: u64,
    #[serde(default = "default_max_concurrent_requests")]
    pub max_concurrent_requests: usize,
}

fn default_access_key_id_env() -> String {
    "OSS_ACCESS_KEY_ID".into()
}
fn default_access_key_secret_env() -> String {
    "OSS_ACCESS_KEY_SECRET".into()
}
fn default_session_token_env() -> String {
    "OSS_SESSION_TOKEN".into()
}
fn default_max_list_pages() -> usize {
    10_000
}
fn default_max_objects() -> usize {
    1_000_000
}
fn default_max_list_page_bytes() -> u64 {
    8 * 1024 * 1024
}
fn default_max_total_key_bytes() -> usize {
    256 * 1024 * 1024
}
fn default_list_timeout_seconds() -> u64 {
    300
}
fn default_max_concurrent_requests() -> usize {
    32
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PruneConfig {
    /// Globs evaluated against mount-relative directory paths.
    #[serde(default)]
    pub deny_directories: Vec<String>,
    /// If non-empty, only matching directory subtrees and their ancestors are visible.
    #[serde(default)]
    pub allow_directories: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountConfig {
    #[serde(default = "default_file_mode")]
    pub file_mode: u16,
    #[serde(default = "default_dir_mode")]
    pub dir_mode: u16,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    #[serde(default = "default_ttl")]
    pub attribute_ttl_seconds: u64,
    #[serde(default = "default_true")]
    pub read_only: bool,
    #[serde(default)]
    pub allow_other: bool,
}

fn default_file_mode() -> u16 {
    0o444
}
fn default_dir_mode() -> u16 {
    0o555
}
fn default_ttl() -> u64 {
    60
}
fn default_true() -> bool {
    true
}

impl Default for MountConfig {
    fn default() -> Self {
        Self {
            file_mode: default_file_mode(),
            dir_mode: default_dir_mode(),
            uid: None,
            gid: None,
            attribute_ttl_seconds: default_ttl(),
            read_only: true,
            allow_other: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BucketPath {
    pub bucket: String,
    /// Empty or slash-terminated. OSS never receives a leading slash.
    pub prefix: String,
}

#[derive(Clone, Debug)]
pub struct Credentials {
    pub access_key_id: String,
    pub access_key_secret: String,
    pub session_token: Option<String>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let config: Self = serde_yaml::from_str(&text)
            .with_context(|| format!("invalid YAML config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        let endpoint = Url::parse(&self.oss.endpoint).context("oss.endpoint must be a URL")?;
        if !matches!(endpoint.scheme(), "http" | "https") || endpoint.host_str().is_none() {
            bail!("oss.endpoint must be an http(s) URL with a host");
        }
        if !self.oss.anonymous && endpoint.scheme() != "https" {
            bail!("authenticated OSS access requires an https endpoint");
        }
        if !endpoint.path().is_empty() && endpoint.path() != "/" {
            bail!("oss.endpoint must not contain a path");
        }
        if endpoint.username() != ""
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            bail!("oss.endpoint must not contain credentials, a query, or a fragment");
        }
        if self.oss.region.trim().is_empty() {
            bail!("oss.region is required for OSS V4 signatures");
        }
        BucketPath::parse(&self.oss.bucket_path)?;
        if self.oss.max_list_pages == 0
            || self.oss.max_objects == 0
            || self.oss.max_list_page_bytes == 0
            || self.oss.max_total_key_bytes == 0
            || self.oss.list_timeout_seconds == 0
            || self.oss.max_concurrent_requests == 0
        {
            bail!("OSS listing resource limits must be greater than zero");
        }
        if self.mount.file_mode & !0o777 != 0 || self.mount.dir_mode & !0o777 != 0 {
            bail!("mount modes must contain permission bits only");
        }
        if self.mount.file_mode & 0o222 != 0 || self.mount.dir_mode & 0o222 != 0 {
            bail!("read-only mount modes must not contain write permission bits");
        }
        if !self.mount.read_only {
            bail!("this filesystem is read-only; mount.read_only must be true");
        }
        crate::tree::Pruner::with_allow(
            &self.prune.deny_directories,
            &self.prune.allow_directories,
        )?;
        Ok(())
    }

    pub fn credentials(&self) -> Result<Option<Credentials>> {
        if self.oss.anonymous {
            return Ok(None);
        }
        let id = env::var(&self.oss.access_key_id_env).with_context(|| {
            format!(
                "credential environment variable {} is not set",
                self.oss.access_key_id_env
            )
        })?;
        let secret = env::var(&self.oss.access_key_secret_env).with_context(|| {
            format!(
                "credential environment variable {} is not set",
                self.oss.access_key_secret_env
            )
        })?;
        let token = env::var(&self.oss.session_token_env)
            .ok()
            .filter(|s| !s.is_empty());
        Ok(Some(Credentials {
            access_key_id: id,
            access_key_secret: secret,
            session_token: token,
        }))
    }
}

impl BucketPath {
    pub fn parse(input: &str) -> Result<Self> {
        let rest = input
            .strip_prefix("oss://")
            .context("oss.bucket_path must use oss://bucket/optional-prefix syntax")?;
        let (bucket, raw_prefix) = rest.split_once('/').unwrap_or((rest, ""));
        if bucket.is_empty()
            || !bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            bail!("invalid OSS bucket name in bucket_path");
        }
        let trimmed = raw_prefix.trim_matches('/');
        if trimmed.split('/').any(|part| part == "." || part == "..") {
            bail!("bucket prefix must not contain . or .. components");
        }
        let prefix = if trimmed.is_empty() {
            String::new()
        } else {
            format!("{trimmed}/")
        };
        Ok(Self {
            bucket: bucket.to_string(),
            prefix,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_normalizes_bucket_path() {
        assert_eq!(
            BucketPath::parse("oss://my-bucket/a/b/").unwrap(),
            BucketPath {
                bucket: "my-bucket".into(),
                prefix: "a/b/".into()
            }
        );
        assert!(BucketPath::parse("s3://bucket/x").is_err());
        assert!(BucketPath::parse("oss://Bucket/x").is_err());
        assert!(BucketPath::parse("oss://bucket/a/../b").is_err());
    }

    #[test]
    fn example_config_is_valid() {
        let config: Config = serde_yaml::from_str(include_str!("../config.example.yaml")).unwrap();
        config.validate().unwrap();
        assert_eq!(config.mount.file_mode, 0o444);
        assert_eq!(config.mount.dir_mode, 0o555);
    }

    #[test]
    fn authenticated_access_requires_https() {
        let mut config: Config =
            serde_yaml::from_str(include_str!("../config.example.yaml")).unwrap();
        config.oss.endpoint = "http://oss.example.com".into();
        assert!(config.validate().is_err());
        config.oss.anonymous = true;
        config.validate().unwrap();
    }

    #[test]
    fn validates_allow_directory_globs() {
        let mut config: Config =
            serde_yaml::from_str(include_str!("../config.example.yaml")).unwrap();
        config.prune.allow_directories = vec!["docs/**".into()];
        config.validate().unwrap();
        config.prune.allow_directories = vec!["[".into()];
        assert!(config.validate().is_err());
    }
}
