use anyhow::{bail, Result};
use clap::Parser;
use freedata_oss_fs::{
    config::{BucketPath, Config},
    oss::{ObjectStore, OssClient},
    tree::{Pruner, Tree},
};
use std::{path::PathBuf, sync::Arc};

#[cfg(target_os = "linux")]
use anyhow::Context;
#[cfg(target_os = "linux")]
use freedata_oss_fs::fs::ReadOnlyFs;
#[cfg(target_os = "linux")]
use fuser::MountOption;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Mount a pruned Aliyun OSS prefix as a read-only Linux filesystem"
)]
struct Args {
    /// YAML configuration file.
    #[arg(short, long)]
    config: PathBuf,
    /// Local directory used as mount point. Not required with --check.
    mountpoint: Option<PathBuf>,
    /// Override oss.bucket_path (oss://bucket/prefix).
    #[arg(long)]
    bucket_path: Option<String>,
    /// Add a mount-relative denied-directory glob. May be repeated.
    #[arg(long = "deny-directory")]
    deny_directories: Vec<String>,
    /// Add a mount-relative allowed-directory glob. May be repeated.
    #[arg(long = "allow-directory")]
    allow_directories: Vec<String>,
    /// Validate configuration and build the pruned index without mounting.
    #[arg(long)]
    check: bool,
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    if let Err(error) = run() {
        eprintln!("freedata-oss-fs: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    let mut config = Config::load(&args.config)?;
    if let Some(bucket_path) = args.bucket_path {
        config.oss.bucket_path = bucket_path;
    }
    config.prune.deny_directories.extend(args.deny_directories);
    config
        .prune
        .allow_directories
        .extend(args.allow_directories);
    config.validate()?;
    if !args.check && cfg!(not(target_os = "linux")) {
        bail!(
            "mounting is supported on Linux only (use --check to validate OSS access and pruning)"
        );
    }
    if !args.check && args.mountpoint.is_none() {
        bail!("mountpoint is required unless --check is used");
    }

    let bucket_path = BucketPath::parse(&config.oss.bucket_path)?;
    let credentials = config.credentials()?;
    let client = Arc::new(OssClient::new(
        &config.oss,
        bucket_path.bucket.clone(),
        credentials,
    )?);
    log::info!(
        "listing oss://{}{prefix}",
        bucket_path.bucket,
        prefix = if bucket_path.prefix.is_empty() {
            String::new()
        } else {
            format!("/{}", bucket_path.prefix)
        }
    );
    let objects = client.list_all(&bucket_path.prefix)?;
    let object_count = objects.len();
    let pruner = Pruner::with_allow(
        &config.prune.deny_directories,
        &config.prune.allow_directories,
    )?;
    let tree = Tree::from_objects(objects, &bucket_path.prefix, &pruner);
    log::info!(
        "index ready: {} OSS objects, {} visible filesystem nodes, {} invalid keys skipped, {} file/directory conflicts hidden",
        object_count, tree.len(), tree.skipped_invalid(), tree.hidden_conflicts()
    );
    if args.check {
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        let mountpoint = args.mountpoint.context("mountpoint was validated above")?;
        let metadata = std::fs::metadata(&mountpoint)
            .with_context(|| format!("cannot access mountpoint {}", mountpoint.display()))?;
        if !metadata.is_dir() {
            bail!("mountpoint {} is not a directory", mountpoint.display());
        }

        let uid = config
            .mount
            .uid
            .unwrap_or_else(|| unsafe { libc::getuid() });
        let gid = config
            .mount
            .gid
            .unwrap_or_else(|| unsafe { libc::getgid() });
        let fs = ReadOnlyFs::new(
            tree,
            client,
            uid,
            gid,
            config.mount.file_mode,
            config.mount.dir_mode,
            Duration::from_secs(config.mount.attribute_ttl_seconds),
        );
        let mut options = vec![
            MountOption::RO,
            MountOption::FSName("freedata-oss-fs".into()),
            MountOption::Subtype("oss".into()),
            MountOption::DefaultPermissions,
            MountOption::NoDev,
            MountOption::NoSuid,
        ];
        if config.mount.allow_other {
            options.push(MountOption::AllowOther);
        }
        log::info!("mounting read-only filesystem at {}", mountpoint.display());
        fuser::mount2(fs, &mountpoint, &options).context("FUSE mount failed")?;
    }
    Ok(())
}
