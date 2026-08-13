# ossfs-ro

`ossfs-ro` 把指定的阿里云 OSS Bucket Path（`oss://bucket/prefix`）挂载为 Linux
只读文件系统。挂载前，它按配置对最终目录路径剪枝；某个目录被拒绝后，该目录及整棵子树都不会出现在挂载点中。

核心语义：

- OSS prefix 是挂载树根。例如 `oss://my-bucket/releases/current/` 中的
  `releases/current/docs/a.txt` 会显示为 `/docs/a.txt`。
- 挂载使用 FUSE `ro`，文件权限默认为 `0444`、目录权限默认为 `0555`；写打开返回
  `EROFS`，没有上传、修改或删除 OSS 对象的代码路径。
- 文件内容不在启动时下载。读取由 OSS `GetObject` 的 HTTP Range 请求按需完成。
- 目录索引在挂载时通过 `ListObjectsV2` 分页构建。对象增删和元数据变化需重新挂载才能看到；
  内容读取使用索引时的 ETag 约束，若对象已被替换则读取失败，避免混合不同版本的数据。
- 剪枝规则相对于挂载根，只对目录求值，不直接匹配文件。一旦目录命中，遍历在该处停止，
  后代不会泄露为孤立条目。

## 环境要求

- Linux 内核 FUSE 支持及可用的 `/dev/fuse`。常见发行版需要安装 `fuse3`；程序通过
  Rust 的 Linux FUSE ABI 直接通信，编译时不要求链接 `libfuse`。
- Rust 1.86 或更高版本（仅从源码构建时需要）。
- OSS RAM 身份至少需要目标范围的 `oss:ListObjects` 和 `oss:GetObject`。也支持匿名读取公开 Bucket。

构建：

```bash
cargo build --release --locked
sudo install -m 0755 target/release/ossfs-ro /usr/local/bin/ossfs-ro
```

也可以从对应版本的 GitHub Release 下载 `x86_64-unknown-linux-musl` 预编译包，并使用 Release
中的 `SHA256SUMS` 校验压缩包。项目不发布 macOS 二进制；FUSE 挂载必须在 Linux 上运行。

## 配置

复制 [config.example.yaml](config.example.yaml)，然后设置凭证。长期 AccessKey 和 STS 凭证均从
环境变量读取，避免把密钥写进配置或命令行：

```bash
export OSS_ACCESS_KEY_ID='...'
export OSS_ACCESS_KEY_SECRET='...'
export OSS_SESSION_TOKEN='...'   # 仅 STS 临时凭证需要
```

默认使用 OSS V4 签名。`endpoint` 写区域 endpoint，不要包含 Bucket 名或路径；`region` 必须与
签名区域一致。带凭据的访问只允许 HTTPS，并且客户端不跟随 HTTP 重定向；内网 endpoint 也应
使用 HTTPS。匿名模式可使用 HTTP，主要用于可信内网或本地测试。

```yaml
oss:
  endpoint: https://oss-cn-hangzhou.aliyuncs.com
  region: cn-hangzhou
  bucket_path: oss://my-bucket/releases/current/
  path_style: false
  anonymous: false
  max_list_pages: 10000
  max_objects: 1000000
  max_list_page_bytes: 8388608
  max_total_key_bytes: 268435456
  list_timeout_seconds: 300
  max_concurrent_requests: 32

prune:
  deny_directories:
    - private
    - teams/*/secret
    - archive/**

mount:
  file_mode: 292 # 十进制 292 = 0444
  dir_mode: 365  # 十进制 365 = 0555
  attribute_ttl_seconds: 60
  read_only: true
  allow_other: false
```

配置文件是安全边界：它可以指定 endpoint 和读取凭据的环境变量名称，只应由挂载服务的管理员
创建和修改。建议权限设为 `0600`，不要运行来源不可信的配置。上述列举限制用于避免异常或过大
Bucket 消耗无限内存与时间；大型 Bucket 应根据实测逐项调整，而不是直接取消限制。

剪枝 glob 规则：

- 路径统一不带开头/结尾 `/`，例如挂载后的 `/teams/red/secret` 按
  `teams/red/secret` 匹配。
- `*` 不跨 `/`，`**` 可跨任意目录层级。
- `archive/**` 同时隐藏 `archive` 自身，而不仅是其后代。
- 规则大小写敏感。
- 配置表达的是一次挂载对所有访问者共同可见的目录树，不会根据每次 FUSE 请求的 uid 动态变化。
  不同 Linux 用户需要不同视图时，应以不同配置和挂载点分别启动实例。

也可在启动时追加规则：

```bash
ossfs-ro --config /etc/ossfs-ro.yaml \
  --deny-directory 'temporary/**' \
  /mnt/oss
```

## 运行

先验证配置、OSS 凭证、分页列举和剪枝索引，不执行挂载：

```bash
RUST_LOG=info ossfs-ro --config /etc/ossfs-ro.yaml --check
```

前台挂载：

```bash
mkdir -p /mnt/oss
RUST_LOG=info ossfs-ro --config /etc/ossfs-ro.yaml /mnt/oss
```

另一个终端可以执行常规只读 POSIX 操作：

```bash
find /mnt/oss -maxdepth 3 -type f
cat /mnt/oss/docs/readme.txt
dd if=/mnt/oss/images/large.img of=/dev/null bs=1M count=1 skip=8
```

卸载使用 `fusermount3 -u /mnt/oss`（部分系统命令名为 `fusermount`）。

`allow_other: true` 会让挂载用户之外的本机用户访问该视图，需要 `/etc/fuse.conf` 中启用
`user_allow_other`。开启前应确认剪枝配置适用于所有这些用户。

## OSS 与 POSIX 名称差异

OSS 是扁平对象键空间，程序会合成目录。无法安全表示的键会在索引时跳过，包括空路径组件、
`.`、`..`、超过 255 字节的名称，以及控制字符或双向文本控制字符。如果 OSS 同时存在对象 `a`
与对象 `a/b`，POSIX 不能同时把 `a` 表示为文件和目录；
程序保留目录 `a/` 以确保后代可访问，并在日志中报告被隐藏的冲突对象数量。

## 测试

```bash
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```

测试覆盖 Bucket Path 归一化、分页限制与异常 continuation token、中文键解码、Range/ETag 一致性、
重定向拒绝、OSS V4 canonical request、非法 POSIX 路径、文件/目录冲突，以及命中目录后整棵子树
消失的剪枝不变量。

在支持 `/dev/fuse` 的 Linux 主机上可运行真实挂载验收；它会启动本地只读 OSS 模拟服务，
实际挂载后验证目录可见性、剪枝、完整及随机读取、写入/创建/删除拒绝，且没有发出任何修改 OSS 请求：

```bash
./tests/linux_e2e.sh
```

macOS 上也可借助 Docker Desktop 的 Linux VM 运行同一验收：

```bash
docker build -f Dockerfile.test -t ossfs-ro-test .
docker run --rm --privileged \
  -e CARGO_TARGET_DIR=/tmp/target-linux \
  -v "$PWD:/work" ossfs-ro-test
```

## 许可证

本项目以 [GNU General Public License v3.0](LICENSE) 发布，仅适用 GPL 第 3 版；
详见 `LICENSE`。
