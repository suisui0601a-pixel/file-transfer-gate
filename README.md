# File Transfer Gate

一个通用、仅密码解锁的单文件传输入口。Python 标准库实现，提供安全会话、全局三次成功解锁额度、文件校验与 HTTP 断点续传。

页面只显示密码输入、当前文件、下载按钮和校验值，没有品牌、联系人、外部脚本或统计服务。仓库不包含实际传输文件、生产口令、会话库或服务器配置。

## 固定基线

`v1.0.0` 是首个可复用基线。部署时检出该标签或其固定 commit，不依赖浮动的 `main`。Docker 基础镜像按 digest 固定；CI 的第三方 Action 也固定到 commit。

## 访问规则

- 正确密码成功解锁一次，消耗一次额度；总额度为三次。
- 错误密码不消耗额度，有独立的尝试频率限制。
- 同一有效会话刷新、下载、HEAD 和续传不重复计数。
- 额度用完后，新会话显示“请联系管理员”；现有会话继续有效。
- 额度与会话保存在 SQLite，进程或容器重启不会自动重置。
- 更换传输文件不会自动补充额度。
- 网页不显示剩余次数，也不提供上传、目录浏览或管理操作。

## 快速使用

需要 Python 3.10 或更新版本，无第三方 Python 依赖。公开访问使用 HTTPS 反向代理。

```sh
mkdir data state
# 将要传输的文件放入 data。
python -B transfer_server.py init --state ./state
python -B transfer_server.py prepare --file ./data/archive.zip --manifest ./data/current.json
python -B transfer_server.py serve --state ./state --files ./data --manifest ./data/current.json --origin https://files.example.com
```

`init` 交互式读取密码，不把密码放在命令行中。自动化可使用 `--password-stdin` 从受保护的标准输入传入。初始化拒绝覆盖已有配置或数据库。

服务默认只监听 `127.0.0.1:8080`。将 `Caddyfile.example` 的示例域名换成自己的域名并配置 TLS。`--origin` 必须与浏览器看到的 HTTPS Origin 一致。

## Docker

`Dockerfile` 和 `compose.yaml` 提供后端示例。容器以 UID/GID `10001:10001` 运行，文件目录只读，状态目录可写；需要先保证状态目录的所有权正确。

```sh
# 在独立目录中操作；以下相对路径只指向本项目自己的状态目录。
mkdir -p data state
cp .env.example .env
# 编辑 .env，填写自己的 PUBLIC_ORIGIN。
# Linux 主机需要让容器用户能写入 state。
sudo chown 10001:10001 state
docker compose build
docker compose run --rm file-transfer init --state /state
```

文件清单应先在宿主机运行 `prepare` 生成。运行服务时数据目录保持只读挂载。

设置 `PUBLIC_ORIGIN` 后运行 `docker compose up -d`。示例只发布到宿主机回环地址。已有反向代理和 Docker 私网时，可去掉 `ports`，把后端接入专用内部网络，避免与其它站点冲突。

只有后端确实仅能被受信任代理访问，且代理覆盖 `X-Real-IP` 时才启用 `--trust-proxy`。默认不信任客户端自报 IP。

## 更换文件

先完整发布一个新的文件，再生成清单。使用不同文件名，保留仍在下载的旧文件。

```sh
python -B transfer_server.py prepare --file ./data/next-file.zip --manifest ./data/current.json
```

清单通过同目录临时文件、刷新和原子替换发布。服务发现新清单后校验实际文件 SHA-256，成功后提供新的内容地址；无需重启服务。

下载地址包含完整 SHA-256。旧地址返回 `410`，不会把旧断点续传拼到新文件上。正在进行的传输继续持有原文件句柄。清理旧文件前应检查是否仍有活跃传输。

文件应保持不可变；不要原地改写正在下载的文件。清单、文件缺失或校验失败时，入口拒绝提供数据。

## 重置三次额度

管理仅通过本地 CLI 完成，不提供公网管理路由。

```sh
python -B transfer_server.py reset --state ./state --operation-id manual-reset-001
```

每次独立重置使用新的操作 ID。重复执行同一个 ID 是幂等操作，不会再次补充额度。默认保留现有会话，密码也不改变。确实需要撤销现有会话时才加 `--revoke-sessions`；已经开始的传输可能继续完成，撤销影响后续请求。

迁移已有站点可通过 `--legacy-session-cookie`、`--legacy-csrf-cookie` 接受旧 Cookie 名称并逐步迁移到通用名称。`--legacy-download PATH=SHA256` 仅在当前文件校验值匹配时兼容旧地址，换文件后返回 `410`。这些参数默认关闭。

## 测试

```sh
python -B -m unittest discover -s tests -v
```

测试包括：三次额度的真实并发竞争、错误密码与限速、CSRF/Origin、Cookie 安全标记、旧会话迁移、幂等重置、文件完整性、路径限制、普通/后缀/开放区间 Range、旧地址退役、空文件、Unicode 文件名，以及真实子进程终止和重启后的会话恢复。

Windows 无符号链接权限时，对应测试明确跳过；不会为了获得通过而启用系统权限。

## 部署边界

这是由受信任管理员维护文件的传输入口。状态目录保存加盐 scrypt 口令校验值及会话令牌的 SHA-256，不保存明文口令或原始会话令牌。备份状态目录应包含 SQLite 的一致性快照，并保持私密。

HTTPS 由反向代理提供。管理员和服务器操作系统仍能读取传输文件；成功下载后的副本也可以再次传播。三次额度控制的是成功解锁次数。

后端限制为最多八个工作线程、30 秒连接超时和小型登录请求。日志只记录请求方法、状态和传输字节/耗时，不记录口令、Cookie、文件正文或客户端 IP。

丢失或未知格式的访问数据库会阻断启动，恢复时不会自动把额度归零。

## License

MIT。传输文件本身的权利由各自权利方决定。
