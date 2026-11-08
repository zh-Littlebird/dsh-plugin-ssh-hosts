# dsh-plugin-ssh-hosts

一个可独立安装的 DeepSeek Harness（DSH）Host 插件：让 Agent 在多台 Linux 服务器上执行命令、读写文件、上传下载，同时把密码/私钥/口令隔离在模型之外，并对高风险命令要求人工审批。

- 插件类型：Host-only bundle（`dsh.bundle.patch`），不改动 Harness 核心源码。
- 工具注册：`@deepseek-ai/dsh-tools` 的 `defineTool`，注册到 `ctx.tools`。
- SSH 实现：`ssh2`（纯 JS，无需本机 `ssh.exe`，支持密码、私钥、带口令私钥）。
- 传输：SFTP（`ssh2` 的 SFTP 子系统）。
- 本机已验证：DSH `0.2.1-rc.2`、Node `24.x`、Windows 11；插件在独立 profile `ssh-dev` 中加载，模型经 mock LLM 调用 `ssh_exec`，对本地真实 SSH 服务返回 `exit 0` 与正确 stdout。

---

## 1. 功能

| 能力 | 说明 |
|---|---|
| 多服务器清单 | 任意多台主机；别名唯一；增删改查；TOFU 主机密钥 |
| 密码 / 私钥认证 | 私钥只按路径读取，不复制、不打印；支持 passphrase |
| 远程命令 | `ssh_exec`：退出码、stdout、stderr、耗时、超时、截断、原始字节数 |
| 服务目录说明 | 每台服务器可声明 `services`（服务名 + 目录 + 启动/日志/端口说明），Agent 用 `ssh_services` 直接定位服务 |
| 文件读写 | `ssh_read_file` / `ssh_write_file`，文本、UTF-8、二进制拒绝 |
| 上传下载 | `ssh_upload` / `ssh_download`，SFTP 流式传输，临时文件落盘后改名 |
| 写权限隔离 | `allowedPaths` 控制读；`editablePaths` 单独控制写/上传；未配置时写入仅限临时目录 |
| 临时目录 | `tempDir`（默认 `/tmp`）在每台服务器上默认获得**读写**权限，Agent 的过程文件都放这里，不往服务目录里丢；把 `tempDir` 设为空字符串即可整体关闭 |
| 会话/服务器授权 | 每个新会话第一次访问某台服务器时，先向用户弹出一次授权；批准只对该会话的**这一台**服务器有效，换一台或多开一个会话都要重新申请。主机清单的查看与新增是另外两个独立授权。处于「完全权限」的会话（不弹审批）会自动获得授权，不再请求 |
| 人工审批 | `rm -rf`、`sudo`、`shutdown`、`mkfs`、`dd`、防火墙清空、DROP DATABASE 等命中时请求一次性批准；「完全权限」会话按已授权执行并标记 `full-access` |
| 提权执行（sudo） | 每台服务器可配置 `sudo`：`nopasswd`（推荐）或 `password`（密码只写本机加密存储，经 SSH stdin 交给 sudo）。`ssh_exec` 传 `privileged: true`，或直接写 `sudo ...`（前导 `sudo` 会被改写为插件托管的提权包装） |
| 凭据隔离 | 无任何工具参数接收密码、私钥内容；凭据单独 AES-256-GCM 加密存储 |
| 路径限制 | 文件操作严格限制在 `allowedPaths`（读）/`editablePaths`（写）内并校验 realpath；命令 cwd 受限；`deniedPaths` 始终拒绝 |
| 命令写入守卫 | `>`/`tee`/`sed -i`/`cp`/`mv`/`rm`/`touch` 等明显写文件的命令，cwd 与路径参数必须在 `editablePaths` 内 |
| 审计 | `audit.log` 逐条记录动作、主机、用户、命令/路径、退出码、耗时、截断、审批结果；不含凭据 |
| 命令历史面板 | Web 侧栏底部的「SSH 命令历史」按钮 + 抽屉面板：按时间倒序列出所有动作，可按服务器/动作/失败/关键字筛选，5 秒自动刷新；服务器按 IP 归并、显示当前别名，改别名不会多出一台服务器 |
| 服务器管理页面 | Web 侧栏「SSH 服务器」页面：手动添加、编辑、测试、删除服务器，录入/清除密码或私钥口令；写接口只接受本机回环请求 |
| 只读服务器 | `readOnly: true` 时拒绝 `ssh_exec` 和远端写入，只允许读取/下载 |

---

## 2. 安装

### 2.1 前置条件

- DeepSeek Harness `0.2.1-rc.2`（`engines.dsh: >=0.2.1-rc.2 <0.3.0`）。
- Node.js `>=22.19`（推荐 24）。
- 能访问 npm registry（安装 `ssh2` 与 `@deepseek-ai/schemastery`）。

### 2.2 构建

```powershell
cd dsh-plugin-ssh-hosts
npm install --legacy-peer-deps
npm run build
npm test
```

`npm run build` 输出到 `lib/`；`npm test` 编译测试到 `dist-test/` 并运行 54 个用例（含真实 ssh2 Server 集成测试与会话/服务器授权测试）。

### 2.3 安装到某个 profile

推荐先装到独立开发 profile，确认无副作用后再装到日常 profile：

```powershell
# 创建一个独立的 headless profile（只创建一次）
dsh --profile ssh-dev --from-default-profile headless

# 安装进该 profile（npm 包名；也可以传克隆下来的本地目录，pnpm 会建立 link）
dsh plugin --profile ssh-dev add dsh-plugin-ssh-hosts

# 确认 bundle 层已出现
dsh --profile ssh-dev --dump-config | Select-String ssh-hosts

# 确认模块可导入且 Config schema 可读（诊断为空）
dsh --profile ssh-dev --dump-config-schema
```

日常 profile 同理，把 `ssh-dev` 换成 `desktop`（Web/Desktop）：

```powershell
dsh plugin --profile desktop add dsh-plugin-ssh-hosts
```

也可以在 Web 侧栏的 **Plugins** 页面点击安装，或让 Agent 调用 `plugin_manager` 的 `install_bundle`，`target` 传包名 `dsh-plugin-ssh-hosts` 或本地目录绝对路径。

> 如果 Desktop 正在运行，安装后需要重启 Harness 进程，新的 Host 插件才会加载。Web 页面本身不会显示新的设置页——本插件是 Host-only，入口是 Agent 工具。
>
> 安装时 pnpm 可能提示这个 link 包的 peerDependencies 未从目标目录解析；这是预期行为：`@deepseek-ai/dsh-tools` 由 Harness 安装提供的运行时解析映射加载，不需要出现在插件目录里。
>
> 如果 pnpm 报告 `ssh2` 的可选原生依赖（如 `cpu-features`）有 pending build scripts，可在插件管理器里允许这些脚本后重试；不批准时 `ssh2` 会回退到纯 JS 路径，命令与 SFTP 仍可用。

卸载：

```powershell
dsh plugin --profile desktop remove dsh-plugin-ssh-hosts
```

插件数据默认在 `$DSH_HOME/ssh-hosts`（Windows：`C:\Users\<你>\.dsh\ssh-hosts`）。卸载插件不会自动删数据；确认不再需要后可手动删除该目录。

---

## 3. 配置

`cordis.patch.yml` 已带一份可直接工作的默认配置：

```yaml
- insert:
    - id: ssh-hosts
      name: dsh-plugin-ssh-hosts
      config:
        maxOutputBytes: 131072
        timeoutMs: 60000
        maxTimeoutMs: 300000
        highRiskPolicy: ask
        sessionConsent: ask
        trustFullAccess: true
        audit: true
        tempDir: /tmp
        debug: false
```

所有字段都可省略；省略时使用默认值。完整字段：

| 字段 | 默认值 | 说明 |
|---|---|---|
| `dataDir` | `$DSH_HOME/ssh-hosts` | 数据目录；也可用环境变量 `DSH_SSH_HOSTS_DATA_DIR` 覆盖（便于测试/多实例） |
| `maxOutputBytes` | `131072` | 单条命令 stdout/stderr **各自**保留上限；超出后保留首尾并标记 |
| `timeoutMs` | `60000` | 命令默认超时 |
| `maxTimeoutMs` | `300000` | 模型单次可请求的最大超时 |
| `connectTimeoutMs` | `20000` | TCP/SSH 握手超时 |
| `idleTimeoutMs` | `300000` | 空闲连接关闭时间；连接池按 host 复用 |
| `maxConcurrentPerHost` | `8` | 单台服务器并发操作上限 |
| `maxTransferBytes` | `52428800` | 单次读/写/上传/下载上限（50 MiB） |
| `secretsBackend` | `file` | `file`、`env` 或 `none` |
| `envPrefix` | `SSH_HOST_` | `env` 后端环境变量前缀 |
| `highRiskPolicy` | `ask` | `ask`（人工审批）、`deny`（直接拒绝）、`allow`（不询问，仍记账） |
| `sessionConsent` | `ask` | 本会话第一次访问某台服务器（或主机清单）时是否申请授权：`ask`（按服务器/清单分别申请一次）、`allow`（恢复旧行为，不询问）、`deny`（全部 `ssh_*` 工具直接拒绝） |
| `trustFullAccess` | `true` | 会话处于「完全权限」（审批策略 `never` + 文件策略 `danger-full-access`）时，直接放行 SSH 授权与高风险命令，而不是去弹一个不可能出现的审批框。设为 `false` 恢复旧行为：高风险命令失败关闭 |
| `audit` | `true` | 写 `audit.log` |
| `debug` | `false` | 输出脱敏调试日志到 stderr |
| `localRoots` | `[]` | 额外允许上传/下载访问的本地根目录；会话工作区始终允许 |
| `strictCommandPaths` | `false` | 为 `true` 时拒绝命令中任何越出 `allowedPaths` 的绝对路径参数 |
| `guardCommandEdits` | `true` | 拒绝在 `editablePaths` 之外执行明显会写文件的 shell 命令（`>`、`tee`、`sed -i`、`cp`、`mv`、`rm`、`touch` 等） |
| `tempDir` | `/tmp` | 每台服务器默认获得**读写**权限的远程临时目录，自动并入该主机的 `allowedPaths` 与 `editablePaths`；Agent 的过程文件应全部放在这里。填空字符串 `""` 关闭该授权，回到「只有 `editablePaths` 可写」的旧行为 |

`tempDir` 的几条约定：

- 它只是把目录**并入**每台服务器的有效路径策略，不改写 `hosts.json`：主机记录里看到的 `allowedPaths`/`editablePaths` 仍是用户配置的原值，`ssh_host_list` 会单独显示 `tempDir` 字段与生效方式。
- 优先级：`deniedPaths` > `tempDir` > `editablePaths` > `allowedPaths`。某台机器不想给 `/tmp`，把 `/tmp` 加进它的 `deniedPaths` 即可；`readOnly: true` 的服务器仍然完全禁止写入。
- 支持绝对路径或 `~/...`（按登录用户的 home 展开），例如 `tempDir: ~/scratch`。
- 关闭方式：`tempDir: ""`（或在 profile 的 `cordis.patch.yml` / Web 插件设置里清空该字段），保存后重启 Harness 生效。
- 默认 `/tmp` 是全局可读目录：不要把密码、令牌等敏感内容写进去；建议每个任务在下面建一个私有子目录（`mkdir -m 700 /tmp/dsh-<任务>`）并在结束时删除。

`secretsBackend: none` 只适合完全不需要密码/口令的私钥主机；密码主机会在连接时报 `SECRET_BACKEND_NONE`。

修改配置：编辑 profile 的 `cordis.patch.yml`，或在 Web 的插件设置里改该行的 `config`。**不要把密码写进 YAML**；凭据走下一节的独立存储。

---

## 4. 添加服务器与录入凭据

### 4.1 添加服务器（由 Agent 工具完成）

让 Agent 调用：

```json
{
  "name": "ssh_host_add",
  "arguments": {
    "alias": "web-1",
    "host": "10.0.0.10",
    "port": 22,
    "username": "deploy",
    "authType": "password",
    "defaultCwd": "~/app",
    "allowedPaths": ["~/app", "/tmp"],
    "editablePaths": ["~/app"],
    "services": [
      {
        "name": "api",
        "directory": "~/app/api",
        "description": "对外 HTTP API，构建后由 systemd 启动",
        "startCommand": "sudo systemctl restart api",
        "logPath": "~/app/logs/api.log",
        "port": 8080
      },
      {
        "name": "worker",
        "directory": "~/app/worker",
        "description": "队列消费者，不要和 API 同时重启",
        "startCommand": "sudo systemctl restart worker"
      }
    ],
    "tags": ["prod", "web"],
    "fingerprintPolicy": "accept-new"
  }
}
```

`ssh_host_add` **不接受** `password`、`privateKey` 或 `passphrase` 字段；这是刻意设计。添加成功后工具返回 `credentialStatus: "missing"` 和下一步提示。

- `allowedPaths`：Agent 可**读**的目录（插件配置的 `tempDir`，默认 `/tmp`，会自动并入）。
- `editablePaths`：Agent 可**写/上传**的目录；留空时除临时目录 `tempDir` 外不能写文件。建议只填服务目录，例如 `["~/app"]`。
- `services`：给 Agent 的服务目录说明。之后调用 `ssh_services` 就能看到 `api -> ~/app/api`、`worker -> ~/app/worker`，不需要每次 `ls` 猜目录。

> **也可以完全手动添加**：Web 侧栏的「SSH 服务器」页面提供同样的字段，并且可以直接输入密码/口令写入本机加密凭据，不需要让 Agent 参与。页面请求只允许本机回环地址。详见下文 5.14。

### 4.2 在本机录入密码或口令

两种方式，任选其一：

1. **Web 页面**：打开「SSH 服务器」→ 编辑目标服务器 → 在密码/口令字段填写后保存。字段留空表示保持原值；页面还提供「清除已保存密码」。
2. **本机终端 CLI**（不是 Agent 会话）：在**你自己的终端**运行插件自带 CLI：

```powershell
cd dsh-plugin-ssh-hosts

# 交互式录入密码（输入不回显）
node scripts/dsh-ssh.mjs set web-1 --password

# 录入带口令私钥的 passphrase
node scripts/dsh-ssh.mjs set web-1 --passphrase

# 适合脚本：从 stdin 读
'my-password' | node scripts/dsh-ssh.mjs set web-1 --password --stdin

# 适合 CI：从环境变量读
$env:MY_SSH_PW = 'my-password'
node scripts/dsh-ssh.mjs set web-1 --password --env MY_SSH_PW

# 查看状态（只显示 available/missing，不显示值）
node scripts/dsh-ssh.mjs status web-1
node scripts/dsh-ssh.mjs list
```

CLI 默认读取 `$DSH_HOME/ssh-hosts`；如果插件用了自定义 `dataDir`：

```powershell
node scripts/dsh-ssh.mjs set web-1 --password --data-dir "D:\dsh-ssh-data"
```

密码写入 `credentials.json`（AES-256-GCM，主密钥 `master.key`，权限收紧为 0600；Windows 上额外尝试 `icacls` 收紧 ACL）。`hosts.json` 里只有 `secretRef`，没有密码。

### 4.3 私钥认证

```json
{
  "name": "ssh_host_add",
  "arguments": {
    "alias": "db-1",
    "host": "10.0.0.20",
    "username": "deploy",
    "authType": "key",
    "privateKeyPath": "C:\\Users\\me\\.ssh\\id_ed25519",
    "fingerprintPolicy": "accept-new"
  }
}
```

- 私钥文件由插件在连接时读取，交给 `ssh2`，不复制到 DSH_HOME、不写日志、不出现在工具结果。
- 私钥有口令时，再执行 `node scripts/dsh-ssh.mjs set db-1 --passphrase`。
- 私钥路径本身属于本机配置，不会出现在 `ssh_host_list` 的返回中（只显示 `privateKeyConfigured: true`）。

### 4.4 `env` 后端（不落盘）

```yaml
config:
  secretsBackend: env
  envPrefix: SSH_HOST_
```

变量名规则：`SSH_HOST_` + 主机 id（去掉 `host:`、大写、非字母数字转 `_`）+ `_PASSWORD` / `_PASSPHRASE` / `_SUDO`。例如 `host_3f5b97c1` 的密码变量是 `SSH_HOST_HOST_3F5B97C1_PASSWORD`，sudo 密码变量是 `SSH_HOST_HOST_3F5B97C1_SUDO`。CLI 的 `status`/`list` 会显示对应变量名解析状态。

### 4.5 主机密钥（TOFU）

- `fingerprintPolicy: "strict"`（默认）：没有记录指纹时拒绝连接，并返回服务器实际指纹，要求用户确认后把策略改为 `accept-new` 再连接。
- `fingerprintPolicy: "accept-new"`：首次连接信任并记录指纹；以后严格比对。
- 指纹不匹配：连接被拒绝，错误里给出旧指纹、新指纹和处理方式；**没有**“本次忽略”开关，只能由用户改配置或删除重加。
- 指纹保存在 `hosts.json` 的 `fingerprint` 字段，格式为 `SHA256:...`（OpenSSH 风格）。

### 4.6 配置 sudo 提权

提权是**按主机、由用户配置**的，模型工具既不能打开也不能扩大它（`ssh_host_add`/`ssh_host_update` 没有 sudo 字段，`ssh_host_update` 传相同值也只是空操作）。

先决定用哪种模式：

| 模式 | 服务器要求 | 插件行为 |
|---|---|---|
| `nopasswd`（推荐） | 给登录用户配置免密 sudo，例如 `/etc/sudoers.d/dsh-ssh`：`deploy ALL=(root) NOPASSWD: /usr/bin/systemctl, /usr/bin/journalctl` | 每条提权命令用 `sudo -n` 执行；不需要任何密码；没有 NOPASSWD 时 sudo 立即失败，不会挂起 |
| `password` | 登录用户有普通 sudo 权限即可 | 用 `sudo -S -k` 执行，密码从本机加密凭据（`host:<id>:sudo`）取出，只写入 SSH 通道的 stdin；未单独录入时回退到该主机的 SSH 登录密码 |

配置方式（三选一，写的是同一份 `hosts.json`）：

1. **Web「SSH 服务器」页面**：编辑主机 → 「提权（sudo）」→ 选择模式、可选目标用户（默认 `root`）→ 密码模式可同时填写 sudo 密码并保存。
2. **本机 CLI**：

   ```powershell
   # 先在 hosts.json 里把该主机的 sudo.mode 设为 password（页面或手工编辑）
   node scripts/dsh-ssh.mjs set web-1 --sudo          # 交互式录入 sudo 密码
   'my-sudo-pw' | node scripts/dsh-ssh.mjs set web-1 --sudo --stdin
   node scripts/dsh-ssh.mjs status web-1 --sudo       # 只看 available/missing
   node scripts/dsh-ssh.mjs delete web-1 --sudo
   ```

3. **直接编辑 `hosts.json`**（重启 Harness 后生效）：

   ```json
   {
     "id": "host_3f5b97c1",
     "alias": "web-1",
     "sudo": { "mode": "password", "user": "root", "passwordRef": "host:host_3f5b97c1:sudo" }
   }
   ```

之后的调用方式（任选其一，效果相同）：

```json
{ "name": "ssh_exec", "arguments": { "server": "web-1", "command": "systemctl restart api", "privileged": true } }
{ "name": "ssh_exec", "arguments": { "server": "web-1", "command": "sudo systemctl restart api" } }
```

细节：

- 前导 `sudo` 会被识别并改写：`sudo -u postgres psql` 的 `-u` 会被保留；`-i`/`-s`/`-e` 等改变执行语义的参数会被明确拒绝（`SUDO_FLAGS_UNSUPPORTED`），不会静默丢掉。
- 实际执行的是 `cd -- '<cwd>' && sudo <flags> [-u user] -- sh -c '<command>'`；`-H` 让 `$HOME` 指向目标账户。
- 提权命令不受 `editablePaths` 写入守卫限制（否则 `sudo tee /etc/...`、系统包安装都用不了），但 `deniedPaths`（`~/.ssh`、`/etc/shadow`、`/etc/sudoers` 等）和 `strictCommandPaths` 仍然生效。
- 提权命令始终算高风险：`ask` 会话仍要逐次批准；「完全权限」会话按已授权执行并标记 `full-access`。
- 密码不会进入命令行、审计、工具结果或调试日志；远程 `ps` 看不到它。

---

## 5. 工具参考

所有工具名以 `ssh_` 开头。`server` 参数可传主机 `id` 或 `alias`；找不到时会列出当前所有别名。

### 5.1 `ssh_host_list`

无参数。返回 `{ hosts, count, nextStep }`。每台主机包含：

`id, alias, host, port, username, authType, hasFingerprint, fingerprint, fingerprintPolicy, credentialStatus, privateKeyConfigured, defaultCwd, allowedPaths, editablePaths, tempDir, services, sudo, deniedPaths, readOnly, tags, note, createdAt, updatedAt`

其中 `sudo` 是脱敏视图：`{ mode: "off" | "nopasswd" | "password", user, passwordConfigured }`，永远不含密码。`tempDir` 是插件配置的临时目录（默认 `/tmp`，已默认授予读写；`null` 表示已关闭），`allowedPaths`/`editablePaths` 仍是主机记录里的原值，渲染结果会明确列出二者的合并效果。

绝不包含密码、口令、私钥内容或私钥路径。

### 5.2 `ssh_host_add`

| 参数 | 必填 | 说明 |
|---|---|---|
| `alias` | 是 | 唯一短名 |
| `host` | 是 | IP / 域名 |
| `port` | 否 | 默认 22 |
| `username` | 是 | 登录用户 |
| `authType` | 是 | `password` 或 `key` |
| `privateKeyPath` | `key` 时必填 | 本机私钥路径 |
| `defaultCwd` | 否 | 默认远程目录，默认登录 home |
| `allowedPaths` | 否 | Agent 可读的远程根，默认 `["~"]` |
| `editablePaths` | 否 | Agent 可写/上传的远程根；默认 `[]`（此时写入仅限插件默认授予读写的临时目录 `tempDir`，即 `/tmp`）。建议只填服务目录 |
| `services` | 否 | 服务目录说明数组：`name`、`directory`、可选 `description`/`startCommand`/`logPath`/`port` |
| `tags` / `note` | 否 | 备注 |
| `fingerprintPolicy` | 否 | `strict`（默认）或 `accept-new` |
| `readOnly` | 否 | 只读服务器 |

### 5.3 `ssh_host_update`

`server` + 可改字段：`alias`、`defaultCwd`、`tags`、`note`、`services`、`authType`；安全方向允许 `readOnly: true`、`fingerprintPolicy: "strict"`。

以下字段在创建后**锁定**，工具会以 `HOST_IDENTITY_LOCKED` / `PATH_POLICY_LOCKED` / `EDIT_POLICY_LOCKED` / `READ_ONLY_LOCKED` / `FINGERPRINT_POLICY_LOCKED` / `KEY_PATH_LOCKED` 拒绝：

- `host`、`port`、`username`：防止把已保存的密码指向另一台服务器。
- `allowedPaths`：防止模型自行扩大可读路径。
- `editablePaths`：防止模型自行扩大可编辑目录。
- `privateKeyPath`：防止把认证指向其他本机密钥。
- 关闭 `readOnly`、把指纹策略放宽为 `accept-new`。

`services` 可以随时替换（用于修正服务目录说明）；需要修改锁定字段时，由用户编辑 `hosts.json`（重启生效），或删除主机后重新添加（删除会同时清除凭据）。`defaultCwd`/`note` 传空字符串表示清除。

### 5.4 `ssh_host_remove`

`server`。删除主机并同步删除其 `host:<id>:*` 凭据，其他主机不受影响。

### 5.5 `ssh_services`

可选 `server`（主机 id/alias）；省略则列出所有主机。返回：

```json
{
  "count": 2,
  "services": [
    {
      "server": "web-1",
      "name": "api",
      "directory": "~/app/api",
      "description": "对外 HTTP API，构建后由 systemd 启动",
      "startCommand": "sudo systemctl restart api",
      "logPath": "~/app/logs/api.log",
      "port": 8080
    }
  ]
}
```

Agent 在检查、构建、重启或编辑某个服务前应先调用它，避免猜目录。它只读本机清单，不连接服务器。

### 5.6 `ssh_test`

`server`。返回：

```json
{
  "server": "web-1",
  "reachable": true,
  "authOk": true,
  "hostKeyFingerprint": "SHA256:...",
  "hostKeyStatus": "learned",
  "banner": "SSH-2.0-OpenSSH_9.6",
  "homeDir": "/home/deploy",
  "durationMs": 42,
  "error": null
}
```

失败时 `error: { code, message, hint }`，不会抛异常。

### 5.7 `ssh_exec`

| 参数 | 必填 | 说明 |
|---|---|---|
| `server` | 是 | 主机 id / alias |
| `command` | 是 | 单条 shell 命令 |
| `cwd` | 否 | 远程工作目录，必须在 `allowedPaths` 内 |
| `timeoutMs` | 否 | 覆盖默认超时，受 `maxTimeoutMs` 限制 |
| `maxOutputBytes` | 否 | 覆盖输出上限，受 16 MiB 限制 |
| `privileged` | 否 | 通过该主机的 sudo 配置以 root（或 `sudo.user`）执行；主机未配置 sudo 时报 `SUDO_NOT_CONFIGURED` |

返回：

```json
{
  "server": "web-1",
  "command": "uname -a && whoami",
  "cwd": "/home/deploy",
  "exitCode": 0,
  "stdout": "...",
  "stderr": "",
  "durationMs": 37,
  "timedOut": false,
  "truncated": false,
  "originalBytes": 58,
  "approval": "not-required",
  "privileged": false,
  "privilegeMode": null
}
```

`approval` 取值：`not-required`、`granted`（用户批准一次）、`policy-allow`（`highRiskPolicy: allow`）、`full-access`（「完全权限」会话，审批提示已关闭）。

语义：

- **非零退出码不是工具错误**：`execute` 正常返回，`exitCode` 如实给出；只有 DNS/连接/认证/主机密钥/channel 打开等基础设施故障才抛错。
- 超时：中断 channel，返回已采集输出，`timedOut: true`；不自动重试。
- 输出超限：保留首尾各一半，中间插入 `... [truncated N bytes] ...`，`truncated: true`，`originalBytes` 是真实总字节数。
- 连接复用：按 host 缓存 Client，空闲 `idleTimeoutMs` 后关闭；并发受 `maxConcurrentPerHost` 限制；插件卸载时统一关闭。
- 命令在 `cd -- '<cwd>' && <command>` 包装下执行，因此 `cwd` 不合法时表现为命令失败，而不是静默换目录。
- **命令写入守卫**：`>`/`>>`/`tee`/`sed -i`/`perl -pi`/`cp`/`mv`/`rm`/`touch`/`mkdir`/`chmod`/`chown`/`dd`/`rsync`/`git checkout|reset`/包管理器安装等明显会写文件的命令，要求 cwd 和路径参数都落在 `editablePaths` 内；否则返回 `EDIT_PATH_DENIED`。临时目录（`tempDir`，默认 `/tmp`）默认也在 `editablePaths` 内，所以过程文件的命令可以直接 `cwd=/tmp` 执行。可用 `guardCommandEdits: false` 关闭，但这会削弱限制。**提权命令不受这一条限制**（见 4.6），`deniedPaths` 与 `strictCommandPaths` 仍然生效。
- **提权**：`privileged: true` 或命令以 `sudo` 开头时，经该主机的 sudo 配置执行；详见 4.6。

### 5.8 `ssh_read_file`

`server`、`path`、可选 `maxBytes`。返回 `{ server, path, content, bytes, originalBytes, truncated }`。

- 路径支持绝对路径、`~/...`、相对 `defaultCwd`，必须位于 `allowedPaths` 内。
- 先做词法校验，再用 SFTP `realpath` 校验父目录和文件本身，防止符号链接逃逸。
- 文件含 NUL 字节时拒绝（`BINARY_FILE`），改用 `ssh_download`。
- 超过 `maxTransferBytes` 拒绝；`maxBytes` 更小时只返回开头并标记 `truncated`。

### 5.9 `ssh_write_file`

`server`、`path`、`content`、可选 `createDirs`、`overwrite`（默认 `true`）。父目录不存在时需 `createDirs: true`。只读服务器、越界路径、`editablePaths` 之外的目标、命中 `deniedPaths` 都会拒绝（`EDIT_PATH_DENIED`）。

过程的临时文件请写到该主机的临时目录（`tempDir`，默认 `/tmp`）：它在默认配置下**可写**，无需事先配置 `editablePaths`；用完请删除。拒绝信息里也会直接给出该目录。

### 5.10 `ssh_upload`

`server`、`localPath`、`remotePath`、可选 `createDirs`、`overwrite`（默认 `false`）。

本地路径必须位于：会话工作区、`localRoots`、或 `<dataDir>/transfers`。远端路径必须位于 `editablePaths` 内（临时目录 `tempDir` 默认也在其中）；只读服务器拒绝。

### 5.11 `ssh_download`

`server`、`remotePath`、`localPath`、可选 `overwrite`（默认 `false`）。本地写入先落到同目录临时文件，成功后再改名，避免半截文件。远端路径只要位于 `allowedPaths` 即可下载，包括临时目录里 Agent 自己生成的文件。

### 5.12 临时目录与过程文件（`tempDir`）

插件默认给每台服务器**额外**授予一个临时目录的读写权限（`tempDir`，默认 `/tmp`），目的是让 Agent 的过程文件有固定去处，不再散落到服务目录、登录 home 或别处：

- 生效方式：`tempDir` 在每次操作时并入该主机的有效 `allowedPaths` 与 `editablePaths`（已存在的父根会自动去重，例如 `allowedPaths: ["/"]` 时不会重复追加）。`hosts.json` 里保存的仍是用户配置的原值，模型不能通过 `ssh_host_update` 修改它。
- 关闭方式：把插件配置的 `tempDir` 设为空字符串。关闭后完全回到旧行为：没有 `editablePaths` 的服务器不可写，写守卫按原规则判定。
- 单机关闭：把 `/tmp` 写进该主机的 `deniedPaths`（`hosts.json`，重启生效）。`deniedPaths` 始终优先于 `tempDir`。
- 只读服务器（`readOnly: true`）：仍然拒绝一切写入与 `ssh_exec`，`tempDir` 不会绕过只读。
- 引导：`ssh_exec`/`ssh_write_file`/`ssh_upload` 的工具描述、`ssh_host_list` 的渲染结果、以及 `EDIT_PATH_DENIED` 的提示里都会写明该目录，并建议「一个任务一个子目录、结束即 `rm -f` 清理」。
- 安全提醒：`/tmp` 通常对本机所有用户可读，不要把凭据、令牌、私钥写进去；需要隔离时用 `mkdir -m 700 /tmp/dsh-<任务>`，或把 `tempDir` 换成例如 `~/scratch`。
- 审计：写入临时目录与其它写入一样记入 `audit.log`，不会因为「只是临时文件」而跳过。

### 5.13 Web 面板：SSH 命令历史

不是工具，而是给人看的面板——Agent 在服务器上执行的每条远端操作都会出现在这里，不需要翻聊天记录，也不需要问模型。

- 位置：左侧栏底部、Settings 上方的终端图标按钮（`SSH 命令历史`）。点击后从右侧滑出一个抽屉。
- 内容：时间、动作（命令/读文件/写文件/上传/下载/测试连接）、服务器别名、命令或路径、`exit` 码、耗时、审批结果、是否截断。超过 160 字符的命令点击可展开全文。
- 服务器筛选：下拉框按 `hosts.json` 里的 `host.host`（IP 或域名）归并，一台地址一行；同一 IP 的多条主机记录（不同端口/别名）共用一行，但行内和下拉框都显示**当前别名**。无论别名改过多少次，旧记录都会显示成当前别名，也不会多出一台服务器。旧版本写入、没有 `hostId` 的记录会按地址做一次兼容映射：`ssh-10-0-0-10`、`10-0-0-10`、`10.0.0.10` 这类别名如果唯一对应当前清单里的某个 IP，就归并到该地址；其它旧别名保留当时的名字，只出现在「全部服务器」下。
- 主机管理动作（`host_add`/`host_update`/`host_remove`/凭据变更）仍然写入 `audit.log`，但**不进入命令历史**，避免改一次别名就多出一条“历史”和一台“服务器”。
- 筛选：服务器、动作类型、只看失败、命令/路径关键字。
- 刷新：面板开着时每 5 秒自动拉取一次，也可点右上角刷新；`Esc` 或点击遮罩关闭。
- 顶栏避让：抽屉从 `--dsh-frame-overlay-top` 下方开始，Windows/macOS 的原生标题栏与窗口按钮不会被遮住，关闭按钮不会和系统关闭按钮叠在一起。
- 数据来源：`<dataDir>/audit.log`（以及轮转后的 `audit.log.1`），只读，不含凭据。`config.audit=false` 时不会产生新记录。
- 实现：Host 侧注册只读端点 `GET /ssh-hosts-api/history`（参数 `limit`、`server`、`action`、`failed`、`q`；`server` 可传 IP、当前别名、旧别名或稳定 id），Client 侧在 `sidebar.footer.action` 放按钮、在 `shell.overlay` 放抽屉。

直接用浏览器查看原始数据：

```powershell
# Harness 的监听地址见 Web GUI 的 URL，例如 http://127.0.0.1:54030
curl "http://127.0.0.1:54030/ssh-hosts-api/history?limit=20"
curl "http://127.0.0.1:54030/ssh-hosts-api/history?server=web-1&failed=1&q=systemctl"
```

响应里除 `entries` 外还有 `servers: [{ id, ip, count, aliases }]`，这是面板的下拉框数据源；`servers` 按 IP/地址归并，同一地址只出现一次，`aliases` 是该地址当前的别名列表。

> 面板需要重启 Harness（或重新加载插件）后才会出现；Host-only 的旧版本没有这个入口。
>
> 端点是否挂上，写在 `<dataDir>/history-route.json`（例如 `%USERPROFILE%\.dsh\ssh-hosts\history-route.json`）：`ok: true` 表示已注册，`mode` 是注册路径（`direct`/`inject`）；`ok: false` 时 `reason` 说明原因（`waiting` = 仍在等 webServer 服务）。

### 5.14 Web 页面：SSH 服务器管理

手动管理服务器的页面，适合不想让 Agent 代劳、或需要直接改主机身份/路径策略的场景。

- 入口：左侧栏「全局面板」里的 `SSH 服务器`（与「自动化任务」并列），点击后在主区域打开页面。
- 列表：每台服务器显示 `user@host:port`、认证方式、凭据状态、只读/指纹策略、可读/可编辑目录、标签、备注、服务目录；可以直接「测试连接」或删除。
- 添加/编辑表单：
  - 基础：别名、主机/IP、SSH 端口、登录用户。
  - 认证：密码或私钥；可以直接输入密码、私钥口令（只写入本机加密凭据，响应里只返回 `credentialStatus`），也可以留空稍后再录入。编辑时凭据字段留空表示保持不变。
  - 访问策略：默认目录、可读路径、可编辑路径、只读、`strict`/`accept-new`、固定 SHA256 指纹。
  - 其他：标签、备注、服务目录（名称/目录/说明/启动命令/日志/端口）。
- 编辑页允许用户修正 `host/port/username`、`allowedPaths`、`editablePaths`、私钥路径等模型工具锁定的字段；修改连接身份时会自动清掉旧的主机指纹，避免用旧指纹校验新端点。模型侧的 `ssh_host_update` 仍然受原有锁定规则约束。
- 「提权（sudo）」区块：选择不启用 / NOPASSWD / 密码模式，可填目标用户（默认 root），密码模式可直接填写 sudo 密码（只写入本机加密凭据），已保存时可一键清除；列表页会给启用 sudo 的主机加标记。
- 删除服务器同时删除该主机的本地凭据；所有写操作都写审计（`host_add`/`host_update`/`host_remove`/`credential`），但不会把密码或口令写进审计。
- 端点：`/ssh-hosts-ui`，包括：
  - `GET /ssh-hosts-ui/hosts`
  - `POST /ssh-hosts-ui/hosts`
  - `GET|PATCH|DELETE /ssh-hosts-ui/hosts/:id`
  - `PUT|DELETE /ssh-hosts-ui/hosts/:id/credential`
  - `POST /ssh-hosts-ui/hosts/:id/test`
  - `GET /ssh-hosts-ui/health`
- 安全边界：只接受回环地址（`127.0.0.1`/`::1`）的请求；写请求必须带 `x-ssh-hosts-ui: 1` 头，且 `Origin` 必须是本机地址，普通跨站表单/脚本无法直接调用。
- 端点状态写在 `<dataDir>/ui-route.json`；页面打不开时先看这里的 `ok`/`reason`，再确认是否需要重启 DSH。

---

## 6. 安全模型

### 6.1 凭据在哪里

| 数据 | 位置 | 模型可见？ |
|---|---|---|
| 主机连接信息 | `hosts.json` | 部分可见（`ssh_host_list` 脱敏后） |
| 密码 / 私钥口令 | `credentials.json`（AES-256-GCM） | 否 |
| 主密钥 | `master.key`（0600） | 否 |
| 私钥内容 | 原文件，只在连接时读入内存 | 否 |
| 审计日志 | `audit.log` | 通过普通文件工具可能可见，但只含命令/路径，不含凭据 |

- **没有任何工具参数接受密码、口令或私钥内容**，因此模型无法“顺手”把凭据写进会话日志。
- 工具返回值、错误、调试日志、审计日志统一经过 `redact()`：已解析的凭据值、PEM 私钥块、`password=...`、`Authorization`、URL 中的 `user:pass@` 都会被替换。
- `credentials.json` 的每个条目以 `secretRef` 作为 GCM AAD，密文被换到别的条目会解密失败。

### 6.2 这不是系统钥匙串

AES-256-GCM + 0600 只防误读、防备份泄露，**不防同一用户下运行的其他程序**。如果威胁模型包含同用户恶意进程，请改用 `secretsBackend: env`（由外部 secret manager 注入），或使用操作系统级凭据服务。

### 6.3 路径限制

- 读取：严格限制在 `allowedPaths`，且 realpath 后仍须在允许根内；`deniedPaths`（默认 `~/.ssh`、`/etc/shadow`、`/etc/sudoers`、`/etc/sudoers.d`）始终拒绝。
- 写入/上传：必须同时位于 `allowedPaths` 和 `editablePaths`；`editablePaths` 为空时除临时目录 `tempDir`（默认 `/tmp`）外一律拒绝。写入前会校验最深已存在祖先目录的 realpath，防止通过符号链接把新目录建到允许范围之外。
- 临时目录：`tempDir` 默认并入每台服务器的 `allowedPaths` 与 `editablePaths`，因此默认配置下 `/tmp` 可读可写；`deniedPaths` 优先于它，`readOnly` 主机仍然禁止写入。要整体关闭就配置 `tempDir: ""`，要单机关闭就把 `/tmp` 写进该主机的 `deniedPaths`。
- 命令：`cwd` 必须落在 `allowedPaths`；`deniedPaths` 中的路径即使出现在命令参数中也会拒绝；`strictCommandPaths: true` 时进一步拒绝所有越界绝对路径参数。
- 命令写入守卫：`>`/`tee`/`sed -i`/`cp`/`mv`/`rm`/`touch`/`chmod` 等明显写文件的命令，要求 cwd 和路径参数都在 `editablePaths` 内；这是为了防止 Agent 用 `ssh_exec` 绕过文件工具。可用 `guardCommandEdits: false` 关闭，但不建议。临时目录默认也在 `editablePaths` 内，所以 `cwd=/tmp` 的过程文件命令可以直接执行。
- 命令是 shell，**无法**做文件系统级沙箱；路径扫描是保守启发式，不是安全边界。真正的边界是服务器账号权限 + 允许的主机清单。需要强保证时，给 SSH 用户只授予 `editablePaths` 的写权限。
- 主机身份（`host/port/username`）、`allowedPaths`、`editablePaths`、`privateKeyPath` 和只读/指纹策略在创建后锁定：模型不能通过 `ssh_host_update` 把已保存的密码发往另一台服务器、扩大读写范围、指向其他本机密钥，或关闭只读。需要变更时由用户改 `hosts.json`，或在 Web「SSH 服务器」页面编辑（该页面只接受本机回环请求）；模型工具仍然拒绝这些字段。

### 6.4 会话 / 服务器使用授权

插件默认 `sessionConsent: ask`。模型在**一个新会话里第一次**访问某台已配置服务器时，会先通过审批通道向用户弹一次授权请求；批准后，该会话对该服务器的后续 `ssh_*` 调用不再逐次询问。授权范围严格按「会话 + 服务器」隔离：

- 同一会话里访问第二台服务器，会单独再弹一次。
- 新会话（包括子 Agent 自己的会话）对所有服务器都重新申请。
- 授权键使用服务器的稳定 `id`，不是可改的 `alias`；改别名不会丢失已有授权。
- `ssh_host_list`（查看清单）与 `ssh_host_add`（新增主机）不属于任何一台服务器，是两个独立的授权范围；批准查看不会顺带批准新增，更不会授予任何服务器的访问权限。
- 服务器授权覆盖该服务器的全部 `ssh_*` 工具（`ssh_exec`、`ssh_test`、文件读写/上传下载、`ssh_services`、`ssh_host_update`、`ssh_host_remove`）。

实现细节与边界：

- 批准结果只保存在当前 Harness 进程内，不落盘。重启 Harness、或会话恢复后进程已重启，都会重新询问。
- 拒绝**不会**被记住：本次调用失败并提示模型不要自动重试；如果用户随后明确同意，下一次调用会重新弹授权框，不需要新开会话。
- 同一目标并发发起的多个首次调用共享一个授权请求，不会弹出多张卡片。
- 审批服务缺失、调用没有关联会话/Agent、用户取消或超时都**失败关闭**：不执行任何远程操作。无头/后台组合没有应答者时，插件会一直拒绝；需要无人值守时由用户显式配置 `sessionConsent: allow`。
- `sessionConsent: deny` 会拒绝所有 `ssh_*` 工具，且不弹审批。
- 「完全权限」会话（审批策略 `never`）**无法弹出审批框**：`trustFullAccess` 为 `true`（默认）时，插件直接记一条本进程内的授权并继续，否则这些调用会一直失败关闭。判定方式是读取 Harness 的 `approval` 服务（`effectivePolicy(session) === 'never'`）与 `sandboxPolicy` 服务（`resolve({ session }).mode`）；任一服务缺失或返回异常都按 `ask` 处理。
- 高风险命令审批（6.5）是独立的一层：即使服务器已在会话内获授权，命中危险命令仍要再次逐次批准。

### 6.5 高风险命令审批

命中以下任一模式时，默认通过 `ctx.approval.request()` 请求一次性人工批准：

`rm -r/-f`、`mkfs`、`dd of=/dev/`、`shutdown/reboot/poweroff/halt`、`systemctl stop/disable/mask`、`kill -9`、`userdel/groupdel`、`passwd`、`chmod 777 /`、`chown -R /`、`iptables -F/ufw disable/nft flush`、`truncate -s 0`、写 `/etc/`、`crontab -r`、`docker system prune/volume rm/rm -f`、`kubectl delete`、`DROP/TRUNCATE DATABASE/TABLE`、`curl|sh`、`sudo`、`su root`、`git reset --hard/clean -f`、`npm publish`、`terraform destroy/apply`、fork 炸弹。

- `highRiskPolicy: ask`：审批服务缺失、无 Agent、用户拒绝、取消、超时都**失败关闭**。
- `highRiskPolicy: deny`：直接拒绝。
- `highRiskPolicy: allow`：不询问，但仍写入审计并在结果里标记 `approval: "policy-allow"`。
- 「完全权限」会话（审批 `never` + `danger-full-access`）：不询问，标记 `approval: "full-access"`，审计里同样记录。若会话是 `never` 但文件策略仍是只读/工作区写入，高风险命令会以 `APPROVAL_POLICY_DENIED` 失败关闭，并提示切换到「完全权限」。
- 把 `trustFullAccess` 设为 `false` 可让「完全权限」会话也按失败关闭处理。
- 审批文案只包含脱敏后的命令和风险原因，不包含凭据。

### 6.6 主机密钥

TOFU + 后续严格比对；不提供“本次忽略”开关。指纹变更必须由用户显式处理。

### 6.7 提权（sudo）的边界

- 提权策略写在该主机的 `sudo` 字段里，只能由用户通过 Web 页面、CLI 或手工编辑 `hosts.json` 配置；模型工具无法打开或扩大它。
- 密码模式的 sudo 密码存放在本机加密凭据里（`host:<id>:sudo`），读取后只写入该次 SSH 通道的 stdin，随后立刻关闭 stdin；不进入命令行、审计、工具结果、错误或调试日志。
- 密码模式用 `sudo -S -k -p ""`，因此**每次**提权都会重新认证，不会误用 sudo 的时间戳缓存；如果服务器实际配置了 NOPASSWD，请把模式改成 `nopasswd`，否则密码行会进入命令的 stdin（虽然不会被回显）。
- 需要 TTY 的 sudo 场景（`Defaults requiretty`，多见于很老的 RHEL/CentOS）不支持：插件没有分配 PTY。请改用 NOPASSWD，或在该主机上关闭 `requiretty`。
- 提权命令会命中 `sudo` 风险规则，因此仍受 6.5 的审批逻辑约束；审计中的 `privileged: true` 表明这次是以提权身份执行的。

---

## 7. 错误码

工具失败时，模型看到的是 `message（hint）[CODE]`：`CODE` 是稳定机器码，括号里的 `hint` 是可执行建议（例如写路径被拒时会直接指出可以改用临时目录 `tempDir`）。Web 管理页的接口则把 `message` 与 `hint` 分成两个字段返回。

| code | 含义 | 常见处理 |
|---|---|---|
| `HOST_NOT_FOUND` | id/alias 不存在 | 先 `ssh_host_list` |
| `HOST_ALIAS_EXISTS` | 别名冲突 | 换别名 |
| `CREDENTIAL_MISSING` | 密码/私钥不可用 | 本机 CLI 录入 |
| `SECRET_DECRYPT_FAILED` | 主密钥与密文不匹配 | 重新录入凭据 |
| `SECRET_BACKEND_NONE` | 后端为 none | 改 `file`/`env` |
| `DNS_FAILED` | 域名解析失败 | 检查地址/DNS |
| `CONNECTION_REFUSED` | 端口拒绝 | 检查 sshd/防火墙 |
| `CONNECT_TIMEOUT` | 连接/握手超时 | 检查网络/负载 |
| `AUTH_FAILED` | 认证失败 | 核对用户名与凭据 |
| `HOST_KEY_UNKNOWN` | 首次连接但策略 strict | 用户确认指纹后改 `accept-new` |
| `HOST_KEY_MISMATCH` | 主机密钥变化 | 核对旧/新指纹；确认重装后再处理 |
| `CHANNEL_OPEN_FAILED` | 无法开 exec 通道 | 服务器会话数/权限限制 |
| `SFTP_UNAVAILABLE` | 未启用 SFTP | 启用子系统，或改用 `ssh_exec` |
| `REMOTE_PATH_DENIED` | 路径越界/被禁止 | 调整 `allowedPaths`/`deniedPaths` |
| `EDIT_PATH_DENIED` | 写入/写命令不在 `editablePaths` 内，或未配置 | 用 `ssh_write_file`/`ssh_upload`，或由用户配置 `editablePaths` |
| `EDIT_POLICY_LOCKED` | 试图通过更新扩大 `editablePaths` | 由用户编辑 `hosts.json` |
| `INVALID_SERVICE` | 服务目录说明格式错误/重名 | 检查 `services` 的 name/directory |
| `COMMAND_PATH_DENIED` | 命令参数命中禁止路径/严格模式越界 | 换路径或调整策略 |
| `FILE_TOO_LARGE` | 超过传输/读写上限 | 调整 `maxTransferBytes` |
| `BINARY_FILE` | 读到二进制 | 改用 `ssh_download` |
| `READ_ONLY` | 只读服务器 | 关闭 `readOnly` |
| `APPROVAL_DENIED` | 高风险命令未获批 | 询问用户或改策略 |
| `APPROVAL_UNAVAILABLE` | 审批服务/Agent 不可用 | 启用审批组件 |
| `APPROVAL_POLICY_DENIED` | 会话不弹审批（`never`），且不是完全权限或 `trustFullAccess=false` | 切换到「完全权限」，或改 `highRiskPolicy`/`trustFullAccess` |
| `SUDO_NOT_CONFIGURED` | 该主机没有配置 sudo | 在 Web 页面或 `hosts.json` 启用 sudo（NOPASSWD 或密码模式） |
| `SUDO_PASSWORD_MISSING` | 密码模式但没有可用的 sudo 密码 | `scripts/dsh-ssh.mjs set <alias> --sudo`，或在 Web 页面填写 |
| `SUDO_USER_LOCKED` | 命令请求的 `sudo -u` 与主机固定用户不一致 | 改用 `privileged: true`，或由用户调整 `sudo.user` |
| `SUDO_FLAGS_UNSUPPORTED` | 命令里的 sudo 参数（`-i`/`-s`/`-e` 等）无法复现 | 去掉这些参数，改用 `privileged: true` |
| `SUDO_POLICY_LOCKED` | 试图用模型工具修改 sudo 策略 | 由用户在 Web 页面或 `hosts.json` 中配置 |
| `INVALID_SUDO` | sudo 配置格式错误（模式、用户、密码组合） | 只填 `mode=off/nopasswd/password`，用户名为合法账户名 |
| `SESSION_CONSENT_DENIED` | 用户拒绝、`sessionConsent: deny`，或本次未获服务器/清单授权 | 由用户批准该服务器/清单；确认同意后可重试 |
| `SESSION_CONSENT_UNAVAILABLE` | 本次调用没有可用的审批通道，失败关闭 | 在带审批界面的会话中重试，或由用户改 `sessionConsent` |
| `SESSION_CONSENT_CANCELLED` | 授权请求被取消 | 在用户可交互时重试 |
| `ABORTED` | 调用被取消 | 重试 |

错误消息统一带 `[CODE]`，并在有建议时附带中文 hint。

---

## 8. 已知限制

- 不支持跳板机/ProxyJump；如需，请在本机用端口转发或系统 SSH config 另行解决。
- 不支持交互式全屏程序（vim、top、tmux attach 等）；`ssh_exec` 是 exec channel，不是 PTY 会话。
- 命令超时/取消会销毁 channel，但**不保证**远端派生进程已退出（shell 可能继续运行子进程）。
- 不支持批量并行命令编排；需要时由 Agent 多次调用。
- `readOnly: true` 会拒绝所有 `ssh_exec`（因为无法可靠判断命令是否只读）；只保留读文件/下载。
- 高风险识别是正则启发式，混淆命令可能绕过；审批不是沙箱。
- `strictCommandPaths` 默认关闭，因为 shell 命令经常引用 `/var/log`、`/etc` 等系统路径；文件工具始终严格。
- `editablePaths` 由插件强制；`guardCommandEdits` 只是对常见写命令的启发式拦截，不能阻止脚本、变量拼接等刻意绕过。需要硬保证时，给远端 SSH 用户只授予目标目录的写权限。
- `services` 是用户/Agent 维护的说明，插件不会自动核对目录是否真实存在；目录变更后需要用 `ssh_host_update` 更新说明。
- `editablePaths` 默认为空：新主机默认只能读/下载，额外只有临时目录 `tempDir`（默认 `/tmp`）可写——这是为了不让 Agent 把过程文件丢进服务目录，同时不开放业务目录。要编辑业务文件仍须由用户配置 `editablePaths`。
- 临时目录不是「安全区」：`/tmp` 通常对本机所有用户可读，且不做配额/清理；插件只负责授权与提示，不负责定期清理。需要更强隔离时把 `tempDir` 指到 `~/scratch`，或在主机上为该目录加 tmpfiles.d/systemd-tmpfiles 清理策略。
- 手工编辑 `hosts.json` 后需要重启 Harness（或重新加载插件）才生效；插件进程内缓存清单。
- Windows 上 `chmod 0600` 语义有限，ACL 收紧是 best-effort（`icacls` 失败不阻断操作）。
- 主机管理既可以通过 Agent 工具完成，也可以在 Web「SSH 服务器」页面手动完成；页面与工具写的是同一份 `hosts.json`，两边不要同时编辑。
- 命令历史面板只展示审计里的元数据（命令/路径/退出码/耗时），不保存命令输出；输出仍在会话里。
- `/ssh-hosts-api/history` 与其它 Web 路由同源、只读；`/ssh-hosts-ui` 的写接口只接受本机回环请求并要求 `x-ssh-hosts-ui: 1` 头。两者都只适合本机可信环境；暴露到局域网前请确认 `audit.log` 内容可以给该网络的人看到。
- 命令历史里的服务器下拉框按 `host.host`（IP/地址）归并，显示当前别名；同一 IP 的不同端口/别名共用一行。旧版本写入、没有 `hostId` 的记录无法总是自动映射：别名如果是 `ssh-<IP>`、`<IP 用 - 连接>` 或 `<IP>` 且唯一对应当前主机，会归并到该地址；其它旧别名保留当时的名字，只出现在「全部服务器」下。
- `ssh_upload`/`ssh_download` 的本地根默认只有会话工作区、`localRoots` 和 `<dataDir>/transfers`；不要为了省事把 `C:\` 加进 `localRoots`。
- 会话/服务器授权只保存在 Harness 进程内：重启进程会重新询问；插件不做「永久记住这台服务器」的授权存储。多开一个会话、或子 Agent 新建会话，都会重新申请。
- 服务器授权是「会话 + 服务器」粒度，不是「会话 + 工具」粒度：批准某台服务器后，本会话对该服务器的 `ssh_host_update`/`ssh_host_remove` 也不再逐次询问。如需更细粒度，请用 `sessionConsent: deny` 或直接不把该服务器加入清单。
- `ssh_host_list`/`ssh_host_add` 不针对某一台服务器，因此只能做「清单一览」和「清单新增」两个会话级授权；这与服务器访问授权相互独立。
- 提权是「按主机」而不是「按命令」授权的：一旦某台主机配置了 sudo，`privileged: true` 就能以 root 执行任意命令（`readOnly`/`deniedPaths` 之外没有进一步限制）。不想要这种能力就不要配置 `sudo`，或只给 `sudoers` 授权具体命令。
- 密码模式的 sudo 依赖 stdin 传密码，因此该次命令的 stdin 会在写入密码后立即关闭；需要交互输入的命令本来就不支持。
- sudo 探测/执行没有为“密码错误”单独分类：密码错误时表现为 sudo 以非零退出码结束、stderr 里有 sudo 的提示，`ssh_exec` 仍按普通命令失败返回（退出码非 0 不是工具异常）。

---

## 9. 兼容性说明（按实际 API 核对）

开发和验证基于 DSH `0.2.1-rc.2` 的实际安装包，而不是凭记忆：

- 插件入口采用命名导出：`export const name`、`export const inject = ['tools']`、`export const Config`、`export function apply(ctx, config)`；没有 `export default`。
- 工具用 `@deepseek-ai/dsh-tools` 的 `defineTool({ name, description, parameters, output, execute, presentCall, presentResult })`；`parameters` 使用其 schema DSL，输出 schema 的必填字段用属性上的 `required: true`（不是顶层 `required` 数组）。
- 高风险审批调用 `ctx.approval.request()`（`ctx.get('approval')` 可选获取），返回 `'allowed-once' | 'rejected' | 'cancelled' | 'unavailable'`；只有 `allowed-once` 放行。
- 会话权限预设从两个可选服务读取：`ctx.get('approval').effectivePolicy(session)`（`ask`/`never`）与 `ctx.get('sandboxPolicy').resolve({ session }).mode`（`read-only`/`workspace-write`/`danger-full-access`）。任一服务缺失、方法不存在或抛错都退化为“未知”，按旧的 `ask` 行为处理，不会因为 API 变化而自动放宽权限。
- 提权执行在 `ssh_exec` 内完成：`sudo -n -H -p ""`（NOPASSWD）或 `sudo -S -k -H -p ""`（密码模式）+ `sh -c '<command>'`，密码只写入 SSH channel 的 stdin。`sudo` 本身不是 PTY 会话，因此不支持需要 TTY 的 sudo 配置。
- 会话/服务器授权复用同一审批 seam：从 `exec.agent.session.id` 取会话身份，从 `ssh_*` 参数里的 `server` 经 `HostStore.find()` 解析成稳定主机 `id`，再按 `session:<id>|server:<host id>` 记住本次进程内的批准；审批服务本身只支持一次性授权，所以「本会话后续不再问」是插件自己的内存缓存，不落盘。
- `ToolDefinition.timeoutMs` 在该版本是**声明式**的，注册表不负责超时；因此 `ssh_exec` 自己实现定时器、channel 销毁和部分输出保留。
- `ssh2` 是 CommonJS 包；插件用默认导入再解构 `Client`，避免 ESM 命名导入在部分 Node 版本下失败。
- 插件以 bundle 形式安装：`package.json` 的 `dsh.bundle.patch` 指向 `cordis.patch.yml`，安装后 profile 的 `--dump-config` 中会出现 `ssh-hosts` 行。
- 依赖策略：`ssh2` 与 `@deepseek-ai/schemastery` 是普通依赖；`@deepseek-ai/dsh-tools`、`@deepseek-ai/cordis` 是 peerDependency，由 Harness 安装提供的运行时解析映射加载，避免重复打包 Harness 包。
- Web 半边不参与 `tsc` 构建：`client/index.js` 是手写 ESM，通过 `window.__ModuleLoader__.load` 注册，由 `package.json` 的 `dsh.client`（`platform: "web"`、`immediately: true`）声明，并用 `ctx.slots.inject` 挂到 `sidebar.footer.action`、`shell.overlay`、`sidebar.panellist` 与 `main`。
- Web 数据由 Host 侧注册的两个前缀路由提供：只读的 `/ssh-hosts-api`（历史）和本机写接口 `/ssh-hosts-ui`（服务器管理），都通过 `ctx.get('webServer').register({ kind: 'prefix', ... })` 挂载，并等待 `webServer` 服务就绪；没有 webServer 的组合（headless profile）自动跳过，不影响工具。
- Web 抽屉/面板使用宿主 CSS 变量（`--dsw-alias-*`、`--dsh-frame-overlay-top`）适配深浅色和 Windows/macOS 标题栏，不修改宿主代码。

如果升级 DSH 后出现 `defineTool`/审批 API 变化，优先以 `dsh --profile <name> --dump-config-schema` 和安装目录下的 `lib/types/*.d.ts` 为准，并相应调整 `src/dsh.d.ts`。

**从旧版数据升级**：旧 `hosts.json` 没有 `editablePaths` 字段时会按空数组读取，即升级后默认禁止写入/上传；`services` 也会为空。请由用户编辑 `hosts.json` 补充 `editablePaths` 与 `services`，或删除主机后重新添加。

---

## 10. 目录结构

```text
dsh-plugin-ssh-hosts/
├── package.json              # ESM、dsh.bundle.patch、engines.dsh、peerDeps
├── cordis.patch.yml          # - insert: [{ id: ssh-hosts, name, config }]
├── tsconfig.json             # 构建 src -> lib
├── tsconfig.test.json        # 测试 -> dist-test
├── locale/en.json, zh.json   # 插件管理器显示元数据
├── icon.svg                  # 插件图标
├── src/
│   ├── index.ts              # name / inject / Config / apply
│   ├── config.ts             # Schemastery 配置与默认值
│   ├── hosts.ts              # hosts.json 校验、原子写、脱敏视图
│   ├── secrets.ts            # AES-256-GCM 凭据存储 + env 后端
│   ├── redact.ts             # 统一脱敏出口
│   ├── ssh.ts                # 连接池、exec、SFTP、超时、错误分类
│   ├── paths.ts              # POSIX 路径展开 / 读写白名单 / 命令路径扫描
│   ├── edits.ts              # 写命令识别与 editablePaths 守卫
│   ├── risk.ts               # 高风险命令分类
│   ├── output.ts             # 首尾保留截断
│   ├── audit.ts              # JSONL 审计
│   ├── history.ts            # 审计读取 + /ssh-hosts-api/history 只读端点
│   ├── ui-api.ts             # /ssh-hosts-ui 服务器管理写接口（仅回环）
│   ├── web.ts                # 前缀路由注册、JSON/CSRF、请求体读取
│   ├── approval.ts           # 审批策略
│   ├── session-policy.ts     # 会话权限预设（approval never / sandbox mode）探测
│   ├── session-consent.ts    # 会话 + 服务器 / 清单的按目标授权缓存
│   ├── sudo.ts               # 前导 sudo 解析、sudo 策略解析与密码读取
│   ├── local.ts              # 本地传输路径限制
│   ├── deps.ts               # 工具依赖接口
│   └── tools/                # host / exec / files 三组工具
├── client/
│   └── index.js              # Web 半边：命令历史抽屉 + 「SSH 服务器」管理页面
├── tests/                    # node:test 单测 + ssh2 Server 集成测试 + E2E harness
├── scripts/dsh-ssh.mjs       # 本机凭据录入 CLI
└── README.md
```

---

## 11. 开发与验证

```powershell
npm run build
npm run typecheck
npm test

# 单独跑 SSH 集成测试（本机随机端口起 ssh2 Server）
npm run test:integration
```

### 11.1 单元/集成测试覆盖

- `hosts.json` 读写、别名冲突、端口/名称校验、损坏 JSON 报错、私钥路径不出现在视图。
- AES-256-GCM 往返、密文不含明文、篡改检测、错误主密钥、env/none 后端、文件权限。
- 脱敏：注册的凭据值、PEM、`password=`、URL 凭据。
- 截断：首尾保留、原始字节数、marker。
- 路径：`~`/相对/绝对、读路径越界、`editablePaths` 写入限制、denied、strict 命令路径、shell 引号。
- 临时目录：`tempDir` 默认值与关闭、`~/...` 展开、已存在父根去重、并入后 `/tmp` 可读写、关闭后恢复原策略、`deniedPaths` 优先、拒绝提示里带上临时目录。
- 写命令守卫：重定向/`sed -i`/`cp`/`rm`/`touch` 识别、`2>/dev/null` 不误报、cwd 与路径检查。
- 服务说明：服务名/目录校验、重名拒绝、`ssh_services` 返回与渲染。
- 风险识别：危险命令命中、普通命令不命中、引号内文本不误报。
- 真实 SSH：strict/accept-new、指纹不匹配、密码错误、私钥登录、stdout/stderr、非零退出码、超时、大输出截断、连接复用、取消。
- 会话授权：同一会话同一服务器只问一次、同会话第二台服务器重新问、新会话重新问、拒绝后显式重试会重新问、未知服务器不弹授权、清单查看/新增各自独立、`allow`/`deny` 策略。
- 会话权限预设：`never`+`danger-full-access` 判为完全权限、`never`+受限沙箱只关闭提示、`ask` 不自动放行、服务缺失/抛错回退为未知、完全权限下授权与高风险命令自动放行、`trustFullAccess=false` 恢复失败关闭。
- 提权（sudo）：前导 `sudo` 解析（`-u`/`--user`、可忽略参数、保留引号与 `&&`）、不支持的 sudo 参数报错、命令包装与引号、NOPASSWD 不带密码、密码模式经 stdin 送达、登录密码回退、目标用户锁定、密码缺失与未配置报错、`hosts.json` 的 sudo 校验与模型锁定、管理 API 的 sudo 策略/密码保存与清除。
- E2E harness：11 个工具全部注册；真实 SSH+SFTP 下跑通 list/services/add/test/exec/审批/提权（NOPASSWD）/完全权限免审批/写读/上传下载/写路径拒绝/命令写守卫/只读/审计。

### 11.2 端到端验证步骤

用一个独立 profile（示例名 `ssh-e2e`，从 `headless` 模板创建）验证完整链路：

```text
dsh --profile ssh-e2e --dump-config          # 应能看到 ssh-hosts 行
dsh --profile ssh-e2e --dump-config-schema   # diagnostics 为空表示 schema 可读
```

再用本地 OpenAI 兼容 mock 模型驱动一次 `ssh_exec` 工具调用，工具注册、真实 SSH 执行和结果回传都走真实 Harness 路径（`headless` profile 没有桌面账户登录态，因此用 mock 模型替代模型层）：

```powershell
# 终端 A：真实 SSH + SFTP 测试服务
node tests/fixtures/ssh-server.mjs

# 终端 B：OpenAI 兼容 mock 模型（只用于驱动一次工具调用）
node tests/fixtures/mock-llm.mjs

# 终端 C：准备数据并跑一轮
node tests/fixtures/seed-host.mjs ".ssh-e2e-data" dev-1 22222
$env:MOCK_API_KEY = 'mock'
$env:DSH_SSH_HOSTS_DATA_DIR = '.ssh-e2e-data'
dsh --profile ssh-e2e --patch "tests\fixtures\ssh-dev-mock-overlay.yml" "Run the SSH command on dev-1."
```

`ssh-dev-mock-overlay.yml` 插入 `@deepseek-ai/dsh-llm-pi-ai` 的 `mock` 路由并把默认模型指向它；不修改 profile 文件本身。验证结束后可删除 `.ssh-e2e-data`。

### 11.3 只做工具层 E2E（不需要模型）

```powershell
# 终端 A：启动本地 SSH 测试服务（内存文件系统，支持 exec + SFTP）
node tests/fixtures/ssh-server.mjs

# 终端 B：注册全部工具并真实执行
node --import ./tests/harness/register.mjs tests/harness/e2e.mjs
```

harness 使用一个 `defineTool` 直通桩（真实 `defineTool` 只做校验并返回同一对象），真实的 Harness 导入路径已由 `--dump-config-schema` 覆盖。harness 会打印注册工具列表、exec 结果、审批次数、文件传输结果和审计行数。

---

## 12. 参考

- DSH 插件/工具文档：<https://deepseek-harness.github.io/deepseek-harness/develop/basic/tool.md>
- 工具契约与 cookbook：<https://deepseek-harness.github.io/deepseek-harness/reference/cookbook/adding-a-tool.md>
- 打包与安装：<https://deepseek-harness.github.io/deepseek-harness/develop/basic/publish.md>
- 配置 schema：<https://deepseek-harness.github.io/deepseek-harness/develop/basic/config.md>
- `ssh2`：<https://github.com/mscdex/ssh2>

许可证：MIT。
