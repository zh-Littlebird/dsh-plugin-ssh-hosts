/**
 * dsh-plugin-ssh-hosts — Web half.
 *
 * Adds two surfaces beside Settings in the sidebar foot:
 *
 *  - "SSH 命令历史": a frame-wide drawer listing every audited SSH action.
 *  - "SSH 服务器": a main page for manually adding, editing, testing, and
 *    removing servers and provisioning their local credentials.
 *
 * Data comes from this package's Host half: `GET /ssh-hosts-api/history` reads
 * `audit.log`, and `/ssh-hosts-ui/hosts` is the loopback-only management API.
 * No credential value is ever returned by either endpoint.
 */

window.__ModuleLoader__.load({
  id: 'dsh-plugin-ssh-hosts',
  factory(require) {
    'use strict'
    const React = require('react')
    const h = React.createElement

    const HISTORY_ENDPOINT = '/ssh-hosts-api/history'
    const SERVERS_API = '/ssh-hosts-ui'
    const SERVER_LIMIT = 500
    const REFRESH_MS = 5000
    const FONT =
      '-apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", "PingFang SC", system-ui, sans-serif'
    const MONO = 'ui-monospace, SFMono-Regular, Consolas, "Cascadia Mono", "Liberation Mono", monospace'

    const COPY = {
      zh: {
        title: 'SSH 命令历史',
        trigger: 'SSH 命令历史',
        subtitle: 'Agent 通过 ssh_* 工具在服务器上执行过的操作',
        close: '关闭',
        refresh: '刷新',
        retry: '重试',
        loading: '正在读取…',
        empty: '还没有记录。Agent 调用 ssh_exec / ssh_read_file / ssh_upload 等工具后，这里会逐条出现。',
        error: '读取审计日志失败',
        allServers: '全部服务器',
        allActions: '全部动作',
        failedOnly: '只看失败',
        search: '搜索命令或路径',
        count: '条记录',
        exit: 'exit',
        truncated: '输出截断',
        expand: '点击展开',
        approved: '✓ 已批准',
        policyAllowed: '策略放行',
        footerHint: '数据来自 audit.log；按服务器 IP 归并，显示当前别名',
        auditOff: '审计已关闭（config.audit=false）',
        notFound: '端点未就绪：重启 Harness 后这个面板才能取到数据。',
        actions: {
          exec: '命令',
          read: '读文件',
          write: '写文件',
          upload: '上传',
          download: '下载',
          test: '测试连接',
        },
      },
      en: {
        title: 'SSH command history',
        trigger: 'SSH command history',
        subtitle: 'Every action the agent ran on your servers through the ssh_* tools',
        close: 'Close',
        refresh: 'Refresh',
        retry: 'Retry',
        loading: 'Reading…',
        empty: 'No records yet. Rows appear after the agent calls ssh_exec, ssh_read_file, ssh_upload, and so on.',
        error: 'Failed to read the audit log',
        allServers: 'All servers',
        allActions: 'All actions',
        failedOnly: 'Failed only',
        search: 'Search command or path',
        count: 'records',
        exit: 'exit',
        truncated: 'truncated',
        expand: 'Click to expand',
        approved: '✓ approved',
        policyAllowed: 'policy',
        footerHint: 'From audit.log; grouped by server IP and shown with the current alias',
        auditOff: 'Auditing is off (config.audit=false)',
        notFound: 'Endpoint not ready: restart Harness to load this panel.',
        actions: {
          exec: 'exec',
          read: 'read',
          write: 'write',
          upload: 'upload',
          download: 'download',
          test: 'test',
        },
      },
    }

    const SERVER_COPY = {
      zh: {
        trigger: 'SSH 服务器',
        title: 'SSH 服务器',
        subtitle: '手动添加、编辑、测试服务器；密码和口令只写入本机加密凭据，不进入模型上下文',
        add: '添加服务器',
        edit: '编辑',
        remove: '删除',
        test: '测试连接',
        testing: '测试中…',
        save: '保存',
        saving: '保存中…',
        cancel: '取消',
        back: '返回列表',
        refresh: '刷新',
        loading: '正在读取服务器…',
        empty: '还没有配置服务器。点击“添加服务器”开始。',
        count: '台服务器',
        error: '读取服务器列表失败',
        endpointMissing: '服务器管理端点未就绪：重启 DSH 后这个页面才能读取和保存服务器。',
        retry: '重试',
        addTitle: '添加服务器',
        editTitle: '编辑服务器',
        basic: '基础信息',
        auth: '认证',
        access: '访问策略',
        extra: '标签与备注',
        services: '服务目录',
        alias: '别名',
        host: '主机 / IP',
        port: 'SSH 端口',
        username: '登录用户',
        authType: '认证方式',
        authPassword: '密码',
        authKey: '私钥',
        password: '密码',
        passwordOptional: '可留空，稍后再录入',
        passwordKeep: '留空表示保持当前密码不变',
        passphrase: '私钥口令',
        passphraseOptional: '私钥没有口令可留空',
        passphraseKeep: '留空表示保持当前口令不变',
        privateKeyPath: '私钥路径',
        privateKeyPathPlaceholder: '例如 C:\\Users\\you\\.ssh\\id_ed25519 或 /home/you/.ssh/id_rsa',
        keyPathKeep: '当前路径已隐藏；留空保持不变',
        defaultCwd: '默认远程目录',
        allowedPaths: '可读路径',
        allowedPathsHint: '每行一个，例如 ~ 或 ~/app；必须至少一个',
        editablePaths: '可编辑路径',
        editablePathsHint: '每行一个；留空表示 Agent 只能读取和下载，写入仅限插件配置的临时目录（默认 /tmp）',
        tempPaths: '临时目录',
        fingerprintPolicy: '主机密钥策略',
        fpStrict: 'strict（必须已有指纹）',
        fpAcceptNew: 'accept-new（首次连接信任并记录）',
        hostKeyFingerprint: '固定指纹（可选）',
        fingerprintHint: 'OpenSSH SHA256 指纹，例如 SHA256:0vWs8...；填写后首次连接即严格校验',
        readOnly: '只读（拒绝命令与写入）',
        readOnlyHint: '只读时仍允许读取和下载',
        tags: '标签',
        tagsHint: '逗号分隔，例如 prod, web',
        note: '备注',
        servicesHint: '声明每个服务的目录与启动方式，Agent 用 ssh_services 定位服务',
        serviceName: '服务名',
        serviceDirectory: '目录',
        serviceDescription: '说明',
        serviceStart: '启动命令',
        serviceLog: '日志路径',
        servicePort: '端口',
        addService: '添加服务',
        removeService: '移除',
        credentialAvailable: '凭据可用',
        credentialMissing: '凭据缺失',
        credentialUnavailable: '凭据不可用',
        sudo: '提权（sudo）',
        sudoHint: '启用后 Agent 可用 sudo 执行命令（ssh_exec 的 privileged=true 或以 sudo 开头）。推荐在服务器上配置 NOPASSWD；密码模式会加密保存 sudo 密码。',
        sudoOff: '不启用',
        sudoNopasswd: 'NOPASSWD（免密码）',
        sudoPassword: '密码模式',
        sudoUser: '目标用户',
        sudoUserHint: '留空表示 root',
        sudoPasswordField: 'sudo 密码',
        sudoPasswordOptional: '留空表示沿用 SSH 登录密码',
        sudoPasswordKeep: '留空表示保持当前 sudo 密码不变',
        sudoPasswordConfigured: '已保存 sudo 密码',
        sudoPasswordMissing: '未保存 sudo 密码',
        clearSudoPassword: '清除已保存的 sudo 密码',
        clearSudoPasswordConfirm: '确定清除 {alias} 已保存的 sudo 密码？',
        sudoPasswordCleared: '已清除保存的 sudo 密码',
        noPassword: '未保存密码',
        clearPassword: '清除已保存密码',
        clearPasswordConfirm: '确定清除 {alias} 已保存的密码？',
        passwordCleared: '已清除保存的密码',
        fingerprintStored: '已记录指纹',
        noFingerprint: '未记录指纹',
        clearFingerprint: '清除指纹',
        clearFingerprintConfirm: '确定清除 {alias} 已记录的主机指纹？下次连接会重新按策略校验。',
        fingerprintCleared: '已清除主机指纹',
        readOnlyOn: '只读',
        readWrite: '可写',
        readPaths: '可读',
        editPaths: '可编辑',
        none: '（无）',
        servicesList: '服务',
        testSuccess: '连接成功',
        testFailed: '连接失败',
        home: 'home',
        duration: '耗时',
        saveFailed: '保存失败',
        deleteConfirm: '确定删除服务器 {alias}？这会同时删除本地保存的密码/口令。',
        deleted: '已删除',
        added: '已添加',
        saved: '已保存',
        securityHint: '密码与口令只写入本机加密凭据文件；命令历史与模型都不会看到明文。',
        confirmDeleteTitle: '删除服务器',
        keyAuthNeedsPath: '私钥认证需要填写私钥路径',
        aliasRequired: '请填写别名',
        hostRequired: '请填写主机地址',
        userRequired: '请填写登录用户',
        allowedPathsRequired: '至少保留一个可读路径',
        editSecretNote: '凭据字段留空即保持不变',
        backendEnv: '当前凭据后端是 env：密码/口令请通过环境变量提供，页面不会写入磁盘。',
        backendNone: '当前凭据后端是 none：页面不能保存密码/口令。',
        nextStep: '提示',
      },
      en: {
        trigger: 'SSH servers',
        title: 'SSH servers',
        subtitle: 'Add, edit, and test servers manually; passwords and passphrases go only to the local encrypted store, never to the model',
        add: 'Add server',
        edit: 'Edit',
        remove: 'Delete',
        test: 'Test',
        testing: 'Testing…',
        save: 'Save',
        saving: 'Saving…',
        cancel: 'Cancel',
        back: 'Back to list',
        refresh: 'Refresh',
        loading: 'Reading servers…',
        empty: 'No servers yet. Click “Add server” to start.',
        count: 'servers',
        error: 'Failed to read the server list',
        endpointMissing: 'The server-management endpoint is not ready: restart DSH to load it.',
        retry: 'Retry',
        addTitle: 'Add server',
        editTitle: 'Edit server',
        basic: 'Basics',
        auth: 'Authentication',
        access: 'Access policy',
        extra: 'Tags and note',
        services: 'Service directories',
        alias: 'Alias',
        host: 'Host / IP',
        port: 'SSH port',
        username: 'Login user',
        authType: 'Authentication',
        authPassword: 'Password',
        authKey: 'Private key',
        password: 'Password',
        passwordOptional: 'Optional; add it later',
        passwordKeep: 'Leave blank to keep the current password',
        passphrase: 'Key passphrase',
        passphraseOptional: 'Leave blank when the key has no passphrase',
        passphraseKeep: 'Leave blank to keep the current passphrase',
        privateKeyPath: 'Private-key path',
        privateKeyPathPlaceholder: 'e.g. C:\\Users\\you\\.ssh\\id_ed25519 or /home/you/.ssh/id_rsa',
        keyPathKeep: 'The current path is hidden; leave blank to keep it',
        defaultCwd: 'Default remote directory',
        allowedPaths: 'Readable paths',
        allowedPathsHint: 'One per line, e.g. ~ or ~/app; at least one is required',
        editablePaths: 'Editable paths',
        editablePathsHint: 'One per line; empty means the agent may only read/download, and write only to the plugin temp directory (/tmp by default)',
        tempPaths: 'Temp directory',
        fingerprintPolicy: 'Host-key policy',
        fpStrict: 'strict (fingerprint required)',
        fpAcceptNew: 'accept-new (trust and record on first connect)',
        hostKeyFingerprint: 'Pinned fingerprint (optional)',
        fingerprintHint: 'OpenSSH SHA256 fingerprint, e.g. SHA256:0vWs8...; when set, the first connection is already strict',
        readOnly: 'Read-only (refuse commands and writes)',
        readOnlyHint: 'Reads and downloads still work',
        tags: 'Tags',
        tagsHint: 'Comma separated, e.g. prod, web',
        note: 'Note',
        servicesHint: 'Declare each service directory and start command so the agent can locate it with ssh_services',
        serviceName: 'Service',
        serviceDirectory: 'Directory',
        serviceDescription: 'Description',
        serviceStart: 'Start command',
        serviceLog: 'Log path',
        servicePort: 'Port',
        addService: 'Add service',
        removeService: 'Remove',
        credentialAvailable: 'credential ready',
        credentialMissing: 'credential missing',
        credentialUnavailable: 'credential unavailable',
        sudo: 'Privilege (sudo)',
        sudoHint: 'When enabled the agent may run commands through sudo (ssh_exec privileged=true or a command starting with sudo). NOPASSWD is recommended; password mode stores the sudo password encrypted.',
        sudoOff: 'Disabled',
        sudoNopasswd: 'NOPASSWD',
        sudoPassword: 'Password mode',
        sudoUser: 'Target user',
        sudoUserHint: 'Leave blank for root',
        sudoPasswordField: 'sudo password',
        sudoPasswordOptional: 'Leave blank to reuse the SSH login password',
        sudoPasswordKeep: 'Leave blank to keep the current sudo password',
        sudoPasswordConfigured: 'sudo password saved',
        sudoPasswordMissing: 'no sudo password saved',
        clearSudoPassword: 'Clear saved sudo password',
        clearSudoPasswordConfirm: 'Clear the saved sudo password for {alias}?',
        sudoPasswordCleared: 'Saved sudo password cleared',
        noPassword: 'No saved password',
        clearPassword: 'Clear saved password',
        clearPasswordConfirm: 'Clear the saved password for {alias}?',
        passwordCleared: 'Saved password cleared',
        fingerprintStored: 'fingerprint stored',
        noFingerprint: 'no fingerprint',
        clearFingerprint: 'Clear fingerprint',
        clearFingerprintConfirm: 'Clear the stored host fingerprint for {alias}? The next connection is checked again by policy.',
        fingerprintCleared: 'Host fingerprint cleared',
        readOnlyOn: 'read-only',
        readWrite: 'writable',
        readPaths: 'Read',
        editPaths: 'Edit',
        none: '(none)',
        servicesList: 'Services',
        testSuccess: 'Connection OK',
        testFailed: 'Connection failed',
        home: 'home',
        duration: 'took',
        saveFailed: 'Save failed',
        deleteConfirm: 'Delete server {alias}? Its locally stored password/passphrase is removed too.',
        deleted: 'Deleted',
        added: 'Added',
        saved: 'Saved',
        securityHint: 'Passwords and passphrases are written only to the local encrypted store; neither the command history nor the model sees them.',
        confirmDeleteTitle: 'Delete server',
        keyAuthNeedsPath: 'Private-key authentication needs a key path',
        aliasRequired: 'Alias is required',
        hostRequired: 'Host is required',
        userRequired: 'Login user is required',
        allowedPathsRequired: 'Keep at least one readable path',
        editSecretNote: 'Leave credential fields blank to keep them unchanged',
        backendEnv: 'The credential backend is env: provide passwords/passphrases through environment variables.',
        backendNone: 'The credential backend is none: the page cannot save passwords.',
        nextStep: 'Next step',
      },
    }

    const CSS = [
      '.sshh-btn { transition: background-color 120ms ease, color 120ms ease; }',
      '.sshh-btn:hover { background: var(--dsw-alias-bg-layer-2) !important; color: var(--dsw-alias-label-primary) !important; }',
      '.sshh-btn:focus-visible { outline: 2px solid var(--dsw-alias-brand-primary); outline-offset: 1px; }',
      '.sshh-row:hover { background: var(--dsw-alias-bg-layer-2); }',
      '.sshh-cmd { cursor: pointer; }',
      '.sshh-scroll { scrollbar-width: thin; }',
      '.sshh-scroll::-webkit-scrollbar { width: 8px; }',
      '.sshh-scroll::-webkit-scrollbar-thumb { background: var(--dsw-alias-border-l2); border-radius: 8px; }',
      '.sshh-field { font-size: 12px; height: 26px; padding: 0 8px; border-radius: 7px;',
      '  border: 1px solid var(--dsw-alias-border-l1); background: var(--dsw-alias-bg-layer-1);',
      '  color: var(--dsw-alias-label-primary); outline: none; font-family: inherit; }',
      '.sshh-field:focus { border-color: var(--dsw-alias-brand-primary); }',
    ].join('\n')

    const SERVER_CSS = [
      '.sshs-page { box-sizing: border-box; height: 100%; min-height: 0; overflow-y: auto;',
      '  padding: 24px 28px 48px; background: var(--dsw-alias-bg-base); color: var(--dsw-alias-label-primary);',
      `  font-family: ${FONT}; font-size: 13px; line-height: 1.45; }`,
      '.sshs-inner { max-width: 1040px; margin: 0 auto; display: flex; flex-direction: column; gap: 14px; }',
      '.sshs-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; flex-wrap: wrap; }',
      '.sshs-head-main { min-width: 220px; display: flex; flex-direction: column; gap: 4px; }',
      '.sshs-title { margin: 0; font-size: 21px; line-height: 28px; font-weight: 600; }',
      '.sshs-sub { margin: 0; font-size: 12px; line-height: 18px; color: var(--dsw-alias-label-secondary); }',
      '.sshs-head-actions { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }',
      '.sshs-btn { display: inline-flex; align-items: center; justify-content: center; gap: 6px; height: 32px;',
      '  padding: 0 14px; border-radius: 8px; border: 1px solid var(--dsw-alias-border-l1);',
      '  background: var(--dsw-alias-bg-layer-1); color: var(--dsw-alias-label-primary); font: inherit;',
      '  font-size: 12.5px; cursor: pointer; white-space: nowrap; }',
      '.sshs-btn:hover:not(:disabled) { background: var(--dsw-alias-interactive-bg-hover); }',
      '.sshs-btn:disabled { opacity: .5; cursor: default; }',
      '.sshs-btn:focus-visible { outline: 2px solid var(--dsw-alias-brand-primary); outline-offset: 1px; }',
      '.sshs-btn-primary { background: var(--dsw-alias-brand-primary); border-color: transparent;',
      '  color: var(--dsw-alias-label-primary-foreground, #fff); }',
      '.sshs-btn-primary:hover:not(:disabled) { background: var(--dsw-alias-brand-primary); filter: brightness(1.06); }',
      '.sshs-mini { display: inline-flex; align-items: center; justify-content: center; height: 27px; padding: 0 10px;',
      '  border-radius: 7px; border: 1px solid var(--dsw-alias-border-l1); background: transparent;',
      '  color: var(--dsw-alias-label-primary); font: inherit; font-size: 12px; cursor: pointer; white-space: nowrap; }',
      '.sshs-mini:hover:not(:disabled) { background: var(--dsw-alias-interactive-bg-hover); }',
      '.sshs-mini:disabled { opacity: .45; cursor: default; }',
      '.sshs-danger { color: var(--dsw-alias-state-error-primary); }',
      '.sshs-danger:hover:not(:disabled) { background: var(--dsw-alias-interactive-bg-hover); }',
      '.sshs-list { display: flex; flex-direction: column; gap: 10px; }',
      '.sshs-card { display: flex; flex-direction: column; gap: 9px; padding: 14px 16px;',
      '  border: 1px solid var(--dsw-alias-border-l1); border-radius: 12px; background: var(--dsw-alias-bg-layer-1); }',
      '.sshs-card-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; flex-wrap: wrap; }',
      '.sshs-card-title { display: flex; align-items: baseline; gap: 9px; flex-wrap: wrap; min-width: 0; }',
      '.sshs-alias { font-size: 15px; font-weight: 600; }',
      '.sshs-addr { font-family: ' + MONO + '; font-size: 12px; color: var(--dsw-alias-label-secondary); }',
      '.sshs-card-actions { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }',
      '.sshs-badges { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }',
      '.sshs-badge { display: inline-flex; align-items: center; height: 20px; padding: 0 7px; border-radius: 5px;',
      '  background: var(--dsw-alias-bg-layer-2); color: var(--dsw-alias-label-secondary); font-size: 11px; white-space: nowrap; }',
      '.sshs-badge-ok { color: var(--dsw-alias-state-success-primary); }',
      '.sshs-badge-bad { color: var(--dsw-alias-state-error-primary); }',
      '.sshs-badge-warn { color: var(--dsw-alias-state-warn-primary); }',
      '.sshs-paths { display: flex; gap: 14px; flex-wrap: wrap; font-size: 11.5px; color: var(--dsw-alias-label-secondary); }',
      '.sshs-paths span { min-width: 0; word-break: break-all; }',
      '.sshs-tags { display: flex; gap: 6px; flex-wrap: wrap; }',
      '.sshs-tag { font-size: 11px; padding: 1px 7px; border-radius: 999px; background: var(--dsw-alias-bg-layer-2);',
      '  color: var(--dsw-alias-label-secondary); }',
      '.sshs-note { font-size: 12px; line-height: 18px; color: var(--dsw-alias-label-secondary); white-space: pre-wrap; }',
      '.sshs-test { font-size: 12px; line-height: 18px; border-radius: 7px; padding: 7px 10px; background: var(--dsw-alias-bg-layer-2); }',
      '.sshs-test-ok { color: var(--dsw-alias-state-success-primary); }',
      '.sshs-test-bad { color: var(--dsw-alias-state-error-primary); }',
      '.sshs-test span { color: var(--dsw-alias-label-secondary); }',
      '.sshs-empty { padding: 44px 22px; text-align: center; border: 1px dashed var(--dsw-alias-border-l2);',
      '  border-radius: 12px; color: var(--dsw-alias-label-secondary); font-size: 12.5px; line-height: 20px; }',
      '.sshs-notice { display: flex; flex-direction: column; gap: 3px; border: 1px solid var(--dsw-alias-border-l1);',
      '  border-left: 3px solid var(--dsw-alias-brand-primary); border-radius: 8px; padding: 9px 12px;',
      '  font-size: 12px; line-height: 18px; background: var(--dsw-alias-bg-layer-1); }',
      '.sshs-notice-error { border-left-color: var(--dsw-alias-state-error-primary); }',
      '.sshs-notice-warn { border-left-color: var(--dsw-alias-state-warn-primary); }',
      '.sshs-form-head { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }',
      '.sshs-form-title { margin: 0; font-size: 18px; line-height: 24px; font-weight: 600; flex: 1; min-width: 140px; }',
      '.sshs-form { display: flex; flex-direction: column; gap: 12px; }',
      '.sshs-section { display: flex; flex-direction: column; gap: 12px; padding: 14px 16px;',
      '  border: 1px solid var(--dsw-alias-border-l1); border-radius: 12px; background: var(--dsw-alias-bg-layer-1); }',
      '.sshs-section-title { font-size: 13px; font-weight: 600; }',
      '.sshs-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 12px; }',
      '.sshs-label { display: flex; flex-direction: column; gap: 5px; min-width: 0; }',
      '.sshs-label-text { font-size: 11.5px; color: var(--dsw-alias-label-secondary); }',
      '.sshs-field { box-sizing: border-box; width: 100%; height: 32px; padding: 0 9px; border-radius: 7px;',
      '  border: 1px solid var(--dsw-alias-border-l1); background: var(--dsw-alias-bg-base);',
      '  color: var(--dsw-alias-label-primary); font: inherit; font-size: 12.5px; outline: none; min-width: 0; }',
      '.sshs-field:focus { border-color: var(--dsw-alias-brand-primary); }',
      '.sshs-field:disabled { opacity: .6; }',
      '.sshs-textarea { height: auto; min-height: 64px; padding: 7px 9px; resize: vertical;',
      '  font-family: ' + MONO + '; font-size: 12px; line-height: 18px; }',
      '.sshs-hint { font-size: 11px; line-height: 16px; color: var(--dsw-alias-label-tertiary); }',
      '.sshs-hint-bad { color: var(--dsw-alias-state-error-primary); }',
      '.sshs-check { display: flex; align-items: center; gap: 8px; font-size: 12.5px; cursor: pointer; }',
      '.sshs-row-inline { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }',
      '.sshs-services { display: flex; flex-direction: column; gap: 8px; }',
      '.sshs-service { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 8px;',
      '  align-items: end; padding: 10px; border: 1px dashed var(--dsw-alias-border-l2); border-radius: 9px; }',
      '.sshs-service-actions { grid-column: 1 / -1; display: flex; justify-content: flex-end; }',
      '.sshs-security { font-size: 11px; line-height: 16px; color: var(--dsw-alias-label-tertiary); }',
    ].join('\n')

    const HISTORY_ACTIONS = ['exec', 'read', 'write', 'upload', 'download', 'test']

    function detectLang(ctx) {
      try {
        const service = ctx && ctx.get ? ctx.get('locale') : undefined
        const snapshot = service && service.getLocale ? service.getLocale() : null
        const raw = JSON.stringify(snapshot || {}).toLowerCase()
        if (raw.indexOf('zh') >= 0) return 'zh'
        if (raw.indexOf('en') >= 0) return 'en'
      } catch (error) {
        // No locale service: fall through to the default.
      }
      return 'zh'
    }

    function pad(value) {
      return value < 10 ? '0' + value : '' + value
    }

    function formatTime(iso) {
      const date = new Date(iso)
      if (isNaN(date.getTime())) return typeof iso === 'string' ? iso : ''
      return pad(date.getHours()) + ':' + pad(date.getMinutes()) + ':' + pad(date.getSeconds())
    }

    function formatDuration(ms) {
      if (typeof ms !== 'number' || isNaN(ms)) return ''
      if (ms < 1000) return Math.round(ms) + ' ms'
      return (ms / 1000).toFixed(1) + ' s'
    }

    function splitLines(text) {
      return String(text || '')
        .split(/\r?\n|,/)
        .map((entry) => entry.trim())
        .filter((entry) => entry.length > 0)
    }

    function splitTags(text) {
      return String(text || '')
        .split(',')
        .map((entry) => entry.trim())
        .filter((entry) => entry.length > 0)
    }

    function portFrom(text) {
      const raw = String(text || '').trim()
      if (raw.length === 0) return undefined
      const value = Number(raw)
      return Number.isFinite(value) ? Math.trunc(value) : undefined
    }

    function HistoryIcon() {
      return h(
        'svg',
        {
          width: 16,
          height: 16,
          viewBox: '0 0 16 16',
          fill: 'none',
          stroke: 'currentColor',
          strokeWidth: 1.5,
          strokeLinecap: 'round',
          strokeLinejoin: 'round',
          'aria-hidden': 'true',
          focusable: 'false',
          style: { display: 'block', flex: 'none' },
        },
        h('rect', { key: 'frame', x: 1.75, y: 2.25, width: 12.5, height: 11.5, rx: 2.5 }),
        h('path', { key: 'prompt', d: 'M4.6 6.2 6.3 7.7 4.6 9.2' }),
        h('path', { key: 'line', d: 'M8 9.4h3.3' }),
      )
    }

    function ServerIcon(props) {
      const size = props && typeof props.size === 'number' ? props.size : 16
      return h(
        'svg',
        {
          width: size,
          height: size,
          viewBox: '0 0 16 16',
          fill: 'none',
          stroke: 'currentColor',
          strokeWidth: 1.5,
          strokeLinecap: 'round',
          strokeLinejoin: 'round',
          'aria-hidden': 'true',
          focusable: 'false',
          style: { display: 'block', flex: 'none' },
        },
        h('rect', { key: 'top', x: 2, y: 2.2, width: 12, height: 4.6, rx: 1.3 }),
        h('rect', { key: 'bottom', x: 2, y: 9.2, width: 12, height: 4.6, rx: 1.3 }),
        h('path', { key: 'dot1', d: 'M4.2 4.5h.01' }),
        h('path', { key: 'dot2', d: 'M4.2 11.5h.01' }),
        h('path', { key: 'line1', d: 'M7 4.5h4.8' }),
        h('path', { key: 'line2', d: 'M7 11.5h4.8' }),
      )
    }

    function mount(ctx) {
      const lang = detectLang(ctx)
      const copy = COPY[lang] || COPY.zh
      const serverCopy = SERVER_COPY[lang] || SERVER_COPY.zh

      // Shared open/closed state: the sidebar button and the drawer are two
      // independent slot entries, so they meet in this tiny store.
      let open = false
      const watchers = new Set()

      function setOpen(next) {
        if (open === next) return
        open = next
        watchers.forEach((watcher) => {
          try {
            watcher()
          } catch (error) {
            // A stale watcher must not break the toggle.
          }
        })
      }

      function useOpen() {
        const [value, setValue] = React.useState(open)
        React.useEffect(() => {
          const watcher = () => setValue(open)
          watchers.add(watcher)
          watcher()
          return () => {
            watchers.delete(watcher)
          }
        }, [])
        return value
      }

      function buttonStyle(active) {
        return {
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          width: 26,
          height: 26,
          padding: 0,
          border: '1px solid transparent',
          borderRadius: 7,
          background: active ? 'var(--dsw-alias-bg-layer-2)' : 'transparent',
          color: 'var(--dsw-alias-label-secondary)',
          fontFamily: FONT,
          fontSize: 13,
          cursor: 'pointer',
          flex: 'none',
        }
      }

      function badge(key, text, color, background) {
        return h(
          'span',
          {
            key: key,
            style: {
              display: 'inline-flex',
              alignItems: 'center',
              height: 18,
              padding: '0 6px',
              borderRadius: 5,
              fontSize: 11,
              lineHeight: '18px',
              whiteSpace: 'nowrap',
              color: color,
              background: background || 'transparent',
            },
          },
          text,
        )
      }

      function Trigger(props) {
        const isOpen = useOpen()
        const wide = props && props.wide === true
        return h(
          'button',
          {
            type: 'button',
            className: 'sshh-btn',
            title: copy.trigger,
            'aria-label': copy.trigger,
            'aria-expanded': isOpen ? 'true' : 'false',
            onClick: () => {
              setOpen(!isOpen)
            },
            style: {
              display: 'flex',
              alignItems: 'center',
              justifyContent: wide ? 'flex-start' : 'center',
              gap: 8,
              width: wide ? '100%' : 32,
              height: 32,
              padding: wide ? '0 10px' : 0,
              border: '1px solid transparent',
              borderRadius: 8,
              background: isOpen ? 'var(--dsw-alias-bg-layer-2)' : 'transparent',
              color: isOpen ? 'var(--dsw-alias-label-primary)' : 'var(--dsw-alias-label-secondary)',
              fontFamily: FONT,
              fontSize: 13,
              cursor: 'pointer',
              overflow: 'hidden',
              whiteSpace: 'nowrap',
            },
          },
          h(HistoryIcon),
          wide ? h('span', { style: { overflow: 'hidden', textOverflow: 'ellipsis' } }, copy.trigger) : null,
        )
      }

      function serverDisplay(server) {
        if (Array.isArray(server.aliases) && server.aliases.length > 0) return server.aliases.join(' / ')
        return String(server.ip || server.alias || server.id || '')
      }

      function deriveServers(entries) {
        const map = new Map()
        for (let index = 0; index < entries.length; index += 1) {
          const entry = entries[index]
          const address = typeof entry.serverIp === 'string' && entry.serverIp.length > 0 ? entry.serverIp : null
          const label = address || entry.server
          if (typeof label !== 'string' || label.length === 0) continue
          const id =
            typeof entry.serverId === 'string' && entry.serverId.length > 0
              ? entry.serverId
              : address || entry.server
          const current = map.get(id)
          if (current === undefined) map.set(id, { id: id, ip: label, count: 1, aliases: [entry.server] })
          else current.count += 1
        }
        return Array.from(map.values()).sort((left, right) => left.ip.localeCompare(right.ip))
      }

      function Panel() {
        const isOpen = useOpen()
        const [state, setState] = React.useState({
          entries: [],
          servers: [],
          total: 0,
          auditEnabled: true,
          ready: false,
        })
        const [error, setError] = React.useState(null)
        const [loading, setLoading] = React.useState(false)
        const [reloadKey, setReloadKey] = React.useState(0)
        const [serverFilter, setServerFilter] = React.useState('')
        const [actionFilter, setActionFilter] = React.useState('')
        const [failedOnly, setFailedOnly] = React.useState(false)
        const [search, setSearch] = React.useState('')
        const [expanded, setExpanded] = React.useState({})

        React.useEffect(() => {
          if (!isOpen) return undefined
          const onKeyDown = (event) => {
            if (event.key === 'Escape') setOpen(false)
          }
          window.addEventListener('keydown', onKeyDown)
          return () => {
            window.removeEventListener('keydown', onKeyDown)
          }
        }, [isOpen])

        React.useEffect(() => {
          if (!isOpen) return undefined
          let disposed = false
          const run = () => {
            setLoading(true)
            window
              .fetch(HISTORY_ENDPOINT + '?limit=' + SERVER_LIMIT, {
                headers: { accept: 'application/json' },
                cache: 'no-store',
              })
              .then((response) => {
                if (!response.ok) throw new Error('HTTP ' + response.status)
                const type = (response.headers.get('content-type') || '').toLowerCase()
                if (type.indexOf('json') < 0) throw new Error('HTTP ' + response.status + ' (non-JSON)')
                return response.json()
              })
              .then((page) => {
                if (disposed) return
                const entries = Array.isArray(page.entries) ? page.entries : []
                const servers = (Array.isArray(page.servers) ? page.servers : deriveServers(entries))
                  .slice()
                  .sort((left, right) => serverDisplay(left).localeCompare(serverDisplay(right)))
                setState({
                  entries: entries,
                  servers: servers,
                  total: typeof page.total === 'number' ? page.total : 0,
                  auditEnabled: page.auditEnabled !== false,
                  ready: true,
                })
                setError(null)
              })
              .catch((failure) => {
                if (disposed) return
                setError(failure && failure.message ? failure.message : String(failure))
              })
              .then(() => {
                if (!disposed) setLoading(false)
              })
          }
          run()
          const timer = window.setInterval(run, REFRESH_MS)
          window.addEventListener('focus', run)
          return () => {
            disposed = true
            window.clearInterval(timer)
            window.removeEventListener('focus', run)
          }
        }, [isOpen, reloadKey])

        if (!isOpen) return null

        const entries = state.entries
        const servers = state.servers
        const wantedServer = servers.find((server) => server.id === serverFilter) || null

        const needle = search.trim().toLowerCase()
        const visible = []
        for (let index = 0; index < entries.length; index += 1) {
          const entry = entries[index]
          if (serverFilter) {
            if (wantedServer !== null) {
              const byGroup = typeof entry.serverId === 'string' && entry.serverId === wantedServer.id
              const byIp = typeof wantedServer.ip === 'string' && entry.serverIp === wantedServer.ip
              const aliases = Array.isArray(wantedServer.aliases) ? wantedServer.aliases : []
              const byAlias = entry.serverId === undefined && aliases.indexOf(entry.server) >= 0
              if (!byGroup && !byIp && !byAlias) continue
            } else if (entry.server !== serverFilter) {
              continue
            }
          }
          if (actionFilter && entry.action !== actionFilter) continue
          if (failedOnly && entry.ok !== false) continue
          if (needle) {
            const haystack = ((entry.command || '') + '\n' + (entry.path || '')).toLowerCase()
            if (haystack.indexOf(needle) < 0) continue
          }
          visible.push(entry)
        }

        const toggleExpanded = (index) => {
          setExpanded((previous) => {
            const next = {}
            for (const key in previous) next[key] = previous[key]
            next[index] = previous[index] !== true
            return next
          })
        }

        const renderRow = (entry, index) => {
          const exitCode = entry.exitCode
          const isFailure = entry.ok === false || (typeof exitCode === 'number' && exitCode !== 0)
          const detail = entry.command || entry.path || entry.code || entry.user || ''
          const long = detail.length > 160
          const isExpanded = expanded[index] === true
          const rule = exitCode === undefined || exitCode === null ? '—' : String(exitCode)

          const meta = [
            h(
              'span',
              {
                key: 'time',
                style: {
                  fontFamily: MONO,
                  fontSize: 11,
                  color: 'var(--dsw-alias-label-secondary)',
                },
              },
              formatTime(entry.time),
            ),
            badge(
              'action',
              copy.actions[entry.action] || entry.action,
              'var(--dsw-alias-label-secondary)',
              'var(--dsw-alias-bg-layer-2)',
            ),
            badge('server', entry.server, 'var(--dsw-alias-brand-primary)', 'transparent'),
          ]

          if (exitCode !== undefined) {
            meta.push(
              badge(
                'exit',
                copy.exit + ' ' + rule,
                isFailure
                  ? 'var(--dsw-alias-state-error-primary)'
                  : 'var(--dsw-alias-state-success-primary)',
                'transparent',
              ),
            )
          }
          if (typeof entry.durationMs === 'number') {
            meta.push(
              badge('duration', formatDuration(entry.durationMs), 'var(--dsw-alias-label-secondary)', 'transparent'),
            )
          }
          if (entry.approval === 'granted' || entry.approval === 'policy-allow') {
            meta.push(
              badge(
                'approval',
                entry.approval === 'granted' ? copy.approved : copy.policyAllowed,
                'var(--dsw-alias-state-warn-primary)',
                'transparent',
              ),
            )
          }
          if (entry.truncated === true) {
            meta.push(badge('truncated', copy.truncated, 'var(--dsw-alias-state-warn-primary)', 'transparent'))
          }

          return h(
            'div',
            {
              key: 'row-' + index,
              className: 'sshh-row',
              style: {
                display: 'flex',
                flexDirection: 'column',
                gap: 5,
                padding: '9px 14px',
                borderBottom: '1px solid var(--dsw-alias-border-l1)',
              },
            },
            h('div', { style: { display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' } }, meta),
            h(
              'div',
              {
                className: long ? 'sshh-cmd' : undefined,
                title: long && !isExpanded ? copy.expand : undefined,
                onClick: long
                  ? () => {
                      toggleExpanded(index)
                    }
                  : undefined,
                style: {
                  fontFamily: MONO,
                  fontSize: 12.5,
                  lineHeight: '18px',
                  color: 'var(--dsw-alias-label-primary)',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                  maxHeight: long && !isExpanded ? 54 : undefined,
                  overflow: long && !isExpanded ? 'hidden' : undefined,
                },
              },
              '$ ' + detail,
            ),
          )
        }

        const header = h(
          'header',
          {
            key: 'header',
            style: {
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              padding: '11px 14px',
              borderBottom: '1px solid var(--dsw-alias-border-l1)',
              flex: 'none',
            },
          },
          h(
            'div',
            { style: { display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0, flex: 1 } },
            h(
              'div',
              { style: { display: 'flex', alignItems: 'center', gap: 7 } },
              h('span', { style: { color: 'var(--dsw-alias-brand-primary)', display: 'flex' } }, h(HistoryIcon)),
              h('strong', { style: { fontSize: 14, fontWeight: 600 } }, copy.title),
              h(
                'span',
                { style: { fontSize: 11, color: 'var(--dsw-alias-label-secondary)' } },
                state.total + ' ' + copy.count,
              ),
              state.auditEnabled
                ? null
                : badge('audit-off', copy.auditOff, 'var(--dsw-alias-state-warn-primary)', 'transparent'),
            ),
            h(
              'span',
              {
                style: {
                  fontSize: 11,
                  color: 'var(--dsw-alias-label-secondary)',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                },
              },
              copy.subtitle,
            ),
          ),
          h(
            'button',
            {
              type: 'button',
              className: 'sshh-btn',
              title: copy.refresh,
              'aria-label': copy.refresh,
              onClick: () => {
                setReloadKey((value) => value + 1)
              },
              style: buttonStyle(loading),
            },
            loading ? '…' : '⟳',
          ),
          h(
            'button',
            {
              type: 'button',
              className: 'sshh-btn',
              title: copy.close,
              'aria-label': copy.close,
              onClick: () => {
                setOpen(false)
              },
              style: buttonStyle(false),
            },
            '✕',
          ),
        )

        const filters = h(
          'div',
          {
            key: 'filters',
            style: {
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              flexWrap: 'wrap',
              padding: '8px 14px',
              borderBottom: '1px solid var(--dsw-alias-border-l1)',
              flex: 'none',
            },
          },
          h(
            'select',
            {
              className: 'sshh-field',
              value: serverFilter,
              onChange: (event) => {
                setServerFilter(event.target.value)
              },
              'aria-label': copy.allServers,
            },
            h('option', { value: '' }, copy.allServers),
            servers.map((server) =>
              h(
                'option',
                { key: server.id, value: server.id },
                serverDisplay(server) + (server.count > 0 ? ' · ' + server.count : ''),
              ),
            ),
          ),
          h(
            'select',
            {
              className: 'sshh-field',
              value: actionFilter,
              onChange: (event) => {
                setActionFilter(event.target.value)
              },
              'aria-label': copy.allActions,
            },
            h('option', { value: '' }, copy.allActions),
            HISTORY_ACTIONS.map((action) => h('option', { key: action, value: action }, copy.actions[action] || action)),
          ),
          h('input', {
            className: 'sshh-field',
            type: 'search',
            value: search,
            placeholder: copy.search,
            'aria-label': copy.search,
            onChange: (event) => {
              setSearch(event.target.value)
            },
            style: { flex: 1, minWidth: 120 },
          }),
          h(
            'label',
            {
              style: {
                display: 'inline-flex',
                alignItems: 'center',
                gap: 5,
                fontSize: 12,
                color: 'var(--dsw-alias-label-secondary)',
                cursor: 'pointer',
                whiteSpace: 'nowrap',
              },
            },
            h('input', {
              type: 'checkbox',
              checked: failedOnly,
              onChange: (event) => {
                setFailedOnly(event.target.checked)
              },
            }),
            copy.failedOnly,
          ),
        )

        const emptyBox =
          visible.length > 0
            ? null
            : h(
                'div',
                {
                  key: 'empty',
                  style: {
                    padding: '36px 22px',
                    textAlign: 'center',
                    fontSize: 12.5,
                    lineHeight: '20px',
                    color: 'var(--dsw-alias-label-secondary)',
                  },
                },
                state.ready ? copy.empty : copy.loading,
              )

        const errorBox = error
          ? h(
              'div',
              {
                key: 'error',
                style: {
                  margin: '12px 14px',
                  padding: '10px 12px',
                  borderRadius: 8,
                  border: '1px solid var(--dsw-alias-state-error-primary)',
                  color: 'var(--dsw-alias-state-error-primary)',
                  fontSize: 12,
                  lineHeight: '18px',
                },
              },
              h('div', { style: { fontWeight: 600 } }, copy.error),
              h('div', { style: { fontFamily: MONO, wordBreak: 'break-all' } }, error),
              h('div', { style: { marginTop: 4, color: 'var(--dsw-alias-label-secondary)' } }, copy.notFound),
              h(
                'button',
                {
                  type: 'button',
                  className: 'sshh-btn',
                  onClick: () => {
                    setReloadKey((value) => value + 1)
                  },
                  style: Object.assign(buttonStyle(false), { marginTop: 8, width: 'auto', padding: '0 10px' }),
                },
                copy.retry,
              ),
            )
          : null

        const footer = h(
          'footer',
          {
            key: 'footer',
            style: {
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              justifyContent: 'space-between',
              padding: '7px 14px',
              borderTop: '1px solid var(--dsw-alias-border-l1)',
              fontSize: 11,
              color: 'var(--dsw-alias-label-secondary)',
              flex: 'none',
            },
          },
          h(
            'span',
            { style: { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } },
            copy.footerHint,
          ),
          h('span', { style: { fontFamily: MONO, flex: 'none' } }, visible.length + ' / ' + entries.length),
        )

        return h(
          'div',
          {
            key: 'backdrop',
            style: {
              position: 'fixed',
              inset: 0,
              zIndex: 60,
              display: 'flex',
              justifyContent: 'flex-end',
              // Leave the Windows/macOS title bar and its window controls clear;
              // otherwise the drawer's ✕ sits under the native ✕.
              padding: 'max(24px, var(--dsh-frame-overlay-top, 24px)) 12px 12px',
              background: 'rgba(0,0,0,0.34)',
              pointerEvents: 'auto',
            },
            onMouseDown: (event) => {
              if (event.target === event.currentTarget) setOpen(false)
            },
          },
          h('style', { key: 'css' }, CSS),
          h(
            'section',
            {
              key: 'drawer',
              role: 'dialog',
              'aria-modal': 'true',
              'aria-label': copy.title,
              style: {
                display: 'flex',
                flexDirection: 'column',
                width: 'min(680px, 100%)',
                height: '100%',
                overflow: 'hidden',
                background: 'var(--dsw-alias-bg-overlay)',
                color: 'var(--dsw-alias-label-primary)',
                border: '1px solid var(--dsw-alias-border-l1)',
                borderRadius: 14,
                boxShadow: '0 24px 64px rgba(0,0,0,0.42)',
                fontFamily: FONT,
                fontSize: 13,
              },
            },
            header,
            filters,
            h(
              'div',
              {
                key: 'list',
                className: 'sshh-scroll',
                style: { flex: 1, minHeight: 0, overflowY: 'auto' },
              },
              errorBox,
              emptyBox,
              visible.map(renderRow),
            ),
            footer,
          ),
        )
      }

      async function serverRequest(method, path, body) {
        const headers = { accept: 'application/json', 'x-ssh-hosts-ui': '1' }
        if (body !== undefined) headers['content-type'] = 'application/json'
        const response = await window.fetch(SERVERS_API + path, {
          method: method,
          headers: headers,
          body: body === undefined ? undefined : JSON.stringify(body),
          cache: 'no-store',
        })
        const type = (response.headers.get('content-type') || '').toLowerCase()
        let payload = null
        if (type.indexOf('json') >= 0) {
          try {
            payload = await response.json()
          } catch (error) {
            payload = null
          }
        }
        if (!response.ok) {
          const detail = payload && payload.error ? payload.error : null
          const failure = new Error(detail && detail.message ? detail.message : 'HTTP ' + response.status)
          failure.code = detail && detail.code ? detail.code : ''
          failure.hint = detail && detail.hint ? detail.hint : null
          failure.status = response.status
          failure.missingEndpoint = response.status === 404
          throw failure
        }
        return payload || {}
      }

      function blankForm() {
        return {
          alias: '',
          host: '',
          port: '22',
          username: '',
          authType: 'password',
          originalAuthType: 'password',
          privateKeyPath: '',
          password: '',
          passphrase: '',
          defaultCwd: '',
          allowedPaths: '~',
          editablePaths: '',
          sudoMode: 'off',
          sudoUser: '',
          sudoPassword: '',
          sudoPasswordConfigured: false,
          fingerprintPolicy: 'accept-new',
          hostKeyFingerprint: '',
          readOnly: false,
          tags: '',
          note: '',
          services: [],
          hasFingerprint: false,
          fingerprint: null,
          credentialStatus: 'missing',
        }
      }

      function formFromHost(host) {
        return {
          alias: host.alias || '',
          host: host.host || '',
          port: String(host.port === undefined ? 22 : host.port),
          username: host.username || '',
          authType: host.authType === 'key' ? 'key' : 'password',
          originalAuthType: host.authType === 'key' ? 'key' : 'password',
          privateKeyPath: '',
          password: '',
          passphrase: '',
          defaultCwd: host.defaultCwd || '',
          allowedPaths: (host.allowedPaths || []).join('\n'),
          editablePaths: (host.editablePaths || []).join('\n'),
          sudoMode: host.sudo && host.sudo.mode !== 'off' ? host.sudo.mode : 'off',
          sudoUser: host.sudo && host.sudo.user ? host.sudo.user : '',
          sudoPassword: '',
          sudoPasswordConfigured: host.sudo ? host.sudo.passwordConfigured === true : false,
          fingerprintPolicy: host.fingerprintPolicy === 'strict' ? 'strict' : 'accept-new',
          hostKeyFingerprint: '',
          readOnly: host.readOnly === true,
          tags: (host.tags || []).join(', '),
          note: host.note || '',
          services: (host.services || []).map((service) => ({
            name: service.name || '',
            directory: service.directory || '',
            description: service.description || '',
            startCommand: service.startCommand || '',
            logPath: service.logPath || '',
            port: service.port === undefined ? '' : String(service.port),
          })),
          hasFingerprint: host.hasFingerprint === true,
          fingerprint: host.fingerprint || null,
          credentialStatus: host.credentialStatus || 'missing',
        }
      }

      function payloadFromForm(form) {
        const body = {
          alias: form.alias.trim(),
          host: form.host.trim(),
          username: form.username.trim(),
          authType: form.authType,
          allowedPaths: splitLines(form.allowedPaths),
          editablePaths: splitLines(form.editablePaths),
          defaultCwd: form.defaultCwd.trim(),
          fingerprintPolicy: form.fingerprintPolicy,
          readOnly: form.readOnly === true,
          tags: splitTags(form.tags),
          note: form.note.trim(),
          services: (form.services || [])
            .map((service) => {
              const port = portFrom(service.port)
              return {
                name: String(service.name || '').trim(),
                directory: String(service.directory || '').trim(),
                ...(String(service.description || '').trim().length > 0
                  ? { description: String(service.description).trim() }
                  : {}),
                ...(String(service.startCommand || '').trim().length > 0
                  ? { startCommand: String(service.startCommand).trim() }
                  : {}),
                ...(String(service.logPath || '').trim().length > 0
                  ? { logPath: String(service.logPath).trim() }
                  : {}),
                ...(port === undefined ? {} : { port: port }),
              }
            })
            .filter((service) => service.name.length > 0 && service.directory.length > 0),
        }
        const port = portFrom(form.port)
        if (port !== undefined) body.port = port
        if (form.authType === 'key' && form.privateKeyPath.trim().length > 0) {
          body.privateKeyPath = form.privateKeyPath.trim()
        }
        if (form.hostKeyFingerprint.trim().length > 0) {
          body.hostKeyFingerprint = form.hostKeyFingerprint.trim()
        }
        if (form.password.length > 0) body.password = form.password
        if (form.authType === 'key' && form.passphrase.length > 0) body.passphrase = form.passphrase
        const sudoUser = form.sudoUser.trim()
        body.sudo = {
          mode: form.sudoMode === 'off' ? 'off' : form.sudoMode,
          ...(sudoUser.length > 0 ? { user: sudoUser } : {}),
          ...(form.sudoMode === 'password' && form.sudoPassword.length > 0 ? { password: form.sudoPassword } : {}),
        }
        return body
      }

      function validateForm(form, isEdit) {
        if (form.alias.trim().length === 0) return serverCopy.aliasRequired
        if (form.host.trim().length === 0) return serverCopy.hostRequired
        if (form.username.trim().length === 0) return serverCopy.userRequired
        if (form.authType === 'key' && form.privateKeyPath.trim().length === 0) {
          // On edit the existing path is hidden; an empty field keeps it.
          if (!isEdit || form.originalAuthType !== 'key') return serverCopy.keyAuthNeedsPath
        }
        if (splitLines(form.allowedPaths).length === 0) return serverCopy.allowedPathsRequired
        return null
      }

      function ServersPage() {
        const [hosts, setHosts] = React.useState([])
        const [loading, setLoading] = React.useState(true)
        const [error, setError] = React.useState(null)
        const [notice, setNotice] = React.useState(null)
        const [editing, setEditing] = React.useState(null)
        const [testing, setTesting] = React.useState('')
        const [testResults, setTestResults] = React.useState({})
        const [busy, setBusy] = React.useState('')

        const load = (quiet) => {
          if (!quiet) setLoading(true)
          return serverRequest('GET', '/hosts')
            .then((page) => {
              setHosts(Array.isArray(page.hosts) ? page.hosts : [])
              setError(null)
            })
            .catch((failure) => {
              setError(failure)
            })
            .then(() => {
              setLoading(false)
            })
        }

        React.useEffect(() => {
          void load(false)
        }, [])

        const showNotice = (tone, text, hint) => {
          setNotice({ tone: tone, text: text, hint: hint || null })
        }

        const openCreate = () => {
          setNotice(null)
          setEditing({ id: null, form: blankForm(), error: null, saving: false })
        }

        const openEdit = (host) => {
          setNotice(null)
          setEditing({ id: host.id, form: formFromHost(host), error: null, saving: false })
        }

        const closeEditor = () => {
          setEditing(null)
        }

        const updateForm = (patch) => {
          setEditing((previous) => {
            if (previous === null) return previous
            return Object.assign({}, previous, {
              form: Object.assign({}, previous.form, patch),
              error: null,
            })
          })
        }

        const updateService = (index, key, value) => {
          setEditing((previous) => {
            if (previous === null) return previous
            const services = previous.form.services.map((service, position) =>
              position === index ? Object.assign({}, service, { [key]: value }) : service,
            )
            return Object.assign({}, previous, { form: Object.assign({}, previous.form, { services: services }) })
          })
        }

        const addService = () => {
          setEditing((previous) => {
            if (previous === null) return previous
            const services = previous.form.services.concat([
              { name: '', directory: '', description: '', startCommand: '', logPath: '', port: '' },
            ])
            return Object.assign({}, previous, { form: Object.assign({}, previous.form, { services: services }) })
          })
        }

        const removeService = (index) => {
          setEditing((previous) => {
            if (previous === null) return previous
            const services = previous.form.services.filter((service, position) => position !== index)
            return Object.assign({}, previous, { form: Object.assign({}, previous.form, { services: services }) })
          })
        }

        const save = async () => {
          if (editing === null || editing.saving) return
          const invalid = validateForm(editing.form, editing.id !== null)
          if (invalid !== null) {
            setEditing(Object.assign({}, editing, { error: new Error(invalid) }))
            return
          }
          const current = editing
          setEditing(Object.assign({}, current, { saving: true, error: null }))
          try {
            const body = payloadFromForm(current.form)
            const result =
              current.id === null
                ? await serverRequest('POST', '/hosts', body)
                : await serverRequest('PATCH', '/hosts/' + encodeURIComponent(current.id), body)
            const host = result.host || {}
            showNotice(
              result.nextStep ? 'warn' : 'ok',
              (current.id === null ? serverCopy.added : serverCopy.saved) + ' ' + (host.alias || ''),
              result.nextStep || null,
            )
            setEditing(null)
            await load(true)
          } catch (failure) {
            setEditing(Object.assign({}, current, { saving: false, error: failure }))
          }
        }

        const removeHost = async (host) => {
          if (!window.confirm(serverCopy.deleteConfirm.replace('{alias}', host.alias))) return
          setBusy('delete:' + host.id)
          try {
            await serverRequest('DELETE', '/hosts/' + encodeURIComponent(host.id))
            showNotice('ok', serverCopy.deleted + ' ' + host.alias, null)
            await load(true)
          } catch (failure) {
            showNotice('error', failure.message, failure.hint)
          } finally {
            setBusy('')
          }
        }

        const applyTestResult = (id, result) => {
          setTestResults((previous) => {
            const next = Object.assign({}, previous)
            next[id] = result
            return next
          })
        }

        const testHost = async (host) => {
          setTesting(host.id)
          try {
            const result = await serverRequest('POST', '/hosts/' + encodeURIComponent(host.id) + '/test')
            applyTestResult(host.id, result)
            if (result.hostKeyStatus === 'learned') void load(true)
          } catch (failure) {
            applyTestResult(host.id, { error: { message: failure.message, hint: failure.hint } })
          } finally {
            setTesting('')
          }
        }

        const clearPassword = async () => {
          if (editing === null || editing.id === null) return
          if (!window.confirm(serverCopy.clearPasswordConfirm.replace('{alias}', editing.form.alias))) return
          setBusy('credential')
          try {
            const result = await serverRequest(
              'DELETE',
              '/hosts/' + encodeURIComponent(editing.id) + '/credential?kind=password',
            )
            setEditing((previous) =>
              previous === null
                ? previous
                : Object.assign({}, previous, {
                    form: Object.assign({}, previous.form, { password: '', credentialStatus: 'missing' }),
                  }),
            )
            if (result && typeof result.deleted === 'number' && result.deleted === 0) {
              showNotice('warn', serverCopy.backendEnv, null)
            } else {
              showNotice('ok', serverCopy.passwordCleared, null)
            }
            await load(true)
          } catch (failure) {
            showNotice('error', failure.message, failure.hint)
          } finally {
            setBusy('')
          }
        }

        const clearSudoPassword = async () => {
          if (editing === null || editing.id === null) return
          if (!window.confirm(serverCopy.clearSudoPasswordConfirm.replace('{alias}', editing.form.alias))) return
          setBusy('sudo-credential')
          try {
            await serverRequest('DELETE', '/hosts/' + encodeURIComponent(editing.id) + '/credential?kind=sudo')
            setEditing((previous) =>
              previous === null
                ? previous
                : Object.assign({}, previous, {
                    form: Object.assign({}, previous.form, { sudoPassword: '', sudoPasswordConfigured: false }),
                  }),
            )
            showNotice('ok', serverCopy.sudoPasswordCleared, null)
            await load(true)
          } catch (failure) {
            showNotice('error', failure.message, failure.hint)
          } finally {
            setBusy('')
          }
        }

        const clearFingerprint = async () => {
          if (editing === null || editing.id === null) return
          if (!window.confirm(serverCopy.clearFingerprintConfirm.replace('{alias}', editing.form.alias))) return
          setBusy('fingerprint')
          try {
            await serverRequest('PATCH', '/hosts/' + encodeURIComponent(editing.id), { hostKeyFingerprint: null })
            setEditing((previous) =>
              previous === null
                ? previous
                : Object.assign({}, previous, {
                    form: Object.assign({}, previous.form, { hasFingerprint: false, hostKeyFingerprint: '' }),
                  }),
            )
            showNotice('ok', serverCopy.fingerprintCleared, null)
            await load(true)
          } catch (failure) {
            showNotice('error', failure.message, failure.hint)
          } finally {
            setBusy('')
          }
        }

        const field = (label, control, hint, hintClass) =>
          h(
            'label',
            { className: 'sshs-label' },
            h('span', { className: 'sshs-label-text' }, label),
            control,
            hint ? h('span', { className: 'sshs-hint' + (hintClass ? ' ' + hintClass : '') }, hint) : null,
          )

        const textField = (label, value, onChange, hint, options) =>
          field(
            label,
            h(
              'input',
              Object.assign(
                {
                  className: 'sshs-field',
                  type: 'text',
                  value: value,
                  spellCheck: false,
                  autoComplete: 'off',
                  onChange: (event) => onChange(event.target.value),
                },
                options || {},
              ),
            ),
            hint,
          )

        const textArea = (label, value, onChange, hint) =>
          field(
            label,
            h('textarea', {
              className: 'sshs-field sshs-textarea',
              value: value,
              spellCheck: false,
              onChange: (event) => onChange(event.target.value),
            }),
            hint,
          )

        const selectField = (label, value, onChange, options, hint) =>
          field(
            label,
            h(
              'select',
              {
                className: 'sshs-field',
                value: value,
                onChange: (event) => onChange(event.target.value),
              },
              options.map((option) => h('option', { key: option.value, value: option.value }, option.label)),
            ),
            hint,
          )

        const serverBadge = (text, extraClass) =>
          h('span', { className: 'sshs-badge' + (extraClass ? ' ' + extraClass : '') }, text)

        const renderTestResult = (result) => {
          if (result === undefined) return null
          if (result.error) {
            return h(
              'div',
              { className: 'sshs-test sshs-test-bad' },
              serverCopy.testFailed + ': ' + result.error.message,
              result.error.hint ? h('div', { className: 'sshs-hint' }, result.error.hint) : null,
            )
          }
          return h(
            'div',
            { className: 'sshs-test sshs-test-ok' },
            serverCopy.testSuccess,
            h(
              'span',
              {},
              ' · ' + serverCopy.home + ' ' + (result.homeDir || '?') + ' · ' + serverCopy.duration + ' ' + String(result.durationMs || 0) + ' ms',
            ),
            result.hostKeyFingerprint
              ? h('div', { className: 'sshs-hint', style: { fontFamily: MONO } }, result.hostKeyFingerprint)
              : null,
          )
        }

        const renderHostCard = (host) => {
          const credentialLabel =
            host.credentialStatus === 'available'
              ? serverCopy.credentialAvailable
              : host.credentialStatus === 'unavailable'
                ? serverCopy.credentialUnavailable
                : serverCopy.credentialMissing
          const credentialClass =
            host.credentialStatus === 'available' ? 'sshs-badge-ok' : 'sshs-badge-bad'
          const testResult = testResults[host.id]
          return h(
            'div',
            { className: 'sshs-card', key: host.id },
            h(
              'div',
              { className: 'sshs-card-head' },
              h(
                'div',
                { className: 'sshs-card-title' },
                h('span', { className: 'sshs-alias' }, host.alias),
                h('span', { className: 'sshs-addr' }, host.username + '@' + host.host + ':' + host.port),
              ),
              h(
                'div',
                { className: 'sshs-card-actions' },
                h(
                  'button',
                  {
                    type: 'button',
                    className: 'sshs-mini',
                    onClick: () => {
                      openEdit(host)
                    },
                  },
                  serverCopy.edit,
                ),
                h(
                  'button',
                  {
                    type: 'button',
                    className: 'sshs-mini',
                    disabled: testing === host.id,
                    onClick: () => {
                      void testHost(host)
                    },
                  },
                  testing === host.id ? serverCopy.testing : serverCopy.test,
                ),
                h(
                  'button',
                  {
                    type: 'button',
                    className: 'sshs-mini sshs-danger',
                    disabled: busy === 'delete:' + host.id,
                    onClick: () => {
                      void removeHost(host)
                    },
                  },
                  serverCopy.remove,
                ),
              ),
            ),
            h(
              'div',
              { className: 'sshs-badges' },
              serverBadge(host.authType === 'key' ? serverCopy.authKey : serverCopy.authPassword),
              serverBadge(credentialLabel, credentialClass),
              serverBadge(host.readOnly === true ? serverCopy.readOnlyOn : serverCopy.readWrite),
              serverBadge(host.fingerprintPolicy === 'strict' ? serverCopy.fpStrict : serverCopy.fpAcceptNew),
              serverBadge(host.hasFingerprint ? serverCopy.fingerprintStored : serverCopy.noFingerprint),
              host.editablePaths.length === 0 ? serverBadge(serverCopy.editablePaths + ': 0', 'sshs-badge-warn') : null,
              host.sudo && host.sudo.mode !== 'off'
                ? serverBadge(
                    'sudo: ' + (host.sudo.mode === 'nopasswd' ? 'NOPASSWD' : host.sudo.user || 'root'),
                    host.sudo.mode === 'password' && host.sudo.passwordConfigured === false
                      ? 'sshs-badge-warn'
                      : 'sshs-badge-ok',
                  )
                : null,
            ),
            (host.tags || []).length > 0
              ? h(
                  'div',
                  { className: 'sshs-tags' },
                  host.tags.map((tag) => h('span', { className: 'sshs-tag', key: tag }, tag)),
                )
              : null,
            h(
              'div',
              { className: 'sshs-paths' },
              h('span', {}, serverCopy.readPaths + ': ' + (host.allowedPaths || []).join('、')),
              h(
                'span',
                {},
                serverCopy.editPaths +
                  ': ' +
                  ((host.editablePaths || []).length > 0 ? host.editablePaths.join('、') : serverCopy.none),
              ),
              host.tempDir
                ? h('span', {}, serverCopy.tempPaths + ': ' + host.tempDir)
                : null,
              (host.services || []).length > 0
                ? h(
                    'span',
                    {},
                    serverCopy.servicesList +
                      ': ' +
                      host.services.map((service) => service.name + ' → ' + service.directory).join('；'),
                  )
                : null,
            ),
            host.note ? h('div', { className: 'sshs-note' }, host.note) : null,
            renderTestResult(testResult),
          )
        }

        const renderForm = () => {
          const form = editing.form
          const isEdit = editing.id !== null
          const sections = []

          sections.push(
            h(
              'section',
              { className: 'sshs-section', key: 'basic' },
              h('div', { className: 'sshs-section-title' }, serverCopy.basic),
              h(
                'div',
                { className: 'sshs-grid' },
                textField(serverCopy.alias, form.alias, (value) => updateForm({ alias: value })),
                textField(serverCopy.host, form.host, (value) => updateForm({ host: value })),
                textField(serverCopy.port, form.port, (value) => updateForm({ port: value }), null, {
                  type: 'number',
                  min: 1,
                  max: 65535,
                }),
                textField(serverCopy.username, form.username, (value) => updateForm({ username: value })),
              ),
            ),
          )

          const credentialHint =
            isEdit && form.credentialStatus === 'available'
              ? serverCopy.credentialAvailable
              : isEdit
                ? serverCopy.credentialMissing
                : null

          sections.push(
            h(
              'section',
              { className: 'sshs-section', key: 'auth' },
              h('div', { className: 'sshs-section-title' }, serverCopy.auth),
              h(
                'div',
                { className: 'sshs-grid' },
                selectField(
                  serverCopy.authType,
                  form.authType,
                  (value) => updateForm({ authType: value }),
                  [
                    { value: 'password', label: serverCopy.authPassword },
                    { value: 'key', label: serverCopy.authKey },
                  ],
                  credentialHint,
                ),
                form.authType === 'key'
                  ? textField(
                      serverCopy.privateKeyPath,
                      form.privateKeyPath,
                      (value) => updateForm({ privateKeyPath: value }),
                      isEdit ? serverCopy.keyPathKeep : serverCopy.privateKeyPathPlaceholder,
                    )
                  : field(
                      serverCopy.password,
                      h('input', {
                        className: 'sshs-field',
                        type: 'password',
                        autoComplete: 'new-password',
                        value: form.password,
                        placeholder: isEdit ? serverCopy.passwordKeep : serverCopy.passwordOptional,
                        onChange: (event) => updateForm({ password: event.target.value }),
                      }),
                      isEdit ? serverCopy.editSecretNote : null,
                    ),
                form.authType === 'key'
                  ? field(
                      serverCopy.passphrase,
                      h('input', {
                        className: 'sshs-field',
                        type: 'password',
                        autoComplete: 'new-password',
                        value: form.passphrase,
                        placeholder: isEdit ? serverCopy.passphraseKeep : serverCopy.passphraseOptional,
                        onChange: (event) => updateForm({ passphrase: event.target.value }),
                      }),
                      isEdit ? serverCopy.editSecretNote : null,
                    )
                  : null,
              ),
              isEdit && form.authType === 'password' && form.credentialStatus === 'available'
                ? h(
                    'div',
                    { className: 'sshs-row-inline' },
                    h(
                      'button',
                      {
                        type: 'button',
                        className: 'sshs-mini sshs-danger',
                        disabled: busy === 'credential',
                        onClick: () => {
                          void clearPassword()
                        },
                      },
                      serverCopy.clearPassword,
                    ),
                  )
                : null,
            ),
          )

          sections.push(
            h(
              'section',
              { className: 'sshs-section', key: 'access' },
              h('div', { className: 'sshs-section-title' }, serverCopy.access),
              h(
                'div',
                { className: 'sshs-grid' },
                textField(serverCopy.defaultCwd, form.defaultCwd, (value) => updateForm({ defaultCwd: value })),
                selectField(
                  serverCopy.fingerprintPolicy,
                  form.fingerprintPolicy,
                  (value) => updateForm({ fingerprintPolicy: value }),
                  [
                    { value: 'strict', label: serverCopy.fpStrict },
                    { value: 'accept-new', label: serverCopy.fpAcceptNew },
                  ],
                ),
                textField(
                  serverCopy.hostKeyFingerprint,
                  form.hostKeyFingerprint,
                  (value) => updateForm({ hostKeyFingerprint: value }),
                  form.hasFingerprint && form.fingerprint
                    ? serverCopy.fingerprintStored + ': ' + form.fingerprint
                    : serverCopy.fingerprintHint,
                ),
              ),
              h(
                'div',
                { className: 'sshs-grid' },
                textArea(serverCopy.allowedPaths, form.allowedPaths, (value) => updateForm({ allowedPaths: value }), serverCopy.allowedPathsHint),
                textArea(
                  serverCopy.editablePaths,
                  form.editablePaths,
                  (value) => updateForm({ editablePaths: value }),
                  serverCopy.editablePathsHint,
                ),
              ),
              h(
                'label',
                { className: 'sshs-check' },
                h('input', {
                  type: 'checkbox',
                  checked: form.readOnly === true,
                  onChange: (event) => updateForm({ readOnly: event.target.checked }),
                }),
                serverCopy.readOnly,
              ),
              h('div', { className: 'sshs-hint' }, serverCopy.readOnlyHint),
              isEdit && form.hasFingerprint
                ? h(
                    'div',
                    { className: 'sshs-row-inline' },
                    serverBadge(serverCopy.fingerprintStored, 'sshs-badge-ok'),
                    h(
                      'button',
                      {
                        type: 'button',
                        className: 'sshs-mini sshs-danger',
                        disabled: busy === 'fingerprint',
                        onClick: () => {
                          void clearFingerprint()
                        },
                      },
                      serverCopy.clearFingerprint,
                    ),
                  )
                : null,
            ),
          )

          sections.push(
            h(
              'section',
              { className: 'sshs-section', key: 'sudo' },
              h('div', { className: 'sshs-section-title' }, serverCopy.sudo),
              h('div', { className: 'sshs-hint' }, serverCopy.sudoHint),
              h(
                'div',
                { className: 'sshs-grid' },
                selectField(
                  serverCopy.sudo,
                  form.sudoMode,
                  (value) => updateForm({ sudoMode: value }),
                  [
                    { value: 'off', label: serverCopy.sudoOff },
                    { value: 'nopasswd', label: serverCopy.sudoNopasswd },
                    { value: 'password', label: serverCopy.sudoPassword },
                  ],
                ),
                form.sudoMode === 'off'
                  ? null
                  : textField(
                      serverCopy.sudoUser,
                      form.sudoUser,
                      (value) => updateForm({ sudoUser: value }),
                      serverCopy.sudoUserHint,
                    ),
                form.sudoMode === 'password'
                  ? field(
                      serverCopy.sudoPasswordField,
                      h('input', {
                        className: 'sshs-field',
                        type: 'password',
                        autoComplete: 'new-password',
                        value: form.sudoPassword,
                        placeholder:
                          isEdit && form.sudoPasswordConfigured
                            ? serverCopy.sudoPasswordKeep
                            : serverCopy.sudoPasswordOptional,
                        onChange: (event) => updateForm({ sudoPassword: event.target.value }),
                      }),
                      isEdit ? serverCopy.editSecretNote : null,
                    )
                  : null,
              ),
              isEdit && form.sudoMode === 'password'
                ? h(
                    'div',
                    { className: 'sshs-row-inline' },
                    serverBadge(
                      form.sudoPasswordConfigured ? serverCopy.sudoPasswordConfigured : serverCopy.sudoPasswordMissing,
                      form.sudoPasswordConfigured ? 'sshs-badge-ok' : 'sshs-badge-warn',
                    ),
                    form.sudoPasswordConfigured
                      ? h(
                          'button',
                          {
                            type: 'button',
                            className: 'sshs-mini sshs-danger',
                            disabled: busy === 'sudo-credential',
                            onClick: () => {
                              void clearSudoPassword()
                            },
                          },
                          serverCopy.clearSudoPassword,
                        )
                      : null,
                  )
                : null,
            ),
          )

          sections.push(
            h(
              'section',
              { className: 'sshs-section', key: 'extra' },
              h('div', { className: 'sshs-section-title' }, serverCopy.extra),
              h(
                'div',
                { className: 'sshs-grid' },
                textField(serverCopy.tags, form.tags, (value) => updateForm({ tags: value }), serverCopy.tagsHint),
                textField(serverCopy.note, form.note, (value) => updateForm({ note: value })),
              ),
            ),
          )

          sections.push(
            h(
              'section',
              { className: 'sshs-section', key: 'services' },
              h('div', { className: 'sshs-section-title' }, serverCopy.services),
              h('div', { className: 'sshs-hint' }, serverCopy.servicesHint),
              h(
                'div',
                { className: 'sshs-services' },
                form.services.map((service, index) =>
                  h(
                    'div',
                    { className: 'sshs-service', key: index },
                    field(
                      serverCopy.serviceName,
                      h('input', {
                        className: 'sshs-field',
                        type: 'text',
                        value: service.name,
                        onChange: (event) => updateService(index, 'name', event.target.value),
                      }),
                    ),
                    field(
                      serverCopy.serviceDirectory,
                      h('input', {
                        className: 'sshs-field',
                        type: 'text',
                        value: service.directory,
                        onChange: (event) => updateService(index, 'directory', event.target.value),
                      }),
                    ),
                    field(
                      serverCopy.serviceDescription,
                      h('input', {
                        className: 'sshs-field',
                        type: 'text',
                        value: service.description,
                        onChange: (event) => updateService(index, 'description', event.target.value),
                      }),
                    ),
                    field(
                      serverCopy.serviceStart,
                      h('input', {
                        className: 'sshs-field',
                        type: 'text',
                        value: service.startCommand,
                        onChange: (event) => updateService(index, 'startCommand', event.target.value),
                      }),
                    ),
                    field(
                      serverCopy.serviceLog,
                      h('input', {
                        className: 'sshs-field',
                        type: 'text',
                        value: service.logPath,
                        onChange: (event) => updateService(index, 'logPath', event.target.value),
                      }),
                    ),
                    field(
                      serverCopy.servicePort,
                      h('input', {
                        className: 'sshs-field',
                        type: 'number',
                        min: 1,
                        max: 65535,
                        value: service.port,
                        onChange: (event) => updateService(index, 'port', event.target.value),
                      }),
                    ),
                    h(
                      'div',
                      { className: 'sshs-service-actions' },
                      h(
                        'button',
                        {
                          type: 'button',
                          className: 'sshs-mini sshs-danger',
                          onClick: () => removeService(index),
                        },
                        serverCopy.removeService,
                      ),
                    ),
                  ),
                ),
              ),
              h(
                'div',
                { className: 'sshs-row-inline' },
                h(
                  'button',
                  {
                    type: 'button',
                    className: 'sshs-mini',
                    onClick: addService,
                  },
                  '+ ' + serverCopy.addService,
                ),
              ),
            ),
          )

          const errorBox = editing.error
            ? h(
                'div',
                { className: 'sshs-notice sshs-notice-error' },
                h('div', {}, editing.error.message || serverCopy.saveFailed),
                editing.error.hint ? h('div', { className: 'sshs-hint' }, editing.error.hint) : null,
              )
            : null

          return h(
            'div',
            { className: 'sshs-form' },
            h(
              'div',
              { className: 'sshs-form-head' },
              h(
                'button',
                { type: 'button', className: 'sshs-mini', onClick: closeEditor, disabled: editing.saving },
                '← ' + serverCopy.back,
              ),
              h('h2', { className: 'sshs-form-title' }, isEdit ? serverCopy.editTitle : serverCopy.addTitle),
              isEdit
                ? h(
                    'button',
                    {
                      type: 'button',
                      className: 'sshs-mini',
                      disabled: testing === editing.id,
                      onClick: () => {
                        void testHost({ id: editing.id, alias: form.alias })
                      },
                    },
                    testing === editing.id ? serverCopy.testing : serverCopy.test,
                  )
                : null,
              h(
                'button',
                { type: 'button', className: 'sshs-mini', onClick: closeEditor, disabled: editing.saving },
                serverCopy.cancel,
              ),
              h(
                'button',
                {
                  type: 'button',
                  className: 'sshs-btn sshs-btn-primary',
                  onClick: () => {
                    void save()
                  },
                  disabled: editing.saving,
                },
                editing.saving ? serverCopy.saving : serverCopy.save,
              ),
            ),
            errorBox,
            isEdit ? renderTestResult(testResults[editing.id]) : null,
            sections,
            h('div', { className: 'sshs-security' }, serverCopy.securityHint),
          )
        }

        const renderError = (failure) => {
          const missing = failure.missingEndpoint === true || failure.status === 404
          return h(
            'div',
            { className: 'sshs-notice sshs-notice-error' },
            h('div', {}, serverCopy.error + ': ' + (failure.message || '')),
            missing ? h('div', { className: 'sshs-hint' }, serverCopy.endpointMissing) : null,
            failure.hint ? h('div', { className: 'sshs-hint' }, failure.hint) : null,
            h(
              'div',
              { className: 'sshs-row-inline', style: { marginTop: 4 } },
              h(
                'button',
                {
                  type: 'button',
                  className: 'sshs-mini',
                  onClick: () => {
                    void load(false)
                  },
                },
                serverCopy.retry,
              ),
            ),
          )
        }

        const head = h(
          'div',
          { className: 'sshs-head' },
          h(
            'div',
            { className: 'sshs-head-main' },
            h('h1', { className: 'sshs-title' }, serverCopy.title),
            h('p', { className: 'sshs-sub' }, serverCopy.subtitle),
            h(
              'div',
              { className: 'sshs-hint' },
              hosts.length + ' ' + serverCopy.count + (error === null ? '' : ' · ' + serverCopy.error),
            ),
          ),
          h(
            'div',
            { className: 'sshs-head-actions' },
            editing === null
              ? [
                  h(
                    'button',
                    {
                      key: 'refresh',
                      type: 'button',
                      className: 'sshs-btn',
                      disabled: loading,
                      onClick: () => {
                        void load(false)
                      },
                    },
                    loading ? serverCopy.loading : serverCopy.refresh,
                  ),
                  h(
                    'button',
                    {
                      key: 'add',
                      type: 'button',
                      className: 'sshs-btn sshs-btn-primary',
                      onClick: openCreate,
                    },
                    '+ ' + serverCopy.add,
                  ),
                ]
              : null,
          ),
        )

        const noticeBox = notice
          ? h(
              'div',
              {
                className:
                  'sshs-notice' +
                  (notice.tone === 'error'
                    ? ' sshs-notice-error'
                    : notice.tone === 'warn'
                      ? ' sshs-notice-warn'
                      : ''),
              },
              h('div', {}, notice.text),
              notice.hint ? h('div', { className: 'sshs-hint' }, notice.hint) : null,
            )
          : null

        let body
        if (editing !== null) {
          body = renderForm()
        } else if (error !== null) {
          body = renderError(error)
        } else if (loading && hosts.length === 0) {
          body = h('div', { className: 'sshs-empty' }, serverCopy.loading)
        } else if (hosts.length === 0) {
          body = h(
            'div',
            { className: 'sshs-empty' },
            h('div', {}, serverCopy.empty),
            h(
              'div',
              { className: 'sshs-row-inline', style: { justifyContent: 'center', marginTop: 12 } },
              h(
                'button',
                { type: 'button', className: 'sshs-btn sshs-btn-primary', onClick: openCreate },
                '+ ' + serverCopy.add,
              ),
            ),
          )
        } else {
          body = h('div', { className: 'sshs-list' }, hosts.map(renderHostCard))
        }

        return h(
          'div',
          { className: 'sshs-page' },
          h('style', { key: 'css' }, SERVER_CSS),
          h(
            'div',
            { className: 'sshs-inner' },
            head,
            noticeBox,
            body,
            h('div', { className: 'sshs-security' }, serverCopy.securityHint),
          ),
        )
      }

      function ServerPanelIcon(props) {
        return h(ServerIcon, { size: props && props.size ? props.size : 16 })
      }

      ctx.slots.inject('sidebar.footer.action', () =>
        ctx.slots.register(
          {
            name: 'sidebar.footer.action',
            id: 'ssh-hosts-history',
            order: 5,
            label: copy.trigger,
          },
          Trigger,
        ),
      )

      ctx.slots.inject('shell.overlay', () =>
        ctx.slots.register(
          {
            name: 'shell.overlay',
            id: 'ssh-hosts-history-panel',
            order: 50,
          },
          Panel,
        ),
      )

      ctx.slots.inject('sidebar.panellist', () =>
        ctx.slots.register(
          {
            name: 'sidebar.panellist',
            id: 'ssh-hosts',
            order: 20,
            label: serverCopy.trigger,
          },
          ServerPanelIcon,
        ),
      )

      ctx.slots.inject('main', () =>
        ctx.slots.register(
          {
            name: 'main',
            key: 'ssh-hosts',
          },
          ServersPage,
        ),
      )
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        try {
          mount(ctx)
        } catch (error) {
          try {
            window.console.error('[ssh-hosts] Web surfaces failed to mount', error)
          } catch (ignored) {
            // Nothing else to do without a console.
          }
        }
      },
    }
  },
})
