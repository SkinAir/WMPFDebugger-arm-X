# WMPFDebugger-arm-X

微信小程序 macOS (arm64) 远程调试，支持微信 4.1.15。

fork 自 [chain00x/WMPFDebugger-arm](https://github.com/chain00x/WMPFDebugger-arm)（原始项目 [evi0s/WMPFDebugger](https://github.com/evi0s/WMPFDebugger)）。

## ⚠️ 4.1.15 变了什么

微信 4.1.15 **整体更换了小程序调试的传输机制**，老版本工具（WMPFDebugger 等）全部失效，表现为「调试端口一直找不到 / 连不上」：

| | ≤ 4.1.13（旧版） | 4.1.15（本仓库适配） |
|---|---|---|
| 触发方式 | Framework 硬编码主动 connect `ws://localhost:9421` | 必须由页面侧 `xweb_remote_debug.RemoteDebugStart(url, token, cb)` 触发，**无任何代码自动调用它** |
| 连接目标 | 本地 `localhost:9421` | 腾讯云 relay `wss://xweb.weixin.qq.com/rd/...`（动态分配，无固定端口） |
| 线上协议 | 私有 WARemoteDebug protobuf | **标准 CDP**（不再需要 protobuf 转换层） |
| 凭证 | 无 | linkToken + deviceToken（走腾讯服务器交换） |

### 本仓库的方案：Relay Hijack（本地冒充腾讯 relay）

```
旧版:  Framework --ws:9421--> 本工具(protobuf转CDP) --ws:62000--> DevTools
新版:  Framework --ws:9421--> 本工具(冒充 xweb relay, 纯透传) --ws:62000--> DevTools
```

1. Frida 把 Framework 内存里硬编码的 3 个腾讯 relay URL 改写为 `127.0.0.1:9421`
2. Hook `XWebRemoteDebugHost::status`（小程序页面加载时自动触发），在 Framework 自己的线程里调用 `StartRemoteDebug` 拉起调试通道
3. 本地 relay 应答 `create_device`（HTTP 201 + `{"code":0,"data":{"token":...}}`），接收 device/target 两条 WebSocket，自动向真实小程序页面发送 `XWeb.inspect` 完成 attach

**不依赖腾讯服务器、不需要 linkToken、不需要微信开发者工具登录。**

### 「远程调试中」悬浮窗

链路打通后，小程序页面内会出现一个**绿色圆点的悬浮窗**（微信官方注入的远程调试状态窗）：

- **悬浮窗出现 = 调试链路已建立**，DevTools 可以开始工作
- 悬浮窗上的 **✕ 按钮 = 停止远程调试**（调用 `RemoteDebugStop`），不想调试时点掉即可
- 它是页面 DOM 元素，不影响小程序功能

![蜜雪冰城小程序调试](screenshots/4.1.15-mixue-devtools.png)

## 使用

```bash
yarn        # 装依赖
```

重签名微信

```bash
sudo python3 tools/step_resign_keep_ents.py
```

启动微信

 Frida 注入（每次启动微信挂一次就行）：

```bash
npx ts-node src/inject.ts
```

再开 relay（这个随便重启）：

```bash
npx ts-node src/relay.ts
```

微信里打开一个小程序，出现悬浮窗后，Chrome 地址栏粘贴：

```
devtools://devtools/bundled/inspector.html?ws=127.0.0.1:62000
```

Console / Sources / Network 都能用，可以直接跑 `wx.*`。

## 端口

- 9421：本地假 relay，给微信 Framework 连的
- 62000：CDP 口，给浏览器 DevTools 连的

## 版本

| 微信版本 | 用法 |
|----------|------|
| 4.1.15 (270102) | `src/inject.ts` + `src/relay.ts` |
| ≤ 4.1.13 | `src/index.ts --script frida/<build>.js`（旧 protobuf 模式，偏移需自备） |

## 注意

微信更新后签名会被重置，Frida 挂不上时先重签（微信要先完全退出）：

```bash
sudo python3 tools/step_resign_keep_ents.py
```

同一个微信进程别反复挂 Frida（两三次之后进程会出问题），挂不上了就重启微信再挂。

## 免责声明

仅供安全研究与学习使用，请勿用于未授权的目标，使用者须自行承担相关法律责任。
