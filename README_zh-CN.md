# tcpcap

> [English](README.md) | 简体中文

> ⚠️ **本项目已归档。** `tcpcap` 已合并进 [`pktcap`](https://github.com/fetaoily/pktcap) —— 一个同时抓取 TCP 和 UDP、输出同样结构化数据的单一工具。`pktcap` 是当前维护的继任者,请改用它。本仓库仅作历史参考保留,已设为只读。

一个用 Go 编写的轻量级 TCP 抓包工具,功能类似 `tcpdump`,但**专注于 TCP** 且输出**结构化的 JSON / 文本**,并把 TCP 特有字段(seq、ack、flags、window)以结构化方式暴露出来,便于其他程序(日志收集、数据分析、Python 脚本、SIEM 等)直接解析,解决 tcpdump 文本输出难以程序化解析的问题。

底层基于 [gopacket](https://github.com/google/gopacket) + libpcap(Windows 下即 Npcap),与 tcpdump 同源,过滤在**内核态 BPF** 完成,效率高。

同系列还有一个专注 UDP 的 [`udpcap`](https://github.com/fetaoily/udpcap),采用相同设计。

---

## 功能特点

- 🎯 **专注 TCP**:只抓 TCP,过滤条件(端口/IP)自动转为 BPF 内核态过滤,高效
- 📊 **TCP 状态字段**:每个报文段都结构化输出 `seq`、`ack`、`flags`(如 `SYN,ACK`)、`data_offset`、`window`,便于连接/流量分析
- 📦 **结构化输出**:
  - `jsonl`(默认,JSON Lines):每行一个 JSON,流式输出,最适合实时管道解析
  - `json`:完整 JSON 数组,适合离线批处理
  - `text`:人类可读文本(类似 tcpdump)
- 🔎 **支持自定义 BPF**:与 tcpdump 语法一致(`-bpf "tcp port 443"`)
- 📝 **负载可选**:`-no-payload` 仅输出元数据;`-max-payload` 限制负载长度
- ⏱️ **纳秒时间戳**:同时提供 RFC3339 时间与 Unix 纳秒时间戳
- 🪟 **跨平台**:Windows / Linux / macOS

---

## 输出格式

### JSON Lines(默认,`-f jsonl`)

每行一个独立 JSON 对象,可用 `jq`、Python `json.loads` 逐行解析:

```json
{"timestamp":"2026-07-08T14:30:00.123456789Z","timestamp_unix_nano":1752014600123456789,"interface":"eth0","ip_version":4,"src_ip":"192.168.1.5","dst_ip":"93.184.216.34","src_port":51234,"dst_port":80,"seq":1,"ack":1,"flags":"PSH,ACK","data_offset":32,"window":64240,"length":117,"payload_size":85,"payload_hex":"474554202f...","payload_text":"GET / HTTP..."}
```

字段说明:

| 字段 | 类型 | 说明 |
| ------ | ------ | ------ |
| `timestamp` | string | RFC3339 纳秒时间戳 |
| `timestamp_unix_nano` | int64 | Unix 纳秒时间戳 |
| `interface` | string | 抓包接口 |
| `ip_version` | int | IP 版本 (4 或 6) |
| `src_ip` / `dst_ip` | string | 源 / 目的 IP |
| `src_port` / `dst_port` | int | 源 / 目的端口 |
| `seq` | uint32 | 序列号 |
| `ack` | uint32 | 确认号 |
| `flags` | string | TCP 标志,如 `SYN,ACK`、`PSH`、`FIN`、`NONE` |
| `data_offset` | int | TCP 头部长度(字节) |
| `window` | int | 接收窗口大小 |
| `length` | int | 报文段总长度(头部 + 负载) |
| `payload_size` | int | 负载字节数 |
| `payload_hex` | string | 负载的十六进制表示 |
| `payload_text` | string | 负载可见字符(不可见字符替换为 `.`) |

### 文本(`-f text`)

```text
14:30:00.123456 IPv4 192.168.1.5:51234 > 93.184.216.34:80 [PSH,ACK] seq=1 ack=1 win=64240 len=117 payload=85 | 474554202f...
```

---

## 环境依赖

抓包依赖 libpcap,不同平台安装方式不同:

### Windows(必需)

1. **安装 Npcap**(运行时抓包驱动):<https://npcap.com/dist/>
   - 安装时勾选 **"Install Npcap in WinPcap API-compatible Mode"**
2. **安装 Npcap SDK**(编译用):<https://npcap.com/dist/> → 下载 `npcap-sdk-*.zip`
   - 解压到例如 `C:\npcap-sdk`
3. **安装 C 编译器**(cgo 需要),推荐 [TDM-GCC](https://jmeubank.github.io/tdm-gcc/) 或 MSYS2 的 mingw-w64
4. 配置环境变量:

   ```bat
   set CGO_ENABLED=1
   set CPATH=C:\npcap-sdk\Include;%CPATH%
   set LIBRARY_PATH=C:\npcap-sdk\Lib\x64;%LIBRARY_PATH%
   ```

   > 运行时还需把 `C:\Windows\System32\Npcap` 加入 `PATH`,或随程序分发 `wpcap.dll` / `Packet.dll`。

### Linux

```bash
sudo apt install libpcap-dev     # Debian/Ubuntu
sudo yum install libpcap-devel   # CentOS/RHEL
```

### macOS

系统自带 libpcap,无需额外安装。

---

## 编译

```bash
cd tcpcap
go mod tidy
go build -o tcpcap .
```

跨平台构建脚本(通过 Docker 产出完全静态的 Linux 二进制)见 [`build.sh`](build.sh)。

---

## 使用

### 1. 查看可用网络接口

```bash
./tcpcap --list-interfaces
```

```text
接口名 (-i 参数)                                  描述 / 地址
----------------------------------------------------------------------------------------------------
eth0                                             Realtek PCIe GbE (192.168.1.5, fe80::1)
```

### 2. 抓取所有 TCP 包(默认 JSON Lines 输出到终端)

```bash
./tcpcap -i eth0
```

### 3. 按端口过滤(如 HTTP)

```bash
./tcpcap -i eth0 -p 80
```

### 4. 输出到文件

```bash
./tcpcap -i eth0 -o http.jsonl -p 80
```

### 5. 文本格式(人类可读,带 TCP flags/seq/ack)

```bash
./tcpcap -i eth0 -f text
```

### 6. 自定义 BPF(与 tcpdump 语法一致)

```bash
./tcpcap -i eth0 -bpf "tcp port 443 or tcp port 22"
```

### 7. 配合管道解析(如统计 TCP flags 分布)

```bash
./tcpcap -i eth0 -p 80 | jq -r '.flags' | sort | uniq -c
```

---

## 命令行参数

| 参数 | 默认值 | 说明 |
| ------ | -------- | ------ |
| `-i` | (必填) | 网络接口名 |
| `--list-interfaces` | - | 列出所有接口后退出 |
| `-f` | `jsonl` | 输出格式: `jsonl` / `json` / `text` |
| `-o` | (stdout) | 输出文件路径 |
| `-p` | 0 | 按端口过滤(源或目的) |
| `--src-port` / `--dst-port` | 0 | 按源 / 目的端口过滤 |
| `--src-ip` / `--dst-ip` | (空) | 按源 / 目的 IP 过滤 |
| `-bpf` | (空) | 原始 BPF 表达式(提供时忽略上方过滤) |
| `--no-payload` | false | 不输出负载内容 |
| `--max-payload` | 256 | 负载最大显示字节数(0=不限制) |
| `--snaplen` | 65536 | 抓包快照长度 |
| `--promisc` | false | 启用混杂模式 |
| `--timeout` | 0 | 读取超时秒数(0=阻塞等待) |

> 💡 大多数系统抓包需要 **管理员/root 权限**。

---

## 项目结构

```text
tcpcap/
├── go.mod
├── main.go                  # CLI 入口
├── build.sh                 # 跨平台构建脚本
├── internal/
│   ├── capture/capture.go   # 抓包核心 (BPF 内核过滤)
│   ├── packet/packet.go     # TCP 包结构化定义
│   └── output/output.go     # 输出格式化 (JSON Lines / JSON / Text)
└── README.md
```
