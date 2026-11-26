# 项目状态（截至 v0.10.0）

## 已完成

| 版本 | 内容 | 测试 |
|---|---|---|
| v0.1 | 3-hop 事件仿真、链路延迟/带宽/队列 | `internal/sim` |
| v0.2 | AES-GCM 洋葱信元、DNS tunnel/local | `internal/onion` |
| v0.3 | 本机 UDP 3-hop 真传输、1024 B 固定帧 | 脚本 |
| v0.4 | 进程级 Ed25519 收据 + 字节链审计 | `internal/audit` |
| v0.5 | 反向路径 + RTT | 脚本 |
| v0.5.1 | per-hop tag 重写（无全局 circuit id） | `internal/circuit` |
| v0.6 | X25519 握手、逐跳会话密钥 | `internal/handshake` |
| v0.7 | 相邻交叉签 link receipt、每包 hash + 随机挑战 | `internal/link`、`internal/sim` |
| v0.8 | 可配置 hop 数/信元大小 | `TestHops234` |
| v0.9 | E+X 关联分析、cover traffic | `internal/privacy` |
| v0.10 | 随机 hop 范围、电路分散度、批量实验表 | `TestRandomHopsAndDiversity` |
| v0.11 | 模拟链：注册/质押/结算/罚没、Ed25519 交易、区块 | `internal/chain` |
| v0.12 | Merkle root/proof、链上争议验 proof、tag 过期 | `internal/merkle`、`TestExpiry` |
| v0.13 | 丢包/重复包建模、3σ 容忍判罚 | `TestHonestLossDupNoFalsePositive` |
| v0.14 | seq 防重放、握手 ACK、反向加密、身份绑定、sent/recv 双签 | `internal/identity`、`TestExpiry` |
| v0.15 | 链上 cap/leaf 验签/nonce/唯一 epoch/争议窗口；bursty loss + CI；PRIVACY.md | `internal/chain`、`cmd/bench` |
| v0.15.1 | nonce 强制；Seal 原子回滚 | `TestSealAtomicOnBadNonce` |
| v0.16 | 注册表 + controller 随机选路、routes 路由表、2×2×2 集群脚本 | `internal/registry`、`run_cluster.sh` |
| v0.17 | TUN 设备 + client/exit TUN 模式 | `internal/tun`、`TestOpenTUN` |

全量：`go test ./...` 通过。

## 当前指标（40 clients × 20 packets，DNS local）

| hops | cell | cover | 延迟 | MB/s | anon | link |
|---|---|---|---|---|---|---|
| 2 | 1024 | 0 | 60 ms | 6.34 | 18.25 | 0.06 |
| 3 | 1024 | 0 | 80 ms | 5.17 | 18.25 | 0.06 |
| 4 | 1024 | 0 | 100 ms | 4.29 | 18.25 | 0.06 |
| 5 | 1024 | 0 | 120 ms | 3.61 | 18.25 | 0.06 |
| 3 | 512 | 0 | 80 ms | 2.20 | 18.25 | 0.06 |
| 3 | 1500 | 0 | 80 ms | 7.93 | 18.25 | 0.06 |
| 3 | 1024 | 100 | 80 ms | 5.17 | 25.52 | 0.04 |

完整表：`go run ./cmd/bench
go run ./cmd/chain` → `results/bench.csv`。

## 已知限制

- 集群 demo 有 2 个 entry / 2 个 middle / 2 个 exit，controller 随机分配；controller 只监听本地、无鉴权。
- 真传输有身份绑定/ACK/反向加密/seq；交叉签/挑战仍只在仿真里。
- 挑战只能抓“没转发”，抓不到“转了却多报字节”；后者靠交叉签字节比对。
- tag 表没有 idle 过期。
- cover 是合成观测，不是真实 cover 流量。
- 没做 ECH 真实集成、TCP fallback、多路径、TEE、ZK、真实链。

## 命令

```bash
go test ./...
go run ./cmd/sim -scenario all
go run ./cmd/sim -scenario honest -hops-min 3 -hops-max 5 -cover 100
go run ./cmd/bench
go run ./cmd/chain
bash scripts/run_local.sh
```

## 下一步

1. tag idle timeout。
2. 真传输上的交叉签/挑战。
3. 真实 trace（包长/时序）替代合成观测。
4. 报告/图表。
