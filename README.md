# dvpn-sim

3-hop dVPN 仿真骨架。Go 标准库，无第三方依赖。

## 运行

```bash
go run ./cmd/sim -scenario all
go run ./cmd/sim -scenario overreport -clients 120 -packets 50
go test ./...
```

## 当前模型

- 3-hop 电路：client → entry → middle → exit → destination。
- 每个包按链路延迟 + 串行化时间推进；链路有排队（`nextFree`）。
- 每个 hop 记录字节数，生成双签收据（Ed25519）和 hash chain。
- 审计按概率抽样，用 client + E/M/X 四个读数的中位数找 outlier：
  - 节点多报 → 罚没节点质押；
  - 客户端少报 → 标记客户端，不罚节点。
- 知识矩阵：C/E/M/X/D 各自能看到什么。

## 已知限制（下一轮补）

- 还没有真正的洋葱信元；目前是“每跳只看到下一跳”的抽象。
- 收据是单方签 + 链，不是相邻节点交叉签。
- 审计是“读数比对”，不是随机数据挑战。
- 没有 DNS 流、padding、E+X 关联实验。
- 没有质押账本/结算，只有罚没计数。
- 签名/验签做了，但收据没有在审计里验签。

## 目录

```
cmd/sim/           CLI
internal/model/    Node, Circuit, Packet, Receipt
internal/sim/      事件循环、链路、计量、审计
```
