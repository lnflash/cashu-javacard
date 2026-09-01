# Cashu JavaCard 实体硬件测试报告

- **测试日期：** 2026-09-01（UTC+08:00）
- **仓库提交：** `afe1081220663f66b8fc9e8445800e599672e849`
- **测试范围：** `tools/cardctl/README.md` 中定义的主机端测试、读卡器发现、实体卡 `selftest` 及安全的只读/签名命令
- **总体结论：** Applet 的实体硬件核心功能通过测试；未修改的 `cardctl selftest` 和 `cardctl sign` 因实体卡返回 65 字节非压缩公钥而异常退出，暴露出 Applet、规范和主机工具之间的公钥编码兼容性问题。

## 1. 摘要

本次测试在 Windows 11 主机上，通过 ACS ACR1281 PICC 接口访问一张基于 **NXP JCOP4.5 J3R452** 芯片、且已安装 Cashu JavaCard Applet 的实体 JavaCard。

测试确认：

- Applet 可以通过 AID 正常选择；
- `GET_INFO`、`GET_BALANCE` 和 `GET_SLOT_STATUS` 正常；
- 卡片返回的公钥是有效的 secp256k1 曲线点；
- `SIGN_ARBITRARY` 生成的签名可通过 BIP-340 验证；
- 对相同消息进行两次签名时使用了不同的 `R`，未观察到 nonce 重用；
- README 中列出的四组无硬件测试全部通过；
- 测试期间未执行写入 proof、消费 proof、修改 PIN 或锁卡等状态修改操作。

未修改的 `cardctl` 命令不能完整处理本卡：`GET_PUBKEY` 实际返回 65 字节、以 `0x04` 开头的非压缩公钥，而规范和主机工具要求 33 字节压缩公钥。为验证卡片密码学功能，本报告补充了一次仅在主机端规范化公钥的手工硬件测试；该测试全部通过。

## 2. 测试环境

| 项目 | 值 |
|---|---|
| 操作系统 | Microsoft Windows 11 专业版，64 位，版本 `10.0.26200`，Build `26200` |
| Python | `3.13.15` |
| pyscard | `2.3.1` |
| 虚拟环境 | `tools/cardctl/.venv` |
| 测试卡片芯片 | `NXP JCOP4.5 J3R452` |
| 读卡器 | `ACS ACR1281 1S Dual Reader PICC 0` |
| cardctl reader index | `1` |
| Docker 镜像 | `cirne/javacard-great-again:latest` |
| Docker 镜像 ID | `sha256:6b4a0602999ab37e14d3fece86333e69c8312d1ceb420014e509537987f2a629` |
| Applet 版本 | `0.1` |
| Package AID | `D2760000850102` |
| Applet AID | `D276000085010201` |

### CAP 构建产物

| 项目 | 值 |
|---|---|
| 文件 | `applet/target/cashu-javacard-0.1.0.cap` |
| 大小 | `30,499` 字节 |
| SHA-256 | `708FB76870F885B544F215C12BDD46445868A5BD4E2186B1F1DAB441ADE35E79` |
| Docker 构建结果 | `BUILD SUCCESSFUL` |
| CAP verification | `passed` |

使用的构建命令：

```powershell
docker run --rm `
  -v "C:\Users\richa\Documents\github\cashu-javacard:/workspace/cashu-javacard" `
  -v "C:\Users\richa\Documents\github\SatochipApplet\sdks\jc305u4_kit:/opt/jc305u4_kit:ro" `
  cirne/javacard-great-again:latest `
  sh -lc "cd /workspace/cashu-javacard/applet; ant cap -Djc.sdk=/opt/jc305u4_kit"
```

## 3. 测试安全边界

根据 `tools/cardctl/README.md`，本次测试只执行无状态修改或预期安全的命令：

- `readers`
- `selftest`
- `info`
- `pubkey`
- `balance`
- `slots --all`
- `sign`

下列命令没有执行：

- `load` / `load-file`：会写入 proof；
- `spend`：会不可逆地将 proof 标记为 spent；
- `clear-spent`：会修改卡片存储；
- `set-pin` / `change-pin`：会修改认证状态；
- `lock`：会永久禁用写操作，无法恢复。

所有实体卡命令均串行执行，没有对同一读卡器并发发送 APDU。

## 4. 主机端测试

在 `tools/cardctl` 目录执行：

```powershell
.\.venv\Scripts\python.exe .\test_bip340.py
.\.venv\Scripts\python.exe .\test_apdu.py
.\.venv\Scripts\python.exe .\test_spec_consistency.py
.\.venv\Scripts\python.exe .\test_card_file.py
```

结果：

| 测试 | 结果 | 覆盖范围 |
|---|---|---|
| `test_bip340.py` | PASS | BIP-340 规范向量、参考签名器往返、变异拒绝、公钥处理 |
| `test_apdu.py` | PASS | APDU 编码、响应解析、状态字、参数校验 |
| `test_spec_consistency.py` | PASS | `cardctl`、Applet 常量和 `spec/APDU.md` 一致性 |
| `test_card_file.py` | PASS | Card File 格式、字段校验、spent 防恢复、重复 proof 和曲线点检查 |

四组测试均输出：

```text
all tests passed
```

## 5. 读卡器发现

执行：

```powershell
.\.venv\Scripts\python.exe .\cardctl.py readers
```

输出：

```text
[0] ACS ACR1281 1S Dual Reader ICC 0
[1] ACS ACR1281 1S Dual Reader PICC 0
[2] ACS ACR1281 1S Dual Reader SAM 0
```

实体卡通过 reader index `1` 访问。

## 6. 未修改的 cardctl 实体硬件测试

执行：

```powershell
.\.venv\Scripts\python.exe .\cardctl.py -r 1 -v selftest
```

成功的检查：

```text
PASS  SELECT applet — version 0.1
PASS  GET_INFO — v0.1, 32 slots, PIN unset
PASS  Schnorr capability advertised — caps=0x07
PASS  GET_BALANCE — 0
PASS  GET_SLOT_STATUS — 32 status bytes
```

SELECT APDU：

```text
> 00a4040007d2760000850102
< 0001 9000
```

`GET_INFO` 解码结果：

```text
version       : 0.1
max slots     : 32
unspent       : 0
spent         : 0
empty         : 32
capabilities  : 0x07
PIN state     : unset
balance       : 0
```

`0x07` 表示卡片声明支持 secp256k1 原生密钥、Schnorr 签名和 PIN。

### 6.1 失败点：GET_PUBKEY 编码不一致

请求和响应：

```text
> b010000021
< 042f3253009b4481805ae7b87e46fcc0b1a469b9e510fd1d9767bf146fb61abec8987303f74519a22b0c75d9cccee43ae61025d018c28fb5be47a1de35cfdad628 9000
```

实际响应为 65 字节、`0x04` 前缀的非压缩 secp256k1 公钥。`cardctl selftest` 记录：

```text
FAIL  GET_PUBKEY well-formed — 042f3253009b4481805a… (65 bytes)
```

随后在进行 BIP-340 验证时异常退出：

```text
ValueError: not a compressed secp256k1 pubkey: 65 bytes
```

因此，未修改的 `selftest` 退出码为 `1`。

### 6.2 未修改的 sign 命令

执行：

```powershell
.\.venv\Scripts\python.exe .\cardctl.py -r 1 -v sign
```

卡片成功返回 64 字节签名和状态字 `9000`，但命令在读取 65 字节公钥并调用 `bip340.x_only()` 时触发同一异常。因此：

- 卡片签名 APDU 成功；
- 未修改的 `cardctl sign` 主机端验证失败；
- 失败发生在公钥格式处理阶段，而不是卡片拒绝签名。

## 7. 安全的只读检查

### 7.1 info

```text
applet version   : 0.1
slots            : 32 total — 0 unspent, 0 spent, 32 empty
capabilities     : 0x07 (secp256k1 native=True, schnorr=True)
PIN              : unset
balance          : 0
```

结果：**PASS**

### 7.2 pubkey

```text
042f3253009b4481805ae7b87e46fcc0b1a469b9e510fd1d9767bf146fb61abec8987303f74519a22b0c75d9cccee43ae61025d018c28fb5be47a1de35cfdad628
```

结果：读取成功，但编码为 65 字节非压缩格式，与当前 33 字节规范不一致。

### 7.3 balance

```text
0
```

结果：**PASS**

### 7.4 slots --all

```text
32 slots (0 non-empty)
```

槽位 `[0]` 至 `[31]` 均为 `empty`。

结果：**PASS**

## 8. 65 字节公钥兼容验证

为确认错误仅来自主机工具格式限制，补充执行了以下兼容测试：

1. 接受 `0x04 || X || Y` 形式的 65 字节公钥；
2. 验证 `(X, Y)` 满足 secp256k1 曲线方程；
3. 提取 `X` 作为 BIP-340 x-only 公钥；
4. 对三个随机 32 字节消息调用 `SIGN_ARBITRARY`；
5. 使用仓库的 `bip340.verify()` 验证每个签名；
6. 对同一个随机消息签名两次，分别验证两个签名并比较两个签名的前 32 字节 `R`。

结果：

```text
Public key point on secp256k1: True
SIGN_ARBITRARY + BIP-340 verify [1/3]: PASS
SIGN_ARBITRARY + BIP-340 verify [2/3]: PASS
SIGN_ARBITRARY + BIP-340 verify [3/3]: PASS
Identical-message signature #1 verifies: PASS
Identical-message signature #2 verifies: PASS
Fresh nonce across identical messages: PASS
MANUAL HARDWARE SELFTEST: PASS
```

该结果证明：

- 实体卡返回的公钥是有效的 secp256k1 公钥；
- 卡片私钥与返回公钥匹配；
- 实体卡生成的 Schnorr 签名符合 BIP-340；
- 相同消息的两次签名没有复用 `R`；
- Applet 的核心签名功能正常。

## 9. 缺陷分析

### 9.1 预期行为

`spec/APDU.md`、`spec/NUT-XX.md`、`spec/CARD-FILE.md`、`docs/HARDWARE_DEPLOYMENT.md` 和 `tools/cardctl/README.md` 均将 `GET_PUBKEY` 定义为 33 字节压缩 secp256k1 公钥。

### 9.2 实际行为

当前实体卡返回 65 字节非压缩公钥。相关实现存在以下不一致：

- `CashuApplet.processGetPubkey()` 直接将 `cardPubKey.getW()` 的结果发送给主机，没有执行压缩；
- 本卡的 `ECPublicKey.getW()` 返回 65 字节非压缩点；
- `CashuAppletTest.testGetPubkey()` 允许 33 或 65 字节；
- `cardctl.Card.get_pubkey()` 和 `bip340.x_only()` 只支持规范要求的压缩格式；
- `cardctl selftest` 的异常未转换为普通测试失败，而是直接显示 Python traceback。

### 9.3 影响

- `cardctl selftest` 无法在此实体卡上完成；
- `cardctl sign` 无法完成主机端验签；
- `cardctl pubkey` 输出不满足 Card File 对 33 字节压缩公钥的要求；
- 使用该输出构造 NUT-11 P2PK secret 或 Card File 时可能产生互操作问题；
- README 中“实体硬件返回压缩公钥”的假设不适用于本次测试硬件。

### 9.4 建议修复

首选规范一致性修复：

1. 在 Applet 的 `processGetPubkey()` 中将 `getW()` 返回的 `0x04 || X || Y` 压缩为 `0x02/0x03 || X`；
2. 始终返回恰好 33 字节；
3. 将 Applet 测试从“33 或 65 字节”收紧为“仅 33 字节”；
4. 在 jCardSim 和实体卡上分别运行回归测试。

建议同时增加主机端防御性兼容：

1. `cardctl` 可识别合法的 65 字节非压缩点；
2. 验证点位于 secp256k1 曲线上后，将其规范化为 33 字节压缩格式；
3. `bip340.x_only()` 可安全地从合法的压缩或非压缩点提取 X；
4. `selftest` 应将不支持的公钥编码报告为明确的 FAIL，而不是 traceback；
5. 为 65 字节硬件响应增加回归测试。

主机端兼容不应替代 Applet 的规范修复，因为协议和 Card File 明确定义了 33 字节压缩格式。

## 10. 结果汇总

| 测试项 | 结果 |
|---|---|
| CAP 构建 | PASS |
| CAP verification | PASS |
| 四组 README 主机端测试 | PASS |
| PC/SC 读卡器发现 | PASS |
| SELECT Applet | PASS |
| GET_INFO | PASS |
| GET_BALANCE | PASS |
| GET_SLOT_STATUS | PASS |
| GET_PUBKEY APDU | PASS，返回 `9000` |
| GET_PUBKEY 规范编码 | FAIL，实际为 65 字节非压缩格式 |
| 未修改的 `cardctl selftest` | FAIL，公钥格式异常导致 traceback |
| 未修改的 `cardctl sign` | FAIL，公钥格式异常导致 traceback |
| 公钥 secp256k1 曲线校验 | PASS |
| 三轮实体卡 BIP-340 签名验证 | PASS |
| 相同消息两次签名验证 | PASS |
| nonce/R 不复用检查 | PASS |
| `info` / `balance` / `slots --all` | PASS |
| 破坏性或状态修改命令 | 未执行 |

## 11. 结论

Applet 已正确安装并可在实体 JavaCard 上运行。SELECT、状态读取、slot 管理读取和 Schnorr 签名硬件路径均正常，BIP-340 验证及 nonce 新鲜性检查通过。

本次测试同时发现了一个可复现的公钥编码兼容缺陷：实体卡的 `ECPublicKey.getW()` 返回 65 字节非压缩点，而协议与 `cardctl` 要求 33 字节压缩点。该问题应作为 Applet/host interoperability 缺陷提交，并建议优先让 Applet 严格返回规范规定的压缩公钥，同时在主机工具中加入防御性兼容和更友好的错误处理。
