# 手机完整性验证服务 · Android Key Attestation 服务端验签

Cloudflare Workers 上实现的 Android Key Attestation 验证后端，为[幻豆浏览器客户端](https://github.com/duskly-jpg/huandou)的「设备可信链」提供云端接入校验。不依赖 Google Play Integrity（无 GMS 设备、无上架记录的场景下不可用），直接验证 TEE 签发的 Key Attestation 证书链。

[![tests](https://github.com/duskly-jpg/huandou-attest/actions/workflows/tests.yml/badge.svg)](https://github.com/duskly-jpg/huandou-attest/actions/workflows/tests.yml)
[![release](https://img.shields.io/github/v/release/duskly-jpg/huandou-attest)](https://github.com/duskly-jpg/huandou-attest/releases)
[![license](https://img.shields.io/github/license/duskly-jpg/huandou-attest)](LICENSE)
![tests](https://img.shields.io/badge/tests-58%20passing-brightgreen)
![dependencies](https://img.shields.io/badge/dependencies-0%20npm-blue)

## 端点

| 端点 | 方法 | 作用 |
|---|---|---|
| `/v1/attest/challenge` | POST | 签发一次性 challenge（D1 会话绑定，防调包） |
| `/v1/attest/verify` | POST | 单发验签：证书链 + 709 扩展 + challenge 回显，出 verdict |
| `/v1/attest/verify_step` | POST | 分步验签协议：每请求只验一级签名，末步出结论，跳步被状态机卡死 |
| `/v1/attest/bind` | POST | 验签通过后签发 HMAC-SHA256 设备凭据（7 天 TTL） |
| `/v1/config` | GET | Bearer 验签后下发公告/黑名单/功能开关，etag 增量更新 |
| `/health` | GET | 存活探针 |

reason 码为文档固定集，另补 `challenge_mismatch`（文档第 5 步要求校验但固定集漏项）。

## 实现要点

- **零依赖 DER 解析与验签**（`src/attest.js`，492 行）：X.509 解析、709 扩展（OID `1.3.6.1.4.1.11129.2.1.17`）取安全等级/challenge 回显/包名/版本/签名摘要，不引入第三方证书库
- **信任集**：Google 经典 RSA-4096 根 + 新 ECDSA「Key Attestation CA1」双根（`src/roots.json`），支持环境变量覆盖（`TRUSTED_ROOTS_JSON`）
- **降级防线**（`run_policy.mjs` 覆盖）：客户端自报字段一律不采信；verifiedBootKey 是设备稳定指纹，据此生成 `device_id` 复用——重装重绑定不新建身份
- **吊销闭环**：`revoked=1` → config 403 + rebind 拒绝（boot_key 锁死，换 token 无效）
- **免费档实测跑通**：完整验签在 Workers 免费档 10ms CPU 限制内完成（文档称必须付费档，实测不成立）

## 测试

```
node  test/run_tests.mjs         # attest.js 单元测试（32 项）
node  test/run_policy.mjs        # 策略层：防降级/自报字段不采信（9 项）
node  test/run_real_chain.mjs    # 真机实拍链回归（17 项）
python3 test/test_attest_parse.py # DER 高位 tag 解析 + openssl 交叉验签（全部通过）
```

夹具三层：`test/fixtures/` 为合成的可控变体链（12 种正负例，`gen_fixtures.py` 可复现）；`test/fixtures_real/` 为真机导出的 4 级链（EC 叶子 / EC 中间 / RSA 中间 / RSA 根，含 openssl 独立交叉验签）。合成夹具覆盖解析器盲区，真机夹具固定「709 的 versionCode 取自当前 APK 而非缓存」这类结论。

端到端验收（`run_matrix.sh` 21 项 / `run_bind.sh` 12 项）依赖 wrangler dev + D1，不在 CI 内，本地跑：

```bash
wrangler dev                       # 需要 .dev.vars：TRUSTED_ROOTS_JSON / ATTEST_BIND_SECRET
bash test/run_matrix.sh
bash test/run_bind.sh
```

## 部署

```bash
npm i -g wrangler
wrangler d1 create huandou-attest-db      # id 填入 wrangler.jsonc
wrangler deploy
```

敏感配置走 secrets（不入库）：`TRUSTED_ROOTS_JSON`（信任根，默认用内置 Google 双根）、`ATTEST_BIND_SECRET`（bind 签名密钥）。

## 许可

MIT
