# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 格式，版本号遵循语义化版本。

## [Unreleased]

### Added

- README 补「环境变量与 Secrets」表：逐一说明 `TRUSTED_ROOTS_JSON` / `ATTEST_BIND_SECRET` / `MIN_VERSION_CODE` / `EXPECTED_VERSION_CODE` / `DB` 的类型、必填性与默认值，并附 D1 免费档限额参考
- 本 CHANGELOG

## [1.0.0] - 2026-11-08

### Added

- Android Key Attestation 服务端验签（Cloudflare Workers + D1），零依赖 DER/X.509 解析（`src/attest.js`）
- 端点集：`/v1/attest/challenge`（一次性 challenge 防调包）、`/v1/attest/verify`（单发验签）、`/v1/attest/verify_step`（分步验签状态机）、`/v1/attest/bind`（HMAC-SHA256 设备凭据，7 天 TTL）、`/v1/config`（Bearer 下发公告/黑名单/功能开关，etag 增量）
- 信任集：Google 经典 RSA-4096 根 + 新 ECDSA「Key Attestation CA1」双根，支持 `TRUSTED_ROOTS_JSON` 覆盖
- 吊销闭环：`revoked=1` → config 403 + rebind 拒绝（boot_key 锁死）
- 每日 cron 03:30 过期会话清理
- 测试三层：单元（32 项）+ 策略（9 项）+ 真机实拍链回归（17 项），另有端到端 matrix（21 项）/ bind（12 项）脚本
- CI：tests workflow + CodeQL 静态安全扫描（buildless）

[Unreleased]: https://github.com/duskly-jpg/huandou-attest/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/duskly-jpg/huandou-attest/releases/tag/v1.0.0
