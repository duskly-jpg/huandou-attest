// run_policy.mjs — 策略层单元测试（§3.1 防降级 / §3.2 客户端自报字段不采信）
// 策略与验签解耦：直接喂数据给 semanticChecks，不跑签名验证。
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { parseCertificate, parseAttestation, semanticChecks } from '../src/attest.js';

const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');
const pemToDer = (p) => {
  const b64 = p.replace(/-----[A-Z ]*-----/g, '').replace(/\s+/g, '');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};
const OFFICIAL_PACKAGE = 'com.huandou.app';
const OFFICIAL_DIGEST = '9a1268033a798c2bb4dada49b4cd1a2e05ee96d07ab6e1d50aa391b42f2ee057';

let passed = 0, failed = 0;
const assert = (cond, name) => {
  if (cond) { passed++; console.log('  ok   ' + name); }
  else { failed++; console.log('  FAIL ' + name); }
};
const ctx = (att, overrides = {}) => ({
  now: Math.floor(Date.now() / 1000),
  challenge: att.challenge, // 用证书自带的 challenge 让第 5 步通过，专打版本判定
  minVersion: 48,           // 线上 1.8.9(v49) - 1
  expectedVersion: null,
  minOsVersion: 120000,
  officialPackage: OFFICIAL_PACKAGE,
  officialDigest: OFFICIAL_DIGEST,
  ...overrides,
});
const leafOf = (pemPath) => {
  const raw = new Uint8Array(readFileSync(pemPath));
  const cert = parseCertificate(raw[0] === 0x30 ? raw : pemToDer(new TextDecoder().decode(raw)));
  return { cert, att: parseAttestation(cert.attestationRaw) };
};
const reasonOf = (r) => (r ? r[0] : 'null(通过)');

// —— 真机夹具（现网实拍样本，权威） ——
const v47 = leafOf(path.join(DIR, 'real/leaf_attest.der'));      // 1.8.7, versionCode 47
const v48 = leafOf(path.join(DIR, 'real/leaf_attest_v48.der'));  // 1.8.8, versionCode 48
const v49 = leafOf(path.join(DIR, 'real/v49_c1.pem'));           // 1.8.9, versionCode 49

console.log('[§3.1 防降级：version_too_old]');
assert(v47.att.packageInfos[0].versionCode === 47, 'v47 夹具 versionCode=47');
assert(reasonOf(semanticChecks(v47.att, ctx(v47.att))) === 'version_too_old',
  'v47 → version_too_old（低于最低支持 48）');
assert(reasonOf(semanticChecks(v48.att, ctx(v48.att))) === 'null(通过)',
  'v48 → 通过（恰在最低支持线上）');
assert(reasonOf(semanticChecks(v49.att, ctx(v49.att))) === 'null(通过)',
  'v49 → 通过');
assert(reasonOf(semanticChecks(v49.att, ctx(v49.att, { expectedVersion: 49 }))) === 'null(通过)',
  '严格模式 expectedVersion=49 → v49 通过');
assert(reasonOf(semanticChecks(v48.att, ctx(v48.att, { expectedVersion: 49 }))) === 'version_mismatch',
  '严格模式 expectedVersion=49 → v48 被 version_mismatch 拦');

console.log('[§3.2 客户端自报字段不采信]');
// 策略函数签名里根本没有"客户端版本/包名"入口——只认证书里的 att
const r = semanticChecks(v49.att, ctx(v49.att));
assert(r === null && v49.att.packageInfos[0].versionCode === 49,
  '判定来源=证书 versionCode=49');
const workerSrc = readFileSync(path.join(DIR, '..', '..', 'src', 'worker.js'), 'utf8');
assert(!/\bbody\.(version_code|package\b|pkg\b)/.test(workerSrc),
  'worker.js 请求体里无 version_code/package 字段读取（grep 级物证）');
assert(!/body\.version/.test(workerSrc), 'worker.js 不读 body.version*');

// 附：challenge 三态在策略外（D1 层），由集成矩阵覆盖
console.log(`\n结果: ${passed} 过 / ${failed} 败`);
process.exit(failed ? 1 : 0);
