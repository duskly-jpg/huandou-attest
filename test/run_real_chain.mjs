// run_real_chain.mjs — 用真机实拍链（OnePlus / Android 16 现网样本）做回归测试
// 真链结构：EC 叶子 ← EC 中间 ← EC 中间 ← Google RSA-4096 根
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import {
  parseCertificate, parseAttestation, verifyLink,
  bytesEqual, hexToBytes,
} from '../src/attest.js';

const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');
const pemToDer = (p) => {
  const b64 = p.replace(/-----[A-Z ]*-----/g, '').replace(/\s+/g, '');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

let passed = 0, failed = 0;
const assert = (cond, name) => {
  if (cond) { passed++; console.log('  ok   ' + name); }
  else { failed++; console.log('  FAIL ' + name); }
};

const certs = [1, 2, 3, 4].map(i =>
  parseCertificate(pemToDer(readFileSync(path.join(DIR, 'real/c' + i + '.pem'), 'utf8'))));

console.log('[真链形态]');
assert(certs[0].keyAlgOid === '1.2.840.10045.2.1' && certs[0].curveName === 'P-256', 'c1 叶子 = EC P-256');
assert(certs[1].keyAlgOid === '1.2.840.10045.2.1' && certs[2].keyAlgOid === '1.2.840.10045.2.1', 'c2/c3 中间 = EC');
assert(certs[3].keyAlgOid === '1.2.840.113549.1.1.1', 'c4 根 = RSA-4096（Google）');

console.log('[KeyDescription]');
const att = parseAttestation(certs[0].attestationRaw);
assert(att.securityLevel === 1, 'securityLevel = 1 (TEE)');
assert(att.rootOfTrust && att.rootOfTrust.deviceLocked === true, 'deviceLocked = true');
assert(att.rootOfTrust && att.rootOfTrust.verifiedBootState === 0, 'verifiedBootState = 0 (Verified)');
assert(att.osVersion === 160000, 'osVersion = 160000 (Android 16)');
assert(att.packageInfos.length === 1 && att.packageInfos[0].packageName === 'com.huandou.app'
  && [47, 48].includes(att.packageInfos[0].versionCode),
  'packageInfos = com.huandou.app v47/v48（SET OF 编码识别）');
const OFFICIAL = hexToBytes('9a1268033a798c2bb4dada49b4cd1a2e05ee96d07ab6e1d50aa391b42f2ee057');
assert(att.signatureDigests.some(d => bytesEqual(d, OFFICIAL)), 'signatureDigests 含官方指纹');

// leaf_attest.der / leaf_attest_v48.der 双夹具
for (const f of ['leaf_attest.der', 'leaf_attest_v48.der']) {
  const c = parseCertificate(new Uint8Array(readFileSync(path.join(DIR, 'real/' + f))));
  const a = parseAttestation(c.attestationRaw);
  assert(a.packageInfos.length === 1 && a.packageInfos[0].packageName === 'com.huandou.app',
    f + ' 包名解析（SET 编码）');
  assert(a.signatureDigests.some(d => bytesEqual(d, OFFICIAL)), f + ' 官方摘要匹配');
}

console.log('[逐级验签]');
assert(await verifyLink(certs[0], certs[1]) === true, 'c1←c2 (EC←EC, namedCurve+P1363)');
assert(await verifyLink(certs[1], certs[2]) === true, 'c2←c3 (EC←EC)');
assert(await verifyLink(certs[2], certs[3]) === true, 'c3←c4 (EC←RSA-4096)');

// Google RSA-4096 根 DER 比对（内嵌信任锚一致性）
const embedded = readFileSync(path.join(DIR, '..', '..', 'src', 'roots.json'), 'utf8');
const roots = JSON.parse(embedded);
const rootDer = pemToDer(roots[0]);
assert(bytesEqual(rootDer, certs[3].der), 'c4 与内嵌 Google 根逐字节一致');

console.log(`\n结果: ${passed} 过 / ${failed} 败`);
process.exit(failed ? 1 : 0);
