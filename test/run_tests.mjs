// run_tests.mjs — attest.js 单元测试（Node 24，global webcrypto）
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import {
  parseCertificate, parseAttestation, verifyLink,
  bytesEqual, hexToBytes, bytesToHex, b64uEncode,
  extractCertsFromText,
} from '../src/attest.js';

const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');
const pem = (n) => readFileSync(path.join(DIR, n + '.pem'), 'utf8');
const parsePem = (n) => parseCertificate(pemToDer(pem(n)));
function pemToDer(p) {
  const b64 = p.replace(/-----[A-Z ]*-----/g, '').replace(/\s+/g, '');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

let passed = 0, failed = 0;
function assert(cond, name) {
  if (cond) { passed++; console.log('  ok  ' + name); }
  else { failed++; console.log('  FAIL ' + name); }
}

const CHALLENGE = new Uint8Array(32).map((_, i) => i);
const OFFICIAL = hexToBytes('9a1268033a798c2bb4dada49b4cd1a2e05ee96d07ab6e1d50aa391b42f2ee057');

const root = parsePem('root');
const inter = parsePem('intermediate');
const leaf = parsePem('leaf_ok');

console.log('[结构解析]');
assert(root.der.length > 0 && inter.der.length > 0 && leaf.der.length > 0, '三张证书都能解析');
assert(bytesEqual(root.issuerDn, root.subjectDn), '根自签 DN 一致');
assert(bytesEqual(leaf.issuerDn, inter.subjectDn), '叶子 issuer = 中间 subject');
assert(leaf.alg.name === 'ECDSA' && leaf.alg.hash === 'SHA-256', '叶子签名算法识别为 ECDSA-SHA256');

console.log('[KeyDescription]');
const att = parseAttestation(leaf.attestationRaw);
assert(att.securityLevel === 1, 'securityLevel = 1 (TEE)');
assert(bytesEqual(att.challenge, CHALLENGE), 'challenge 逐字节一致');
assert(att.osVersion === 160000, '705 osVersion = 160000（INTEGER TLV 去头正确）');
assert(att.rootOfTrust !== null, '704 rootOfTrust 存在');
assert(att.rootOfTrust.verifiedBootState === 0, 'verifiedBootState = 0');
assert(att.rootOfTrust.deviceLocked === true, 'deviceLocked = true');
assert(att.packageInfos.length === 1, '709 packageInfos = 1');
assert(att.packageInfos[0].packageName === 'com.huandou.app', '包名正确');
assert(att.packageInfos[0].versionCode === 48, 'versionCode = 48（不是 8640426240 那种错值）');
assert(att.signatureDigests.length === 1 && bytesEqual(att.signatureDigests[0], OFFICIAL), 'signatureDigests 与官方指纹一致');

console.log('[负例解析]');
const attBad = parseAttestation(parsePem('leaf_sigmismatch').attestationRaw);
assert(!bytesEqual(attBad.signatureDigests[0], OFFICIAL), 'sigmismatch 变体摘要确实不同');
const attChal = parseAttestation(parsePem('leaf_chalmismatch').attestationRaw);
assert(!bytesEqual(attChal.challenge, CHALLENGE), 'chalmismatch 变体 challenge 确实不同');
const attL0 = parseAttestation(parsePem('leaf_lvl0').attestationRaw);
assert(attL0.securityLevel === 0, 'lvl0 变体 securityLevel = 0');
const attUnl = parseAttestation(parsePem('leaf_unlocked').attestationRaw);
assert(attUnl.rootOfTrust.deviceLocked === false, 'unlocked 变体 deviceLocked = false');
const attB2 = parseAttestation(parsePem('leaf_boot2').attestationRaw);
assert(attB2.rootOfTrust.verifiedBootState === 2, 'boot2 变体 verifiedBootState = 2');
const attOs = parseAttestation(parsePem('leaf_osold').attestationRaw);
assert(attOs.osVersion === 90000, 'osold 变体 osVersion = 90000');
const attVo = parseAttestation(parsePem('leaf_verold').attestationRaw);
assert(attVo.packageInfos[0].versionCode === 40, 'verold 变体 versionCode = 40');
const attPkg = parseAttestation(parsePem('leaf_pkgbad').attestationRaw);
assert(attPkg.packageInfos[0].packageName === 'com.example.fake', 'pkgbad 变体包名正确读出');
const attN709 = parseAttestation(parsePem('leaf_no709').attestationRaw);
assert(attN709.packageInfos.length === 0, 'no709 变体无 packageInfos');
assert(parsePem('leaf_noext').attestationRaw === null, 'noext 变体无 attestation 扩展');

console.log('[验签]');
assert(leaf.keyAlgOid === '1.2.840.10045.2.1' && leaf.curveName === 'P-256', '叶子 EC P-256 密钥识别（namedCurve 从 SPKI 参数读出）');
assert(inter.keyAlgOid === '1.2.840.10045.2.1' && inter.algOid === '1.2.840.113549.1.1.11', '中间 EC 密钥 / RSA 签名算法并存（混合链形态）');
assert(await verifyLink(leaf, inter) === true, 'EC 叶子←EC 中间 签名有效（namedCurve + DER→P1363 转换）');
assert(await verifyLink(inter, root) === true, 'EC 中间←RSA 根 签名有效');
assert(await verifyLink(leaf, root) === false, '叶子←根 直接验签 = false（链级次序正确）');
const tamperedLeafBytes = new Uint8Array(leaf.tbs);
tamperedLeafBytes[tamperedLeafBytes.length - 1] ^= 0x01;
const tamperedLeaf = { ...leaf, tbs: tamperedLeafBytes };
assert(await verifyLink(tamperedLeaf, inter) === false, 'tbs 改一字节 → ECDSA 验签失败（原始字节纪律生效）');

console.log('[导出文本提取]');
const multi = extractCertsFromText('垃圾前缀\n' + pem('leaf_ok') + '中间说明\n' + pem('intermediate') + '\n尾部');
assert(multi.length === 2, '从混合文本里提取出 2 张 PEM 证书');
assert(bytesEqual(multi[0], leaf.der) && bytesEqual(multi[1], inter.der), '提取顺序 = 文本顺序（叶子在前）');

console.log(`\n结果: ${passed} 过 / ${failed} 败`);
process.exit(failed ? 1 : 0);
