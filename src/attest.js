// attest.js — Android Key Attestation 解析与验链（零依赖，Workers/Node 双端可用）
// 依据《幻豆 · Key Attestation 后端接入指令 v1》：
//  - OID 1.3.6.1.4.1.11129.2.1.17 在叶子证书扩展里
//  - 704 rootOfTrust / 705 osVersion 在 teeEnforced；709 attestationApplicationId 在 softwareEnforced
//  - 705 内容是完整 INTEGER TLV（要去头）；709 是 EXPLICIT OCTET STRING 套 SEQUENCE
// 验签必须用原始 tbsCertificate 字节，不得重编码。

// ---------- 基础 DER ----------
export function readTLV(buf, pos) {
  const first = buf[pos];
  if (first === undefined) throw new Error('der:out_of_range');
  const cls = first >> 6;
  const constructed = !!(first & 0x20);
  let tagNum = first & 0x1f;
  let p = pos + 1;
  if (tagNum === 0x1f) {
    tagNum = 0;
    for (;;) {
      const b = buf[p++];
      if (b === undefined) throw new Error('der:bad_tag');
      tagNum = tagNum * 128 + (b & 0x7f);
      if (!(b & 0x80)) break;
    }
  }
  let len = buf[p++];
  if (len === undefined) throw new Error('der:bad_len');
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || p + n > buf.length) throw new Error('der:bad_len');
    len = 0;
    for (let i = 0; i < n; i++) { len = len * 256 + buf[p++]; }
  }
  const contentStart = p;
  const contentEnd = p + len;
  if (contentEnd > buf.length) throw new Error('der:truncated');
  return { cls, constructed, tagNum, contentStart, contentEnd, rawStart: pos, rawEnd: contentEnd };
}

export function children(buf, t) {
  const out = [];
  let p = t.contentStart;
  while (p < t.contentEnd) {
    const c = readTLV(buf, p);
    out.push(c);
    p = c.rawEnd;
  }
  return out;
}

export function parseIntBytes(buf, t) {
  // INTEGER 内容（补码），转非负整数
  let i = t.contentStart;
  // 跳过前导 0x00（若次字节高位为 1 的填充）
  while (i < t.contentEnd - 1 && buf[i] === 0 && buf[i + 1] & 0x80) i++;
  let v = 0;
  for (; i < t.contentEnd; i++) v = v * 256 + buf[i];
  return v;
}

// ---------- OID ----------
function findCtx(list, num) {
  for (const c of list) {
    if (c.cls !== 2) continue;
    // 重算 tag number（readTLV 的 tagNum 已处理高位 tag）
    if (c.tagNum === num) return c;
  }
  return null;
}

// ---------- OID ----------
function encodeOid(dotted) {
  const parts = dotted.split('.').map(Number);
  const out = [parts[0] * 40 + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    let n = parts[i];
    const stack = [n & 0x7f];
    n >>= 7;
    while (n > 0) { stack.unshift((n & 0x7f) | 0x80); n >>= 7; }
    out.push(...stack);
  }
  return new Uint8Array(out);
}

export const ATTESTATION_OID = '1.3.6.1.4.1.11129.2.1.17';
const ATTESTATION_OID_DER = encodeOid(ATTESTATION_OID);

function containsOidDer(haystack, oidDer) {
  // 在 DER 原始字节里搜完整 OID TLV（值部分），避免误匹配中间片段
  for (let i = 0; i + oidDer.length <= haystack.length; i++) {
    let ok = true;
    for (let j = 0; j < oidDer.length; j++) {
      if (haystack[i + j] !== oidDer[j]) { ok = false; break; }
    }
    if (ok) return true;
  }
  return false;
}

// ---------- 证书解析 ----------
const OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1';
const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';
const CURVE_NAMES = {
  '1.2.840.10045.3.1.7': 'P-256',
  '1.3.132.0.34': 'P-384',
  '1.3.132.0.35': 'P-521',
};

const SIG_ALGS = {
  '1.2.840.113549.1.1.5': { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-1' },
  '1.2.840.113549.1.1.11': { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
  '1.2.840.113549.1.1.12': { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
  '1.2.840.113549.1.1.13': { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
  '1.2.840.10045.4.3.2': { name: 'ECDSA', hash: 'SHA-256' },
  '1.2.840.10045.4.3.3': { name: 'ECDSA', hash: 'SHA-384' },
};

function readName(buf, t) { return buf.slice(t.rawStart, t.rawEnd); } // 原始 DN 字节，用于比对

function parseTime(buf, t) {
  const s = new TextDecoder().decode(buf.slice(t.contentStart, t.contentEnd));
  let m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
  let year;
  if (m) {
    year = parseInt(m[1], 10) < 50 ? 2000 + parseInt(m[1], 10) : 1900 + parseInt(m[1], 10);
  } else {
    m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
    if (!m) return null;
    year = parseInt(m[1], 10);
  }
  return Date.UTC(year, parseInt(m[2], 10) - 1, parseInt(m[3], 10),
    parseInt(m[4], 10), parseInt(m[5], 10), parseInt(m[6], 10));
}

export function parseCertificate(der) {
  const buf = der instanceof Uint8Array ? der : new Uint8Array(der);
  const cert = readTLV(buf, 0);
  if (cert.tagNum !== 16 || !cert.constructed) throw new Error('cert:not_sequence');
  const top = children(buf, cert); // [tbs, sigAlg, sigValue]
  if (top.length !== 3) throw new Error('cert:bad_structure');
  const [tbs, sigAlg, sigVal] = top;
  const tbsChildren = children(buf, tbs);
  // [0] version 可选, serial, sigAlg, issuer, validity, subject, spki, ...
  let idx = 0;
  if (tbsChildren[idx].cls === 2 && tbsChildren[idx].tagNum === 0) idx++;
  const serial = tbsChildren[idx++];
  const innerSigAlg = tbsChildren[idx++];
  const issuer = tbsChildren[idx++];
  const validity = tbsChildren[idx++];
  const subject = tbsChildren[idx++];
  const spki = tbsChildren[idx++];

  const sigAlgChildren = children(buf, sigAlg);
  // OID 内容字节 → dotted
  const oidBytes = buf.slice(sigAlgChildren[0].contentStart, sigAlgChildren[0].contentEnd);
  const algOidStr = decodeOid(oidBytes);
  if (!SIG_ALGS[algOidStr]) throw new Error('cert:unsupported_sig_alg:' + algOidStr);

  // SPKI 内层：[算法标识(OID + 参数), 公钥 BIT STRING]
  // ECDSA 密钥的 namedCurve 在参数里——importKey 时缺了它 webcrypto 直接报
  // "Missing field namedCurve"，真机链（叶子 ECDSA P-256）首个就踩中
  const spkiChildren = children(buf, spki);
  const spkiAlgChildren = children(buf, spkiChildren[0]);
  const keyOidStr = decodeOid(buf.slice(spkiAlgChildren[0].contentStart, spkiAlgChildren[0].contentEnd));
  let curveName = null;
  if (keyOidStr === OID_EC_PUBLIC_KEY) {
    if (spkiAlgChildren.length < 2) throw new Error('cert:missing_curve_param');
    curveName = CURVE_NAMES[decodeOid(buf.slice(spkiAlgChildren[1].contentStart, spkiAlgChildren[1].contentEnd))] || null;
    if (!curveName) throw new Error('cert:unsupported_curve');
  }

  const validityChildren = children(buf, validity);
  const notBefore = parseTime(buf, validityChildren[0]);
  const notAfter = parseTime(buf, validityChildren[1]);

  const sigContent = buf.slice(sigVal.contentStart, sigVal.contentEnd);
  const unusedBits = sigContent[0];
  if (unusedBits !== 0) throw new Error('cert:bad_bitstring');
  const signature = sigContent.slice(1);

  // 找扩展 [3]
  let attestationRaw = null;
  for (let i = idx; i < tbsChildren.length; i++) {
    const c = tbsChildren[i];
    if (c.cls === 2 && c.tagNum === 3) {
      const extSeq = children(buf, c)[0]; // SEQUENCE OF Extension
      for (const ext of children(buf, extSeq)) {
        const extChildren = children(buf, ext);
        const oidBytes2 = buf.slice(extChildren[0].contentStart, extChildren[0].contentEnd);
        if (bytesEqual(oidBytes2, ATTESTATION_OID_DER)) {
          // extnValue = OCTET STRING，内容是 KeyDescription 的 DER
          const extnValue = extChildren[extChildren.length - 1];
          attestationRaw = buf.slice(extnValue.contentStart, extnValue.contentEnd);
        }
      }
    }
  }

  return {
    der: buf.slice(cert.rawStart, cert.rawEnd),
    tbs: buf.slice(tbs.rawStart, tbs.rawEnd),
    spki: buf.slice(spki.rawStart, spki.rawEnd),
    issuerDn: readName(buf, issuer),
    subjectDn: readName(buf, subject),
    algOid: algOidStr,
    alg: SIG_ALGS[algOidStr],
    keyAlgOid: keyOidStr,   // SPKI 密钥类型 OID（rsaEncryption / id-ecPublicKey）
    curveName,              // ECDSA 时为 'P-256' 等，RSA 为 null
    signature,
    notBefore,
    notAfter,
    attestationRaw,
  };
}

function decodeOid(bytes) {
  const out = [Math.floor(bytes[0] / 40), bytes[0] % 40];
  let v = 0;
  for (let i = 1; i < bytes.length; i++) {
    v = v * 128 + (bytes[i] & 0x7f);
    if (!(bytes[i] & 0x80)) { out.push(v); v = 0; }
  }
  return out.join('.');
}

// ---------- KeyDescription 解析 ----------
export function parseAttestation(attestationRawDer) {
  const buf = attestationRawDer instanceof Uint8Array ? attestationRawDer : new Uint8Array(attestationRawDer);
  // 注意：extnValue 的内容本身就是 KeyDescription SEQUENCE 的 DER
  const kd = readTLV(buf, 0);
  if (kd.tagNum !== 16) throw new Error('kd:not_sequence');
  const f = children(buf, kd);
  // [attestationVersion INTEGER, attestationSecurityLevel ENUMERATED,
  //  keymasterVersion INTEGER, keymasterSecurityLevel ENUMERATED,
  //  attestationChallenge OCTET STRING, uniqueId OCTET STRING,
  //  softwareEnforced SEQ, teeEnforced SEQ]
  if (f.length < 8) throw new Error('kd:bad_structure');
  const securityLevel = parseIntBytes(buf, f[1]); // ENUMERATED 内容同样按整型读
  const challenge = buf.slice(f[4].contentStart, f[4].contentEnd);
  const softwareEnforced = children(buf, f[6]);
  const teeEnforced = children(buf, f[7]);

  const out = {
    securityLevel,
    challenge,
    rootOfTrust: null,       // { verifiedBootKey, deviceLocked, verifiedBootState }
    osVersion: null,         // 705
    packageInfos: [],        // 709 内 [{packageName, versionCode}]
    signatureDigests: [],    // 709 内 [Uint8Array]
  };

  // teeEnforced: 704 rootOfTrust ([704] EXPLICIT SEQUENCE)
  const t704 = findCtx(teeEnforced, 704);
  if (t704 && t704.constructed) {
    const inner = children(buf, t704); // EXPLICIT：里面是 RootOfTrust SEQUENCE
    if (inner.length === 1 && inner[0].tagNum === 16) {
      const rot = children(buf, inner[0]);
      // [verifiedBootKey OCTET STRING, deviceLocked BOOLEAN,
      //  verifiedBootState ENUMERATED, verifiedBootHash OCTET STRING]
      if (rot.length >= 3) {
        out.rootOfTrust = {
          verifiedBootKey: buf.slice(rot[0].contentStart, rot[0].contentEnd),
          deviceLocked: buf[rot[1].contentStart] !== 0,
          verifiedBootState: parseIntBytes(buf, rot[2]),
        };
      }
    }
  }

  // teeEnforced: 705 osVersion（[705] 内容是一整个 INTEGER TLV——无论 wrapper 是
  // constructed(EXPLICIT) 还是 primitive，children() 都能从内容起点解析出那个 INTEGER TLV）
  const t705 = findCtx(teeEnforced, 705);
  if (t705) {
    const intTlv = children(buf, t705);
    if (intTlv.length >= 1 && intTlv[0].tagNum === 2) {
      out.osVersion = parseIntBytes(buf, intTlv[0]);
    }
  }

  // softwareEnforced: 709 attestationApplicationId ([709] EXPLICIT OCTET STRING → SEQUENCE)
  const t709 = findCtx(softwareEnforced, 709);
  if (t709) {
    const wrapper = children(buf, t709); // [OCTET STRING]
    if (wrapper.length === 1) {
      // OCTET STRING 的内容 = AttestationApplicationId SEQUENCE 的 DER
      const appBuf = buf.slice(wrapper[0].contentStart, wrapper[0].contentEnd);
      try {
        const appSeq = readTLV(appBuf, 0);
        if (appSeq.tagNum === 16) {
          const appChildren = children(appBuf, appSeq);
          // AOSP 规范（source.android.com keystore attestation）：两个字段都是
          // SET OF，位置固定 —— [0]=package_infos(SET OF SEQUENCE)、
          // [1]=signature_digests(SET OF OCTET STRING)。按位置取+按类型校验，
          // 类型不对就保持空（fail-closed），不靠内容倒推位置。
          if (appChildren.length >= 1 && appChildren[0].tagNum === 17) {
            let ok = true;
            const pkgInfos = [];
            for (const pi of children(appBuf, appChildren[0])) {
              const pis = pi.tagNum === 16 ? children(appBuf, pi) : null;
              if (!pis || pis.length < 2 || pis[0].tagNum !== 4) { ok = false; break; }
              pkgInfos.push({
                packageName: new TextDecoder().decode(appBuf.slice(pis[0].contentStart, pis[0].contentEnd)),
                versionCode: parseIntBytes(appBuf, pis[1]),
              });
            }
            if (ok) out.packageInfos = pkgInfos;
          }
          if (appChildren.length >= 2 && appChildren[1].tagNum === 17) {
            let ok = true;
            const digests = [];
            for (const d of children(appBuf, appChildren[1])) {
              if (d.tagNum !== 4) { ok = false; break; }
              digests.push(appBuf.slice(d.contentStart, d.contentEnd));
            }
            if (ok) out.signatureDigests = digests;
          }
        }
      } catch { /* 709 结构异常 → 保持空，由语义校验 fail-closed 拒绝 */ }
    }
  }

  return out;
}

// ---------- 验签 ----------
export async function verifyLink(child, issuer) {
  // importKey 的算法必须按「签发者公钥的类型」拼：
  //  - RSA  公钥：{name:'RSASSA-PKCS1-v1_5', hash:<证书签名算法的 hash>}
  //  - ECDSA公钥：{name:'ECDSA', namedCurve:<SPKI 参数里的曲线>} —— namedCurve
  //    是必填项，漏了就是真机报的 "Missing field namedCurve in algorithm"
  // verify 的算法按「被验证书的签名算法 OID」拼（决定 hash）。
  const sigAlg = child.alg; // {name, hash}
  let keyAlg, verifyAlg;
  if (issuer.keyAlgOid === OID_EC_PUBLIC_KEY) {
    keyAlg = { name: 'ECDSA', namedCurve: issuer.curveName };
    verifyAlg = { name: 'ECDSA', hash: { name: sigAlg.hash } };
  } else {
    keyAlg = { name: 'RSASSA-PKCS1-v1_5', hash: { name: sigAlg.hash } };
    verifyAlg = keyAlg;
  }
  // X.509 的 ECDSA 签名是 DER 编码 (r,s 两个 INTEGER)，WebCrypto 只吃 P1363
  // 裸格式（定长 r‖s）——必须转换
  const sig = issuer.keyAlgOid === OID_EC_PUBLIC_KEY
    ? derSigToP1363(child.signature, issuer.curveName)
    : child.signature;
  const key = await crypto.subtle.importKey('spki', issuer.spki, keyAlg, false, ['verify']);
  return crypto.subtle.verify(verifyAlg, key, sig, child.tbs);
}

// DER SEQUENCE{r INTEGER, s INTEGER} → 定长 r‖s（P1363）
export function derSigToP1363(derSig, curveName) {
  const buf = derSig instanceof Uint8Array ? derSig : new Uint8Array(derSig);
  const seq = readTLV(buf, 0);
  if (seq.tagNum !== 16) throw new Error('sig:not_der_sequence');
  const parts = children(buf, seq);
  if (parts.length !== 2) throw new Error('sig:bad_ecdsa_structure');
  const size = { 'P-256': 32, 'P-384': 48, 'P-521': 66 }[curveName];
  if (!size) throw new Error('sig:unknown_curve:' + curveName);
  // r/s 可能是 256+ 位大数，不能走 JS Number——直接按字节去前导零再左填充
  const out = new Uint8Array(size * 2);
  for (let i = 0; i < 2; i++) {
    const t = parts[i];
    let bytes = buf.slice(t.contentStart, t.contentEnd);
    let start = 0;
    while (start < bytes.length && bytes[start] === 0) start++;
    bytes = bytes.slice(start);
    if (bytes.length > size) throw new Error('sig:component_too_long');
    out.set(bytes, (i === 0 ? 0 : size) + (size - bytes.length));
  }
  return out;
}

// ---------- 策略层（语义校验，纯 CPU，与验签解耦，可独立单元测试） ----------
// ctx: { now, challenge, minVersion, expectedVersion(null=关), minOsVersion,
//        officialPackage, officialDigest }
// 返回 null（通过）或 [reason, detail]
export function semanticChecks(att, ctx) {
  // 4. securityLevel
  if (att.securityLevel === 0) return ['software_key', '密钥由软件（非 TEE/StrongBox）生成'];
  if (att.securityLevel !== 1 && att.securityLevel !== 2) {
    return ['software_key', `未知 securityLevel=${att.securityLevel}`];
  }
  // 5. challenge（叶子证书里 TEE 签的那份）
  if (!ctx.challenge || !bytesEqual(att.challenge, ctx.challenge)) {
    return ['challenge_mismatch', '证书内 challenge 与下发不一致'];
  }
  // 8/9. rootOfTrust
  if (!att.rootOfTrust) return ['boot_unverified', 'teeEnforced 缺少 704 rootOfTrust'];
  if (att.rootOfTrust.verifiedBootState !== 0) return ['boot_unverified', 'verifiedBootState != Verified'];
  if (!att.rootOfTrust.deviceLocked) return ['device_unlocked', '设备 bootloader 处于解锁状态'];
  // 10. osVersion
  if (att.osVersion === null || att.osVersion < ctx.minOsVersion) {
    return ['os_too_old', `osVersion=${att.osVersion} 低于 Android 12 门槛`];
  }
  // 11. 包名 + 签名摘要（fail-closed：缺、空都拒绝，绝不跳过）
  if (!att.packageInfos.length) return ['not_attested', '证书缺少 709 attestationApplicationId 或 package_infos 为空'];
  if (!att.signatureDigests.length) return ['not_attested', '证书 709 signature_digests 为空'];
  const pkg = att.packageInfos.find(p => p.packageName === ctx.officialPackage);
  if (!pkg) return ['pkg_mismatch', `包名不是 ${ctx.officialPackage}`];
  const expectDigest = hexToBytes(ctx.officialDigest);
  const digestOk = att.signatureDigests.some(d => bytesEqual(d, expectDigest));
  if (!digestOk) return ['sig_mismatch', '证书里的签名摘要与官方指纹不一致'];
  // 12. 版本（只能信证书里的，客户端自报字段一律不看）
  const minV = ctx.minVersion;
  if (pkg.versionCode < minV) return ['version_too_old', `versionCode=${pkg.versionCode} 低于最低支持 ${minV}`];
  if (ctx.expectedVersion !== null && pkg.versionCode !== ctx.expectedVersion) {
    return ['version_mismatch', `versionCode=${pkg.versionCode} 不是当前线上版本 ${ctx.expectedVersion}`];
  }
  return null;
}

// ---------- 工具 ----------
export function bytesEqual(a, b) {
  const x = a instanceof Uint8Array ? a : new Uint8Array(a);
  const y = b instanceof Uint8Array ? b : new Uint8Array(b);
  if (x.length !== y.length) return false;
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return false;
  return true;
}

export function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

export function bytesToHex(b) {
  return [...b].map(x => x.toString(16).padStart(2, '0')).join('');
}

export function b64uEncode(bytes) {
  let s = '';
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64uDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// PEM / 导出文本 → DER 数组（容忍任意杂项文本）
export function extractCertsFromText(text) {
  const out = [];
  const pemRe = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  const pems = text.match(pemRe);
  if (pems && pems.length) {
    for (const pem of pems) {
      const b64 = pem.replace(/-----[A-Z ]*-----/g, '').replace(/\s+/g, '');
      out.push(b64uDecode(b64.replace(/\+/g, '-').replace(/\//g, '_')));
    }
    return out;
  }
  // 退路：找长 base64 块（连续 ≥100 个 base64 字符）
  const b64Re = /[A-Za-z0-9+/=\n]{200,}/g;
  const blobs = text.match(b64Re);
  if (blobs) {
    for (const blob of blobs) {
      const clean = blob.replace(/\s+/g, '');
      try {
        const der = b64uDecode(clean.replace(/\+/g, '-').replace(/\//g, '_'));
        const t = readTLV(der, 0);
        if (t.tagNum === 16) out.push(der);
      } catch { /* 不是证书，跳过 */ }
    }
  }
  return out;
}

// JSON body 的 chain 数组：PEM 字符串 / base64 / base64url 均可
export function normalizeChainInput(chainArr) {
  const out = [];
  for (const item of chainArr) {
    if (typeof item !== 'string' || !item.length) continue;
    if (item.includes('-----BEGIN')) {
      out.push(...extractCertsFromText(item));
      continue;
    }
    const clean = item.replace(/\s+/g, '');
    let der = null;
    try { der = b64uDecode(clean); } catch { continue; }
    try {
      const t = readTLV(der, 0);
      if (t.tagNum === 16 && t.cls === 0) out.push(der);
    } catch { /* skip */ }
  }
  return out;
}
