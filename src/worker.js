// worker.js — 幻豆 Key Attestation 后端（免费档，单发 + 分步双模式）
import {
  parseCertificate, parseAttestation, verifyLink,
  bytesEqual, hexToBytes, bytesToHex, b64uEncode, b64uDecode,
  extractCertsFromText, normalizeChainInput, ATTESTATION_OID,
  semanticChecks,
} from './attest.js';

// ---------- 配置 ----------
const OFFICIAL_DIGEST_HEX = '9a1268033a798c2bb4dada49b4cd1a2e05ee96d07ab6e1d50aa391b42f2ee057';
const OFFICIAL_PACKAGE = 'com.huandou.app';
const MIN_OS_VERSION = 120000; // Android 12
const CHALLENGE_TTL = 120;     // 秒
const SESSION_TTL = 300;       // 分步会话秒数
const MAX_CERTS = 8;
const MAX_CERT_BYTES = 16384;
const BUILD = '2026-11-08.3'; // 三态 challenge / 缺根补全提示 / health 别名+roots / 策略层解耦

// Google 硬件认证根（https://android.googleapis.com/attestation/root，2026-11-08 抓取）
// [0] 经典 RSA-4096 根；[1] ECDSA "Key Attestation CA1" —— 与测试共享同一份文件
import TRUSTED_ROOT_PEMS from './roots.json';

function getTrustedRoots(env) {
  const pems = (env && env.TRUSTED_ROOTS_JSON)
    ? JSON.parse(env.TRUSTED_ROOTS_JSON)
    : TRUSTED_ROOT_PEMS;
  return pems.map(p => parseCertificate(pemToDer(p)));
}

function pemToDer(pem) {
  const b64 = pem.replace(/-----[A-Z ]*-----/g, '').replace(/\s+/g, '');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function minVersionCode(env) {
  // 线上 1.8.9 = versionCode 49，最低支持 = 线上-1 = 48（可走 env 覆盖）
  return Number((env && env.MIN_VERSION_CODE) || 48);
}
function expectedVersionCode(env) {
  // 严格模式：设置后要求 versionCode 精确相等（可走配置下发）
  if (env && env.EXPECTED_VERSION_CODE) return Number(env.EXPECTED_VERSION_CODE);
  return null;
}

// ---------- HTTP 骨架 ----------
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS },
  });
}

function reject(reason, detail, status = 400) {
  return json({ ok: false, verdict: 'reject', reason, detail: detail || '' }, status);
}

async function readBodyJson(request, maxBytes = 128 * 1024) {
  const text = await request.text();
  if (text.length > maxBytes) throw new Error('body_too_large');
  return JSON.parse(text);
}

// ---------- ULID（时间前缀 + 随机，Crockford base32） ----------
const B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
function ulid() {
  const out = [];
  let t = Date.now();
  for (let i = 0; i < 10; i++) { out.unshift(B32[t % 32]); t = Math.floor(t / 32); }
  const rnd = crypto.getRandomValues(new Uint8Array(16));
  for (let i = 0; i < 16; i++) out.push(B32[rnd[i] % 32]);
  return out.join('');
}

function randomChallenge() {
  return crypto.getRandomValues(new Uint8Array(32));
}

async function sha256(bytes) {
  const d = await crypto.subtle.digest('SHA-256', bytes);
  return new Uint8Array(d);
}

// ---------- D1 ----------
async function consumeChallenge(env, id, now) {
  // 三态区分（验收单 §2.2）：没发过 → not_found；发过已被消费 → used；
  // 发过且过期 → expired。软删除：consumed 标记保留一小时回放窗口，
  // 条件 UPDATE（AND consumed=0）保证并发下只有一个成功——双花仍不可能。
  if (typeof id !== 'string' || id.length < 8 || id.length > 64) return { notFound: true };
  const sel = await env.DB.prepare(
    'SELECT challenge, expires_at, install_id, consumed FROM attest_challenge WHERE id=?'
  ).bind(id).first();
  if (!sel) return { notFound: true };
  if (sel.consumed) return { used: true };
  if (sel.expires_at <= now) return { expired: true };
  const upd = await env.DB.prepare(
    'UPDATE attest_challenge SET consumed=1 WHERE id=? AND consumed=0'
  ).bind(id).run();
  if (!upd.success || upd.changes === 0) return { used: true };
  return { expired: false, challenge: new Uint8Array(sel.challenge), install_id: sel.install_id };
}

// ---------- 链规范化 ----------
// 返回 { error } 或 { certs, links }（links = 需验证的签名数）
function buildChain(env, certs) {
  if (!certs.length || certs.length > MAX_CERTS) return { error: ['chain_broken', '证书链为空或过长'] };
  for (const c of certs) {
    if (c.der.length > MAX_CERT_BYTES) return { error: ['chain_broken', '单张证书超大'] };
  }
  const roots = getTrustedRoots(env);
  const last = certs[certs.length - 1];
  let chain = certs;
  let appended = false;
  if (!roots.some(r => bytesEqual(r.der, last.der))) {
    // 末张不是受信根：按 issuer DN 匹配补挂受信根
    const match = roots.find(r => bytesEqual(r.subjectDn, last.issuerDn));
    if (!match) return { error: ['chain_broken', '链末级 issuer 与受信根不匹配'] };
    chain = [...certs, match];
    appended = true; // 请求链缺根——后续 reject detail / success warnings 会说明
  }
  // 相邻 issuer/subject DN 粗校验（真正的校验是签名）
  for (let i = 0; i + 1 < chain.length; i++) {
    if (!bytesEqual(chain[i].issuerDn, chain[i + 1].subjectDn)) {
      return { error: ['chain_broken', `第 ${i} 级 issuer 与下一级 subject 不衔接`] };
    }
  }
  return { certs: chain, links: chain.length - 1, appended };
}

// 请求体 → 解析好的证书数组。body.chain = 数组（PEM/DER/base64 混合，API 用）；
// body.export = App 原始导出文本（粘贴框用）。注意 extractCertsFromText 返回的是
// DER 字节，不能再过一遍 normalizeChainInput（只收字符串）——v49 修复。
function parseChainFromBody(body) {
  let derList;
  if (Array.isArray(body.chain)) derList = normalizeChainInput(body.chain);
  else if (typeof body.export === 'string' && body.export.trim()) {
    derList = extractCertsFromText(body.export);
  } else return null;
  if (!derList.length || derList.length > MAX_CERTS) return null;
  return derList.map(parseCertificate);
}

// 链哈希（分步会话绑定）
async function chainHash(certs) {
  const enc = new TextEncoder();
  const parts = certs.map(c => bytesToHex(c.der)).join('|');
  return sha256(enc.encode(parts));
}

// ---------- 语义校验：策略层已移入 attest.js（可独立单元测试），worker 只传策略常量 ----------
function policyCtx(env, now, challenge) {
  return {
    now,
    challenge,
    minVersion: minVersionCode(env),
    expectedVersion: expectedVersionCode(env),
    minOsVersion: MIN_OS_VERSION,
    officialPackage: OFFICIAL_PACKAGE,
    officialDigest: OFFICIAL_DIGEST_HEX,
  };
}

function successPayload(att, appended = false) {
  const pkg = att.packageInfos.find(p => p.packageName === OFFICIAL_PACKAGE);
  return {
    ok: true,
    verdict: 'L3',
    level: att.securityLevel,
    package: pkg ? pkg.packageName : OFFICIAL_PACKAGE,
    version_code: pkg ? pkg.versionCode : null,
    signature_digest: OFFICIAL_DIGEST_HEX,
    boot_state: att.rootOfTrust && att.rootOfTrust.verifiedBootState === 0 ? 'Verified' : 'Unknown',
    device_locked: !!(att.rootOfTrust && att.rootOfTrust.deviceLocked),
    os_version: att.osVersion,
    warnings: appended ? ['请求链缺根，已用内置 Google 根补全'] : [],
  };
}

// ---------- 端点：challenge ----------
async function handleChallenge(request, env) {
  let body = {};
  try { body = await readBodyJson(request); } catch { body = {}; }
  const now = Math.floor(Date.now() / 1000);
  const id = ulid();
  const challenge = randomChallenge();
  await env.DB.prepare(
    'INSERT INTO attest_challenge (id, challenge, install_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(id, challenge, (body.install_id || null), now, now + CHALLENGE_TTL).run();
  return json({
    challenge_id: id,
    challenge: b64uEncode(challenge),
    challenge_hex: bytesToHex(challenge),
    expires_in: CHALLENGE_TTL,
  });
}

// ---------- 端点：verify / bind（共用验签管线，成功响应不同） ----------
// §10：bind = 验证通过后签发 device_token（HMAC），设备身份按 verifiedBootKey 复用
async function handleVerify(request, env, mode = 'verify') {
  const now = Math.floor(Date.now() / 1000);
  let body;
  try {
    body = await readBodyJson(request);
  } catch {
    return reject('challenge_not_found', '请求体无效');
  }
  if (!body.challenge_id) return reject('challenge_not_found', '缺少 challenge_id');

  // 1. 原子取走 challenge（三态：not_found / used / expired）
  const c = await consumeChallenge(env, body.challenge_id, now);
  if (c.notFound) return reject('challenge_not_found', 'challenge 不存在（未下发或格式无效）');
  if (c.used) return reject('challenge_used', 'challenge 已被使用');
  if (c.expired) return reject('challenge_expired', 'challenge 已超过有效期');

  // 2+. 解析与验链
  let certs;
  try {
    certs = parseChainFromBody(body);
  } catch (e) {
    return reject('chain_broken', '证书解析失败: ' + e.message);
  }
  if (!certs) return reject('chain_broken', 'chain 为空或格式无法识别');
  const built = buildChain(env, certs);
  if (built.error) return reject(built.error[0], built.error[1]);

  // 叶子必须有 attestation 扩展（步骤 2）
  const leaf = built.certs[0];
  if (!leaf.attestationRaw) return reject('not_attested', '叶子证书没有 Key Attestation 扩展');

  // 3. 解析 KeyDescription
  let att;
  try {
    att = parseAttestation(leaf.attestationRaw);
  } catch (e) {
    return reject('not_attested', 'KeyDescription 解析失败: ' + e.message);
  }

  // 6. 验整条链签名（每级一张）
  for (let i = 0; i + 1 < built.certs.length; i++) {
    let okSign;
    try { okSign = await verifyLink(built.certs[i], built.certs[i + 1]); }
    catch (e) { return reject('chain_broken', `第 ${i} 级验签异常: ${e.message}`); }
    if (!okSign) return reject('chain_broken', `第 ${i} 级证书签名验证失败`);
  }

  // 7. 有效期
  for (let i = 0; i < built.certs.length; i++) {
    const cert = built.certs[i];
    if (cert.notBefore && now * 1000 < cert.notBefore) return reject('chain_broken', `第 ${i} 级证书尚未生效`);
    if (cert.notAfter && now * 1000 > cert.notAfter) return reject('chain_broken', `第 ${i} 级证书已过期`);
  }

  // 4/5/8~12
  const fail = semanticChecks(att, policyCtx(env, now, c.challenge));
  if (fail) {
    let detail = fail[1];
    if (fail[0] === 'challenge_mismatch' && built.appended) {
      detail += '（注：请求链缺根，已用内置根补全后验签通过）';
    }
    return reject(fail[0], detail);
  }

  if (mode === 'bind') {
    if (!env.ATTEST_BIND_SECRET) return json({ ok: false, verdict: 'reject', reason: 'server_error', detail: 'bind secret 未配置' }, 503);
    const token = await issueDeviceToken(env, att, now);
    if (token instanceof Response) return token; // issueDeviceToken 内部 reject 直接透传
    return json(token);
  }
  return json(successPayload(att, built.appended));
}

// ---------- device_token（§10.2） ----------
// payload = {"d":device_id,"l":level,"v":version,"e":exp}（不加密，不许放敏感信息）
// device_token = b64url(payload) + "." + b64url(HMAC-SHA256(secret, b64url(payload)))
const TOKEN_TTL = 7 * 24 * 3600; // 7 天

async function hmacSign(secret, bytes) {
  const key = await crypto.subtle.importKey(
    'raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, bytes));
}

async function issueDeviceToken(env, att, now) {
  // device_id 服务端生成（§10.2 三条不能省之一）；同一设备的 verifiedBootKey
  // 稳定不变（§2.1 实测），按它复用 device_id —— 重复 bind = 复用，不新建。
  // 客户端上报的 device_id/level/version_code 一律不读（§10.4 最后一条）。
  const bootKey = att.rootOfTrust ? att.rootOfTrust.verifiedBootKey : null;
  if (!bootKey || !bootKey.length) return reject('not_attested', '证书缺少 verifiedBootKey，无法建立设备凭据');
  const pkg = att.packageInfos.find(p => p.packageName === OFFICIAL_PACKAGE);
  const level = att.securityLevel;

  const existing = await env.DB.prepare(
    'SELECT device_id, revoked FROM attest_devices WHERE boot_key=?'
  ).bind(bootKey).first();
  if (existing && existing.revoked) {
    return reject('device_revoked', '该设备已被吊销', 403);
  }
  let deviceId;
  if (existing) {
    deviceId = existing.device_id; // 复用：同一设备重复 bind 不新建
    await env.DB.prepare(
      'UPDATE attest_devices SET last_seen_at=?, level=?, version_code=? WHERE device_id=?'
    ).bind(now, level, pkg.versionCode, deviceId).run();
  } else {
    deviceId = 'dvc' + bytesToHex(crypto.getRandomValues(new Uint8Array(10)));
    await env.DB.prepare(
      'INSERT INTO attest_devices (device_id, boot_key, level, version_code, created_at, last_seen_at, revoked) VALUES (?, ?, ?, ?, ?, ?, 0)'
    ).bind(deviceId, bootKey, level, pkg.versionCode, now, now).run();
  }
  const exp = now + TOKEN_TTL;
  const payloadObj = { d: deviceId, l: level, v: pkg.versionCode, e: exp };
  const payloadB64 = b64uEncode(new TextEncoder().encode(JSON.stringify(payloadObj)));
  const sig = await hmacSign(new TextEncoder().encode(env.ATTEST_BIND_SECRET), new TextEncoder().encode(payloadB64));
  return json({
    ok: true,
    device_token: payloadB64 + '.' + b64uEncode(sig),
    exp,
    level,
    version_code: pkg.versionCode,
  });
}

async function readDeviceToken(env, authHeader, now) {
  // 返回 payload 或 null（无效/过期/格式错）。403 一律空响应体。
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.slice(7).trim();
  const dot = token.indexOf('.');
  if (dot <= 0 || token.indexOf('.', dot + 1) !== -1) return null;
  const payloadB64 = token.slice(0, dot);
  let sig, payloadBytes;
  try {
    sig = b64uDecode(token.slice(dot + 1));
    payloadBytes = b64uDecode(payloadB64);
  } catch { return null; }
  const expect = await hmacSign(new TextEncoder().encode(env.ATTEST_BIND_SECRET || ''), new TextEncoder().encode(payloadB64));
  if (!bytesEqual(sig, expect)) return null;
  let payload;
  try { payload = JSON.parse(new TextDecoder().decode(payloadBytes)); } catch { return null; }
  if (!payload || typeof payload.d !== 'string' || !Number.isFinite(payload.e)) return null;
  if (payload.e <= now) return null; // 过期
  const dev = await env.DB.prepare(
    'SELECT revoked FROM attest_devices WHERE device_id=?'
  ).bind(payload.d).first();
  if (!dev || dev.revoked) return null; // 不存在或被吊销
  return payload;
}

// ---------- 端点：config（§10.3，Bearer 凭据下发） ----------
async function handleConfig(request, env) {
  const now = Math.floor(Date.now() / 1000);
  const payload = await readDeviceToken(env, request.headers.get('Authorization') || '', now);
  if (!payload) return new Response(null, { status: 403 }); // 403 且不返回任何内容
  const row = await env.DB.prepare(
    "SELECT value, etag FROM attest_config WHERE id='config'"
  ).first();
  let config = {};
  let etag = 'w/' + new Date(now * 1000).toISOString().slice(0, 10) + '.1';
  if (row) {
    try { config = JSON.parse(row.value) || {}; } catch { config = {}; }
    etag = row.etag || etag;
  }
  return json({ ok: true, config, etag });
}

// ---------- 端点：verify_step（分步，每请求最多验一级签名，适配免费档 10ms CPU） ----------
// init:  消耗 challenge，建会话，返回 session_id / total
// step:  验第 step 级签名；最后一级过后做全量语义校验并出判定
async function handleVerifyStep(request, env) {
  const now = Math.floor(Date.now() / 1000);
  let body;
  try {
    body = await readBodyJson(request);
  } catch {
    return reject('challenge_not_found', '请求体无效');
  }
  let certs;
  try {
    certs = parseChainFromBody(body);
  } catch (e) {
    return reject('chain_broken', '证书解析失败: ' + e.message);
  }
  if (!certs) return reject('chain_broken', 'chain 为空或格式无法识别');
  const built = buildChain(env, certs);
  if (built.error) return reject(built.error[0], built.error[1]);
  const chash = await chainHash(built.certs);

  if (body.init) {
    if (!body.challenge_id) return reject('challenge_not_found', '缺少 challenge_id');
    const c = await consumeChallenge(env, body.challenge_id, now);
    if (c.notFound) return reject('challenge_not_found', 'challenge 不存在（未下发或格式无效）');
    if (c.used) return reject('challenge_used', 'challenge 已被使用');
    if (c.expired) return reject('challenge_expired', 'challenge 已超过有效期');
    const leaf = built.certs[0];
    if (!leaf.attestationRaw) return reject('not_attested', '叶子证书没有 Key Attestation 扩展');
    let att;
    try { att = parseAttestation(leaf.attestationRaw); }
    catch (e) { return reject('not_attested', 'KeyDescription 解析失败: ' + e.message); }
    const fail = semanticChecks(att, policyCtx(env, now, c.challenge));
    if (fail) {
      let detail = fail[1];
      if (fail[0] === 'challenge_mismatch' && built.appended) {
        detail += '（注：请求链缺根，已用内置根补全后验签通过）';
      }
      return reject(fail[0], detail);
    }
    const sessionId = ulid();
    await env.DB.prepare(
      'INSERT INTO attest_session (id, chain_hash, challenge, step, total, created_at, expires_at) VALUES (?, ?, ?, 0, ?, ?, ?)'
    ).bind(sessionId, chash, c.challenge, built.links, now, now + SESSION_TTL).run();
    return json({
      ok: true, session_id: sessionId, step: 0, total: built.links,
      done: built.links === 0, // 理论上不会为 0（叶子不会是根）
    });
  }

  // step 调用
  const sid = body.session_id;
  if (!sid) return reject('challenge_used', '缺少 session_id');
  const srow = await env.DB.prepare(
    'SELECT chain_hash, challenge, step, total, expires_at FROM attest_session WHERE id=?'
  ).bind(sid).first();
  if (!srow) return reject('challenge_used', '会话不存在（可能已用完或过期）');
  if (srow.expires_at <= now) {
    await env.DB.prepare('DELETE FROM attest_session WHERE id=?').bind(sid).run();
    return reject('challenge_expired', '分步会话已过期，请重新发起');
  }
  if (!bytesEqual(new Uint8Array(srow.chain_hash), chash)) {
    return reject('chain_broken', '本次提交的证书链与会话建立时不一致');
  }
  const step = srow.step;
  const total = srow.total;
  if (step >= total) return reject('challenge_used', '会话步骤已用尽');

  // 只验这一级签名
  let okSign;
  try { okSign = await verifyLink(built.certs[step], built.certs[step + 1]); }
  catch (e) { return reject('chain_broken', `第 ${step} 级验签异常: ${e.message}`); }
  if (!okSign) {
    await env.DB.prepare('DELETE FROM attest_session WHERE id=?').bind(sid).run();
    return reject('chain_broken', `第 ${step} 级证书签名验证失败`);
  }

  const next = step + 1;
  if (next < total) {
    await env.DB.prepare('UPDATE attest_session SET step=? WHERE id=?').bind(next, sid).run();
    return json({ ok: true, session_id: sid, step: next, total, done: false });
  }

  // 最后一级也过了：出判定并清会话
  await env.DB.prepare('DELETE FROM attest_session WHERE id=?').bind(sid).run();
  const leaf = built.certs[0];
  if (!leaf.attestationRaw) return reject('not_attested', '叶子证书没有 Key Attestation 扩展');
  let att;
  try { att = parseAttestation(leaf.attestationRaw); }
  catch (e) { return reject('not_attested', 'KeyDescription 解析失败: ' + e.message); }
  const fail = semanticChecks(att, policyCtx(env, now, new Uint8Array(srow.challenge)));
  if (fail) return reject(fail[0], fail[1]);
  return json({ ...successPayload(att, built.appended), mode: 'stepwise', steps: total });
}

// ---------- 粘贴框页面 ----------
function page() {
  return new Response(`<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>幻豆 · Key Attestation 验证台</title>
<style>
:root{color-scheme:light}
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}
a,button,textarea,summary,select,input{outline:none} /* WebView 点击高亮/焦点框全关（蓝色方框元凶） */
button{-webkit-user-select:none;user-select:none}
textarea{width:100%;min-height:168px;border:1.5px solid #e3d7fa;border-radius:14px;padding:12px;font-size:11.5px;line-height:1.5;color:#3d3357;background:#fbfaff;resize:vertical;font-family:ui-monospace,Menlo,monospace}
textarea:focus{outline:none;border-color:#c9a7ff;background:#fff}
textarea:-webkit-autofill{-webkit-box-shadow:0 0 0 1000px #fbfaff inset;-webkit-text-fill-color:#3d3357}
body{font-family:Quicksand,Nunito,'PingFang SC','Microsoft YaHei',system-ui,sans-serif;
background:linear-gradient(165deg,#f6f2ff 0%,#fdf0f6 100%);min-height:100vh;color:#4a3d66;padding:14px 14px 44px}
.wrap{max-width:520px;margin:0 auto}
header{text-align:center;padding:20px 0 4px}
h1{font-size:20px;color:#6b4fa8;letter-spacing:.5px;font-weight:800}
.sub{font-size:12px;color:#a293c4;margin-top:5px}
.paw{font-size:16px}
.card{background:#fff;border-radius:22px;padding:16px 15px;margin-top:13px;box-shadow:0 6px 24px rgba(139,109,255,.10)}
.tag{display:inline-flex;align-items:center;gap:7px;font-size:13px;font-weight:800;color:#8a6cc9;margin-bottom:10px}
.tag .n{width:22px;height:22px;border-radius:50%;background:linear-gradient(135deg,#c9a7ff,#f7a8c4);color:#fff;display:inline-flex;align-items:center;justify-content:center;font-size:12px;flex:0 0 auto}
.btn{display:block;width:100%;padding:13px;border:none;border-radius:16px;font-size:15px;font-weight:800;cursor:pointer;color:#fff;background:linear-gradient(135deg,#b892f5,#f79ac0);box-shadow:0 4px 14px rgba(196,132,240,.35);font-family:inherit}
.btn:active{transform:scale(.98)}
.btn:disabled{opacity:.45;box-shadow:none}
.btn.ghost{background:#f4eefc;color:#7c5cbf;box-shadow:none;border:1.5px solid #e3d7fa}
.code-box{background:#f8f5fd;border:1.5px dashed #dccdf7;border-radius:14px;padding:12px;margin-top:12px}
.row{display:flex;gap:8px;align-items:flex-start;margin-top:8px}
.row:first-child{margin-top:0}
.row .k{flex:0 0 92px;font-size:12px;color:#a293c4;padding-top:3px;font-weight:700}
.row .v{flex:1;font-size:12px;word-break:break-all;color:#3d3357;font-family:ui-monospace,Menlo,monospace;line-height:1.5}
.copy{flex:0 0 auto;border:none;background:#efe7fb;color:#7c5cbf;font-size:11px;padding:5px 11px;border-radius:10px;font-weight:800;cursor:pointer;font-family:inherit}
.copy:active{background:#e2d4f8}
.hint{font-size:12px;color:#a293c4;line-height:1.7;margin-top:7px}
.btns{display:flex;flex-direction:column;gap:9px;margin-top:12px}
#result{display:none;margin-top:13px}
.banner{border-radius:18px;padding:15px;text-align:center}
.banner.okb{background:linear-gradient(135deg,#efe3ff,#ffe4ef)}
.banner.okb .v{font-size:30px;font-weight:800;color:#6b46c1;letter-spacing:1px}
.banner.badb{background:#ffe9ee}
.banner.badb .v{font-size:20px;font-weight:800;color:#c2447a}
.banner .why{font-size:12.5px;color:#8a75a8;margin-top:6px;line-height:1.6;word-break:break-all}
.fields{margin-top:11px;background:#f8f5fd;border-radius:14px;padding:11px 13px}
.steps{font-size:12px;color:#b0a2cc;margin-top:8px;text-align:center}
details{margin-top:10px}
summary{font-size:12px;color:#a293c4;cursor:pointer;font-weight:700}
pre{font-size:11px;white-space:pre-wrap;word-break:break-all;background:#f8f5fd;border-radius:12px;padding:10px;color:#5a4a8a;margin-top:6px}
.foot{text-align:center;font-size:11px;color:#c4b8de;margin-top:18px}
</style></head><body>
<div class="wrap">
<header>
  <h1><span class="paw">🐾</span> 幻豆 · Key Attestation 验证台</h1>
  <div class="sub">TEE 证书链验签 · 侧载分发防伪</div>
</header>

<div class="card">
  <span class="tag"><span class="n">1</span>获取挑战</span>
  <button class="btn" id="btn-ch">获取挑战</button>
  <div class="code-box" id="ch-box" style="display:none">
    <div class="row"><span class="k">挑战 (hex)</span><span class="v" id="ch-hex"></span><button class="copy" data-c="hex">复制</button></div>
    <div class="row"><span class="k">challenge_id</span><span class="v" id="ch-id"></span><button class="copy" data-c="id">复制</button></div>
    <div class="row"><span class="k">有效期</span><span class="v" id="ch-timer">120s</span></div>
  </div>
  <div class="hint" id="ch-hint">点击后把挑战 (hex) 复制到 App 里生成密钥证明，120 秒内有效。</div>
</div>

<div class="card">
  <span class="tag"><span class="n">2</span>粘贴证书链</span>
  <textarea id="chain" placeholder="把 App 导出的文本整段贴进来（PEM / 原始导出均可，叶子在前）"></textarea>
  <div class="btns">
    <button class="btn" id="btn-verify" disabled>验证（单发）</button>
    <button class="btn ghost" id="btn-verify-step" disabled>验证（分步 · 免费档稳）</button>
  </div>
  <div class="hint">单发失败会自动降级到分步，不用手动重试。</div>
</div>

<div id="result">
  <div class="banner" id="banner">
    <div class="v" id="r-v"></div>
    <div class="why" id="r-why"></div>
  </div>
  <div class="fields" id="r-fields" style="display:none"></div>
  <div class="steps" id="r-steps"></div>
  <details id="r-detail"><summary>原始 JSON</summary><pre id="r-raw"></pre></details>
</div>

<div class="foot">🐾 幻豆 · attest.flaros.xyz</div>
</div>
<script>
var CID = '', TIMER = null;
function $(id) { return document.getElementById(id); }
function esc(s) { return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;'); }
async function post(path, obj) {
  const r = await fetch(path, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(obj) });
  return { status: r.status, data: await r.json() };
}
$('btn-ch').onclick = async function() {
  this.disabled = true; this.textContent = '获取中…';
  try {
    const d = (await post('/v1/attest/challenge', {})).data;
    CID = d.challenge_id || '';
    $('ch-hex').textContent = d.challenge_hex || '';
    $('ch-id').textContent = d.challenge_id || '';
    $('ch-box').style.display = 'block';
    $('ch-hint').textContent = '把挑战 (hex) 复制进 App 生成密钥证明，导出文本贴到下一步。';
    var left = d.expires_in || 120;
    if (TIMER) clearInterval(TIMER);
    TIMER = setInterval(function() {
      left--; $('ch-timer').textContent = left + 's';
      if (left <= 0) { clearInterval(TIMER); $('ch-timer').textContent = '已过期，请重新获取'; }
    }, 1000);
    $('btn-verify').disabled = false; $('btn-verify-step').disabled = false;
  } catch (e) { $('ch-hint').textContent = '获取失败：' + e; }
  this.disabled = false; this.textContent = '获取挑战';
};
document.querySelectorAll('.copy').forEach(function(b) {
  b.onclick = function() {
    var t = b.getAttribute('data-c') === 'hex' ? $('ch-hex').textContent : $('ch-id').textContent;
    navigator.clipboard.writeText(t).then(function() {
      b.textContent = '已复制'; setTimeout(function() { b.textContent = '复制'; }, 1200);
    });
  };
});
function render(d, stepsNote) {
  var box = $('result'); box.style.display = 'block';
  var ok = d.ok === true;
  var banner = $('banner');
  banner.className = 'banner ' + (ok ? 'okb' : 'badb');
  $('r-v').textContent = ok ? ('✓ ' + (d.verdict || 'OK')) : ('✗ ' + (d.reason || '失败'));
  $('r-why').textContent = ok
    ? ('官方签名 · ' + (d.boot_state === 'Verified' ? '启动链已验证' : '启动状态未知') + ' · ' + (d.device_locked ? '设备锁定' : '设备未锁定'))
    : (d.detail || d.error || '请检查后重试');
  var f = $('r-fields'); f.innerHTML = ''; f.style.display = ok ? 'block' : 'none';
  if (ok) {
    [['包名', d.package], ['版本', d.version_code], ['安全等级', d.level === 2 ? '2（StrongBox）' : '1（TEE）'],
     ['签名摘要', String(d.signature_digest || '').slice(0, 16) + '…'], ['系统版本', d.os_version],
     ['警告', (d.warnings && d.warnings.length) ? d.warnings.join('；') : '无']
    ].forEach(function(kv) {
      var row = document.createElement('div'); row.className = 'row';
      row.innerHTML = '<span class="k">' + esc(kv[0]) + '</span><span class="v">' + esc(kv[1]) + '</span>';
      f.appendChild(row);
    });
  }
  $('r-steps').textContent = stepsNote || '';
  $('r-raw').textContent = JSON.stringify(d, null, 2);
  box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}
function setBusy(on) {
  $('btn-verify').disabled = on || !CID;
  $('btn-verify-step').disabled = on || !CID;
  if (on) $('btn-verify').textContent = '验证中…'; else $('btn-verify').textContent = '验证（单发）';
}
async function verifyFlow(stepwise) {
  var chainText = $('chain').value.trim();
  if (!CID) { render({ ok:false, reason:'no_challenge', detail:'请先获取挑战' }); return; }
  if (!chainText) { render({ ok:false, reason:'no_chain', detail:'请先粘贴证书链' }); return; }
  setBusy(true);
  try {
    if (!stepwise) {
      var r = await post('/v1/attest/verify', { challenge_id: CID, export: chainText });
      if (r.status < 500 && r.data && (r.data.ok || r.data.verdict === 'reject')) {
        render(r.data); setBusy(false); return;
      }
      // 5xx / 异常 → 自动降级分步
    }
    var d = (await post('/v1/attest/verify_step', { init: true, challenge_id: CID, export: chainText })).data;
    if (!d.ok && !d.session_id) { render(d); setBusy(false); return; }
    var total = d.total, n = 0;
    for (var s = 0; s < total; s++) {
      n = s + 1;
      d = (await post('/v1/attest/verify_step', { session_id: d.session_id, export: chainText })).data;
      if (d.ok === false) { render(d, '分步 ' + n + '/' + total + ' 处被拦'); setBusy(false); return; }
      if (d.done || d.verdict) break;
    }
    render(d, '分步验证完成（' + n + '/' + total + ' 级）');
  } catch (e) { render({ ok:false, reason:'network', detail:String(e) }); }
  setBusy(false);
}
$('btn-verify').onclick = function() { verifyFlow(false); };
$('btn-verify-step').onclick = function() { verifyFlow(true); };
</script></body></html>`, {
    headers: { 'Content-Type': 'text/html; charset=utf-8', ...CORS },
  });
}

// ---------- 路由 ----------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    if (request.method === 'GET' && (path === '/' || path === '/index.html')) return page();
    // health 别名四路（/v1/attest/health 为主，其余兼容验收单的探测路径）
    if (request.method === 'GET' &&
        (path === '/v1/attest/health' || path === '/health' || path === '/v1/health' || path === '/healthz')) {
      const rootCount = getTrustedRoots(env).length;
      return json({
        ok: true,
        service: 'huandou-attest',
        build: BUILD,
        roots: rootCount, // 内置受信根数量（全部来自 android.googleapis.com/attestation/root）
        time: Math.floor(Date.now() / 1000),
      });
    }
    if (request.method === 'POST' && path === '/v1/attest/challenge') {
      return handleChallenge(request, env);
    }
    if (request.method === 'POST' && path === '/v1/attest/verify') {
      return handleVerify(request, env);
    }
    if (request.method === 'POST' && path === '/v1/attest/bind') {
      return handleVerify(request, env, 'bind');
    }
    if (request.method === 'GET' && path === '/v1/config') {
      return handleConfig(request, env);
    }
    if (request.method === 'POST' && path === '/v1/attest/verify_step') {
      return handleVerifyStep(request, env);
    }
    return reject('not_found', '未知路径 ' + path, 404);
  },
  async scheduled(event, env) {
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare('DELETE FROM attest_challenge WHERE expires_at < ?').bind(now).run();
    // consumed 行保留 1 小时回放窗口（challenge_used 判定用），过期后清理
    await env.DB.prepare('DELETE FROM attest_challenge WHERE consumed=1 AND expires_at < ?')
      .bind(now - 3600).run();
    await env.DB.prepare('DELETE FROM attest_session WHERE expires_at < ?').bind(now).run();
  },
};
