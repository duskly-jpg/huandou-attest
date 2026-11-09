#!/usr/bin/env python3
"""生成合成 Key Attestation 测试链（真实签名，结构照 AOSP KeyMint 规范）。
输出 test/fixtures/{root,intermediate,leaf_*}.pem —— 仅测试用，不是真机证书。
真机夹具缺失（huandou-cloudflare/ 未随任务单传上来），负例覆盖度靠这套补。"""
import os, sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import datetime, hashlib

OUT = os.path.join(os.path.dirname(__file__), 'fixtures')
os.makedirs(OUT, exist_ok=True)

ATTEST_OID = '1.3.6.1.4.1.11129.2.1.17'
OFFICIAL_DIGEST = bytes.fromhex('9a1268033a798c2bb4dada49b4cd1a2e05ee96d07ab6e1d50aa391b42f2ee057')
CHALLENGE = bytes(range(32))  # 测试挑战：00..1f

# ---------- 手搓 ASN.1 ----------
def _len(b):
    n = len(b)
    if n < 0x80: return bytes([n])
    raw = n.to_bytes((n.bit_length()+7)//8, 'big')
    return bytes([0x80 | len(raw)]) + raw

def tlv(tag, content):
    return bytes([tag]) + _len(content) + content

def high_tag(num, constructed, content):
    # context class, high tag number form
    first = 0x80 | (0x20 if constructed else 0) | 0x1F
    digs = [num & 0x7f]
    num >>= 7
    while num:
        digs.insert(0, 0x80 | (num & 0x7f)); num >>= 7
    return bytes([first]) + bytes(digs) + _len(content) + content

def der_int(v):
    if v == 0: return tlv(0x02, b'\x00')
    raw = v.to_bytes((v.bit_length()+8)//8, 'big')
    return tlv(0x02, raw)

def der_enum(v):  return tlv(0x0A, bytes([v]))
def der_octet(b): return tlv(0x04, b)
def der_bool(v):  return tlv(0x01, b'\xff' if v else b'\x00')
def der_seq(*items): return tlv(0x30, b''.join(items))
def der_set(*items): return tlv(0x31, b''.join(items))
def der_utf8(s): return tlv(0x0C, s.encode())

def key_description(challenge=CHALLENGE, security_level=1,
                    verified_boot_state=0, device_locked=True,
                    os_version=160000, package='com.huandou.app',
                    version_code=48, sig_digest=OFFICIAL_DIGEST,
                    include_709=True, empty_digests=False):
    # AOSP 规范（source.android.com）：package_infos 与 signature_digests 都是
    # SET OF，从该字段存在起就是——不是真机特例
    app_id = der_seq(
        der_set(der_seq(der_octet(package.encode()), der_int(version_code))),
        der_set(der_octet(sig_digest)),
    )
    if empty_digests:
        app_id = der_seq(der_set(der_seq(der_octet(package.encode()), der_int(version_code))), der_set())
    sw = der_seq(high_tag(709, True, der_octet(app_id))) if include_709 else der_seq()
    tee = der_seq(
        high_tag(704, True, der_seq(
            der_octet(b'\x12\x83\x7c\xc3' + b'\x00'*28),   # verifiedBootKey（占位）
            der_bool(device_locked),
            der_enum(verified_boot_state),
            der_octet(hashlib.sha256(b'boot-hash').digest()),
        )),
        high_tag(705, True, der_int(os_version)),          # [705] EXPLICIT INTEGER
    )
    return der_seq(
        der_int(300),          # attestationVersion (KeyMint 3)
        der_enum(security_level),
        der_int(1),
        der_enum(security_level),
        der_octet(challenge),  # attestationChallenge
        der_octet(b''),        # uniqueId
        sw, tee,
    )

def make_key(root_key=None, issuer=None, subject_cn='leaf', ca=False, attestation_der=None,
             use_ec=False):
    """ec=True 用 ECDSA P-256 密钥（真机同款：叶子 EC，TEE 中间也是 EC）"""
    if use_ec:
        key = ec.generate_private_key(ec.SECP256R1())
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
         .issuer_name(issuer or x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
         .public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1))
         .not_valid_after(now + datetime.timedelta(days=3650)))
    if ca: b = b.add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    if attestation_der is not None:
        b = b.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(ATTEST_OID), attestation_der),
            critical=False)
    signer = root_key or key
    # 签名算法跟签名方密钥类型走：EC 签发 → ecdsa-with-SHA256（真机叶子即此形态）
    cert = b.sign(signer, hashes.SHA256())
    return key, cert

# ---------- 根 / 中间 ----------
# 真机链结构（OnePlus PJF110 实测）：EC 叶子 ← EC 中间(T=TEE) ← Google 根(RSA-4096/EC)
# 测试同构：EC 中间 ← RSA 测试根；EC 叶子 ← EC 中间
root_key, root_cert = make_key(subject_cn='HuanDou Test Root', ca=True)
inter_key, inter_cert = make_key(root_key,
    issuer=root_cert.subject, subject_cn='HuanDou Test Intermediate', ca=True, use_ec=True)

def name_of(c): return c.subject
_, leaf_ok = make_key(inter_key, issuer=inter_cert.subject,
                      subject_cn='HuanDou Key', attestation_der=key_description(), use_ec=True)

variants = {
    'leaf_sigmismatch': key_description(sig_digest=bytes([OFFICIAL_DIGEST[0]^1]) + OFFICIAL_DIGEST[1:]),
    'leaf_chalmismatch': key_description(challenge=bytes([CHALLENGE[0]^1]) + CHALLENGE[1:]),
    'leaf_lvl0': key_description(security_level=0),
    'leaf_unlocked': key_description(device_locked=False),
    'leaf_boot2': key_description(verified_boot_state=2),
    'leaf_osold': key_description(os_version=90000),
    'leaf_verold': key_description(version_code=40),
    'leaf_pkgbad': key_description(package='com.example.fake'),
    'leaf_no709': key_description(include_709=False),
    'leaf_nodigest': key_description(empty_digests=True),
}
leaves = {'leaf_ok': leaf_ok}
for name, att in variants.items():
    _, c = make_key(inter_key, issuer=inter_cert.subject, subject_cn='HuanDou Key '+name,
                    attestation_der=att)
    leaves[name] = c
# 无 attestation 扩展的普通叶子
_, leaf_noext = make_key(inter_key, issuer=inter_cert.subject, subject_cn='No Ext')
leaves['leaf_noext'] = leaf_noext

# 冒充根：与真根同 DN、不同密钥（用于打步骤级验签失败——语义全过但第 1 级签名必挂）
rogue_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
rogue_cert = (x509.CertificateBuilder()
    .subject_name(root_cert.subject).issuer_name(root_cert.subject)
    .public_key(rogue_key.public_key()).serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(rogue_key, hashes.SHA256()))
leaves['rogue_root'] = rogue_cert

def write(c, name):
    with open(os.path.join(OUT, name + '.pem'), 'wb') as f:
        f.write(c.public_bytes(serialization.Encoding.PEM))

write(root_cert, 'root')
write(inter_cert, 'intermediate')
for name, c in leaves.items():
    write(c, name)

# 测试根 PEM 也存成 JSON（供 .dev.vars 的 TRUSTED_ROOTS_JSON 用）
root_pem = root_cert.public_bytes(serialization.Encoding.PEM).decode()
import json
with open(os.path.join(OUT, 'test_root_json.txt'), 'w') as f:
    f.write(json.dumps([root_pem]))

print('fixtures ->', OUT)
for f in sorted(os.listdir(OUT)):
    print(' ', f, os.path.getsize(os.path.join(OUT, f)))
