# -*- coding: utf-8 -*-
"""用构造的 DER 验证解析器：重点是高 tag number（704/705/709）能不能正确解出。"""
import os
import re
import sys
from attest_parse import parse_extension, summarize

FP = bytes.fromhex("9a1268033a798c2bb4dada49b4cd1a2e05ee96d07ab6e1d50aa391b42f2ee057")
CH = b"\x11" * 32


def L(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, body, high=False):
    if high:
        out = bytearray([0xBF])
        g = []
        t = tag
        while True:
            g.append(t & 0x7F)
            t >>= 7
            if not t:
                break
        g.reverse()
        for i, x in enumerate(g):
            out.append(x | (0x80 if i < len(g) - 1 else 0))
        return bytes(out) + L(len(body)) + body
    return bytes([tag]) + L(len(body)) + body


def seq(*items):
    return tlv(0x30, b"".join(items))


def integer(v):
    b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
    return tlv(0x02, b)


def enum(v):
    return tlv(0x0A, bytes([v]))


def octets(b):
    return tlv(0x04, b)


def boolean(v):
    return tlv(0x01, b"\xff" if v else b"\x00")


def build():
    root_of_trust = seq(
        octets(b"\xAA" * 32),      # verifiedBootKey
        boolean(True),             # deviceLocked
        enum(0),                   # Verified
        octets(b"\xBB" * 32),      # verifiedBootHash
    )
    # AttestationApplicationId ::= SEQUENCE { packageInfos SET, signatureDigests SET }
    # 注意：这里不能再套一层 seq()，SET 直接就是 SEQUENCE 的第一个元素
    app_id = seq(
        tlv(0x31, seq(octets(b"com.huandou.app"), integer(45))),   # packageInfos
        tlv(0x31, octets(FP)),                                     # signatureDigests
    )
    # 2026-11-08 修正：709 在 softwareEnforced 里，且外面包了一层 OCTET STRING。
    # 705 的内容是一整个 INTEGER TLV，不是裸的三字节数字。
    # 之前这两处都写错了，测试数据照着同样的错造，于是测试全绿、真机全错。
    sw = seq(
        tlv(709, octets(app_id), high=True),
    )
    tee = seq(
        tlv(704, root_of_trust, high=True),
        tlv(705, integer(160000), high=True),
    )
    return seq(
        integer(3), enum(1), integer(4), enum(1),
        octets(CH), octets(b""),
        sw,      # softwareEnforced
        tee,     # teeEnforced
    )



def ext_value(cert_der):
    """从整张证书里抠出 KeyDescription（extnValue 的内容）。"""
    # 1.3.6.1.4.1.11129.2.1.17 的完整 TLV：06 0a + 10 字节 OID
    oid = bytes([0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x01, 0x11])
    p = cert_der.find(oid)
    if p < 0:
        raise ValueError("证书里没有 Key Attestation 扩展")
    pos = p + len(oid)
    b = cert_der[pos]
    if b != 0x04:
        raise ValueError("扩展值不是 OCTET STRING")
    lb = cert_der[pos + 1]
    if lb & 0x80:
        n = lb & 0x7F
        start = pos + 2 + n
        ln = int.from_bytes(cert_der[pos + 2:pos + 2 + n], "big")
    else:
        start = pos + 2
        ln = lb
    return cert_der[start:start + ln]


def load_fixture(name):
    base = os.path.dirname(os.path.abspath(__file__))
    for sub in ("fixtures", "fixtures_real"):
        path = os.path.join(base, sub, name)
        if os.path.exists(path):
            der = open(path, "rb").read()
            return der, parse_extension(ext_value(der))
    raise FileNotFoundError(name)


def test_real_fixture(name, want_vc, want_ch, note):
    """
    真机证书回归（challenge 与 verifiedBootKey 已替换为固定值，其余原样）。

    第一条来自 2026-11-08 幻豆 1.8.7。当时结论是 sigdigest=1，但解析器对它跑出了
    错结果：709 完全没取到（因为它不在 tee 里）、osVersion 多了五个数量级。
    第二条是升级到 1.8.8 后在同一台机器上再导的一次，用来固定「versionCode 会跟着
    包变」这个事实。以后谁改解析器，都得先过这两关。
    """
    der, info = load_fixture(name)
    s = summarize(info)

    checks = [
        ("security_level", s["security_level"], "TrustedEnvironment"),
        ("challenge", info["challenge"], want_ch),
        ("packages", s["packages"], [("com.huandou.app", want_vc)]),
        ("sig_digests_hex", s["sig_digests_hex"], [FP.hex()]),
        ("app_id.source", info["app_id"].get("source"), "software"),
        ("os_version", s["os_version"], 160000),
        ("boot", s["boot"], "Verified"),
        ("device_locked", s["device_locked"], True),
        ("version", s["version"], 300),
    ]

    ok = True
    print("真机证书夹具 %s（%s）: %d 字节" % (name, note, len(der)))
    for cname, got, want in checks:
        good = got == want
        ok = ok and good
        print(("  OK   " if good else "  FAIL ") + cname + " =", got,
              "" if good else ("期望 " + str(want)))
    return ok


def test_real_fixtures():
    ok = True
    ok = test_real_fixture("leaf_attest.der", 47, b"\x11" * 32, "1.8.7") and ok
    ok = test_real_fixture("leaf_attest_v48.der", 48, b"\x33" * 32, "1.8.8") and ok

    # 两条链来自同一台设备、同一个签名密钥，只有 versionCode 不同。
    # 这条断言固定住一个结论：709 里的 versionCode 是生成密钥时实时从当前 APK 读的，
    # 不是缓存。所以「换回旧版官方包」这种降级，签名对得上，版本号对不上，后端能发现。
    _, a = load_fixture("leaf_attest.der")
    _, b = load_fixture("leaf_attest_v48.der")
    pairs = [
        ("两条链签名摘要相同",
         a["app_id"]["signature_digests"] == b["app_id"]["signature_digests"]),
        ("两条链 versionCode 不同",
         a["app_id"]["packages"][0][1] != b["app_id"]["packages"][0][1]),
        ("两条链 verifiedBootKey 相同（同一台设备）",
         a["root_of_trust"]["verified_boot_key"] == b["root_of_trust"]["verified_boot_key"]),
    ]
    for cname, got in pairs:
        print(("  OK   " if got else "  FAIL ") + cname)
        ok = ok and got
    return ok


def test_real_chain_signature():
    """
    用 openssl 验完整真机链的签名。

    这条夹具（chain_real_v48.pem）是原样的，一个字节都没改 —— 证书里只要动一个字节，
    上级签名立刻对不上。所以：脱敏过的 leaf_attest*.der 只能测「字段解析」，
    不能测验签；要测验签就用这条。

    链结构：EC 叶子 <- EC 中间 <- RSA 中间 <- RSA 根（自签）。
    中间证书由设备 TEE 在出厂时签发，随链上传。它不是公开 CA，不进 CT 日志，
    在任何公开渠道都搜不到，也不应该去搜。
    """
    import shutil
    import subprocess
    import tempfile

    if not shutil.which("openssl"):
        print("  SKIP  openssl 不可用，跳过真机链验签")
        return True

    here = os.path.dirname(os.path.abspath(__file__))
    pem_path = next(p for sub in ("fixtures", "fixtures_real")
                    for p in [os.path.join(here, sub, "chain_real_v48.pem")]
                    if os.path.exists(p))
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        open(pem_path).read(), re.S)
    if len(blocks) != 4:
        print("  FAIL 真机链应为 4 张，实际 %d 张" % len(blocks))
        return False

    with tempfile.TemporaryDirectory() as d:
        for n, b in zip(("leaf.pem", "int1.pem", "int2.pem", "root.pem"), blocks):
            open(os.path.join(d, n), "w").write(b + "\n")
        ints = os.path.join(d, "ints.pem")
        with open(ints, "w") as f:
            f.write(blocks[1] + "\n" + blocks[2] + "\n")
        r = subprocess.run(
            ["openssl", "verify",
             "-CAfile", os.path.join(d, "root.pem"),
             "-untrusted", ints,
             os.path.join(d, "leaf.pem")],
            capture_output=True, text=True)

    good = r.returncode == 0
    print(("  OK   " if good else "  FAIL ") + "真机 4 级链验签（EC 叶子 / EC 中间 / RSA 中间 / RSA 根）")
    if not good:
        print("        openssl:", (r.stdout or r.stderr).strip()[:240])
    return good


def main():
    der = build()
    print("构造的 KeyDescription 长度:", len(der), "字节")
    info = parse_extension(der)
    s = summarize(info)

    ok = True
    checks = [
        ("version", s["version"], 3),
        ("security_level", s["security_level"], "TrustedEnvironment"),
        ("boot", s["boot"], "Verified"),
        ("device_locked", s["device_locked"], True),
        ("os_version", s["os_version"], 160000),
        ("packages", s["packages"], [("com.huandou.app", 45)]),
        ("sig_digests_hex", s["sig_digests_hex"], [FP.hex()]),
        ("challenge", info["challenge"], CH),
    ]
    for name, got, want in checks:
        good = got == want
        ok = ok and good
        print(("  OK   " if good else "  FAIL ") + name + " =", got, "" if good else ("期望 " + str(want)))

    print()
    real_ok = test_real_fixtures()
    ok = ok and real_ok

    chain_ok = test_real_chain_signature()
    ok = ok and chain_ok

    print("\n总结果:", "全部通过" if ok else "有失败项")
    sys.exit(0 if ok else 1)



if __name__ == "__main__":
    main()
