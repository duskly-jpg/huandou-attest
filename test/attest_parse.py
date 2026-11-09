# -*- coding: utf-8 -*-
"""
解析 Android Key Attestation 扩展（OID 1.3.6.1.4.1.11129.2.1.17）。

只取后端判断需要的几个字段，不做通用 ASN.1 解析：
  - attestationSecurityLevel  (0=Software 1=TEE 2=StrongBox)
  - attestationChallenge
  - teeEnforced[704] rootOfTrust  -> verifiedBootState / deviceLocked
  - teeEnforced[705] osVersion
  - softwareEnforced[709] attestationApplicationId -> packageName / signatureDigests

关于 709 的位置（2026-11-08 用真机证书实测更正）：
    它不在 teeEnforced 里，在 softwareEnforced 里。原因：包名和签名摘要由
    Android 的 keystore2 在签名前填进去，不是 Keymaster 在 TEE 内部生成的。
    这并不降低可信度——整张证书由 TEE 的密钥签名，softwareEnforced 改了签名就废，
    所以内容仍然不可篡改，只是「谁填的」不同。

关于包裹层数（同样是实测更正）：
    704  [704] EXPLICIT RootOfTrust(SEQUENCE)      -> 内容首字节 30
    705  [705] EXPLICIT INTEGER                    -> 内容首字节 02
    709  [709] EXPLICIT OCTET STRING(⟶SEQUENCE)     -> 内容首字节 04
    三者不一样。之前按「都是 SEQUENCE」写，测试数据也照着这个错误假设构造，
    结果测试全绿、真机全错。夹具已换成真实结构。

用法：
    from attest_parse import parse_extension
    der = cert.extensions.get_extension_for_oid(...).value.value   # pyca/cryptography
    info = parse_extension(der)

注意：tag 704/705/709 属于高 tag number，编码为 BF 85 40 / BF 85 41 / BF 85 45，
不是单字节 0xA0|n。这里已按 base-128 多字节形式处理。
"""

VBS = {0: "Verified", 1: "SelfSigned", 2: "Unverified", 3: "Failed"}
SEC = {0: "Software", 1: "TrustedEnvironment", 2: "StrongBox"}


def tlv(buf, pos):
    """返回 (tag_number, value_bytes, next_pos)。只处理单层，不做递归。"""
    b0 = buf[pos]
    pos += 1
    num = b0 & 0x1F
    if num == 0x1F:                       # 高 tag number
        num = 0
        while True:
            b = buf[pos]
            pos += 1
            num = (num << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
    ln = buf[pos]
    pos += 1
    if ln & 0x80:                         # 长长度
        n = ln & 0x7F
        ln = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    return num, buf[pos:pos + ln], pos + ln


def parse_extension(der):
    num, body, _ = tlv(der, 0)
    if num != 16:                         # SEQUENCE
        raise ValueError("not a KeyDescription SEQUENCE, tag=%d" % num)

    fields = []
    pos = 0
    while pos < len(body):
        n, v, pos = tlv(body, pos)
        fields.append((n, v))
    if len(fields) < 8:
        raise ValueError("KeyDescription has %d fields, expected 8" % len(fields))

    out = {
        "version": int.from_bytes(fields[0][1], "big"),
        "security_level": int.from_bytes(fields[1][1], "big"),
        "challenge": fields[4][1],
    }

    # 两个授权列表都要扫。704/705 只认 teeEnforced（那才是硬件保证的部分），
    # 709 只会出现在 softwareEnforced，由 keystore2 在交给 TEE 之前填好。
    for slot, source in ((6, "software"), (7, "tee")):
        blob = fields[slot][1]
        pos = 0
        while pos < len(blob):
            n, v, pos = tlv(blob, pos)

            if source != "tee" and n in (704, 705):
                continue

            if n == 704:                  # RootOfTrust
                # EXPLICIT 包裹的是完整 SEQUENCE，先剥一层
                if v and v[0] == 0x30:
                    _, v, _ = tlv(v, 0)
                names = ["verified_boot_key", "device_locked",
                         "verified_boot_state", "verified_boot_hash"]
                rt, p, i = {}, 0, 0
                while p < len(v):
                    _, vv, p = tlv(v, p)
                    if i < len(names):
                        rt[names[i]] = vv
                    i += 1
                out["root_of_trust"] = {
                    "verified_boot_key": rt.get("verified_boot_key", b""),
                    "device_locked": rt.get("device_locked", b"\x00") != b"\x00",
                    "verified_boot_state": int.from_bytes(
                        rt.get("verified_boot_state", b"\x03"), "big"),
                }

            elif n == 705:                # osVersion，INTEGER，如 16.0.0 -> 160000
                # [705] EXPLICIT 里装的是一整个 INTEGER TLV，不是裸字节。
                # 直接 int.from_bytes(v) 会把 02 03 这个头也算进去：
                # 02 03 02 71 00 -> 8640426240，看着像个正常的八位数，实际差了五个数量级。
                iv = v
                if iv and iv[0] == 0x02:
                    _, iv, _ = tlv(iv, 0)
                out["os_version"] = int.from_bytes(iv, "big")

            elif n == 709:                # AttestationApplicationId
                # [709] EXPLICIT OCTET STRING，OCTET STRING 里才是 SEQUENCE。
                # 2026-11-08 用真机证书才发现这层：原实现只剥 SEQUENCE，
                # 而测试数据也是照着同样错误假设造的，两边一起错、测试全绿。
                if v and v[0] == 0x04:
                    _, v, _ = tlv(v, 0)
                if v and v[0] == 0x30:
                    _, v, _ = tlv(v, 0)
                sets, p = [], 0
                while p < len(v):
                    _, vv, p = tlv(v, p)
                    sets.append(vv)

                pkgs, p = [], 0
                if sets:
                    while p < len(sets[0]):
                        _, pv, p = tlv(sets[0], p)
                        q, name, ver = 0, None, 0
                        while q < len(pv):
                            _, fv, q = tlv(pv, q)
                            if name is None:
                                name = fv
                            else:
                                ver = int.from_bytes(fv, "big")
                        if name is not None:
                            pkgs.append((name.decode("utf-8", "replace"), ver))

                digests, p = [], 0
                if len(sets) > 1:
                    while p < len(sets[1]):
                        _, dv, p = tlv(sets[1], p)
                        digests.append(dv)

                out["app_id"] = {"packages": pkgs,
                                 "signature_digests": digests,
                                 "source": source}

    return out


def summarize(info):
    rt = info.get("root_of_trust", {})
    aid = info.get("app_id", {})
    return {
        "version": info["version"],
        "security_level": SEC.get(info["security_level"], info["security_level"]),
        "boot": VBS.get(rt.get("verified_boot_state"), "missing"),
        "device_locked": rt.get("device_locked"),
        "os_version": info.get("os_version"),
        "packages": aid.get("packages"),
        "sig_digests_hex": [d.hex() for d in aid.get("signature_digests", [])],
    }


if __name__ == "__main__":
    import sys
    print("模块本身不含测试向量，请用真实证书链调用 parse_extension()。")
    print("最小自检：解析一个空 SEQUENCE 应该抛 ValueError")
    try:
        parse_extension(bytes([0x30, 0x00]))
        print("  FAIL: 空 SEQUENCE 没报错")
    except ValueError as e:
        print("  OK:", e)
