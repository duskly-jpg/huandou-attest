#!/usr/bin/env bash
# 本地/线上通用验收矩阵。用法: BASE=http://127.0.0.1:8790 bash run_matrix.sh
set -u
BASE="${BASE:-http://127.0.0.1:8790}"
DIR="$(cd "$(dirname "$0")/fixtures" && pwd)"
PASS=0; FAIL=0

pem2json() { python3 -c "
import json,sys
files=sys.argv[1:]
out=[open(f).read() for f in files]
print(json.dumps(out))" "$@"; }

expect() { # $1=testname $2=expected_reason_or_OK $3=response_json
  local name="$1" want="$2" got="$3"
  local verdict reason ok
  verdict=$(echo "$got" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('verdict','?'))" 2>/dev/null)
  reason=$(echo "$got" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('reason',''))" 2>/dev/null)
  if [ "$want" = "OK" ]; then
    if [ "$verdict" = "L3" ]; then PASS=$((PASS+1)); echo "  ok   $name"
    else FAIL=$((FAIL+1)); echo "  FAIL $name (want L3, got verdict=$verdict reason=$reason)"; fi
  else
    if [ "$reason" = "$want" ]; then PASS=$((PASS+1)); echo "  ok   $name ($reason)"
    else FAIL=$((FAIL+1)); echo "  FAIL $name (want reason=$want, got verdict=$verdict reason=$reason)"; fi
  fi
}

# 夹具 challenge 是固定 32 字节（00..1f），本地模式一次性批量插入 30 行预置 challenge，
# new_chal 从文件顺序取 id（避免逐条 d1 execute 拖死网关）
CHAL_HEX="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
CHAL_FILE="/tmp/hd_chal_ids.txt"
if [ "${CHAL_SOURCE:-local}" = "local" ]; then
  cd /home/z/my-project/tools/huandou-attest
  : > "$CHAL_FILE"
  for i in $(seq 1 40); do echo "01PRE${i}x${RANDOM}${RANDOM}" >> "$CHAL_FILE"; done
  SQL="DELETE FROM attest_challenge WHERE id LIKE '01PRE%';"
  while read -r id; do
    SQL+="INSERT INTO attest_challenge (id, challenge, install_id, created_at, expires_at) VALUES ('$id', x'$CHAL_HEX', 'matrix', strftime('%s','now'), strftime('%s','now')+600);"
  done < "$CHAL_FILE"
  echo "$SQL" > /tmp/hd_chal_seed.sql
  npx wrangler d1 execute huandou-attest-db --local --file /tmp/hd_chal_seed.sql >/dev/null 2>&1
  new_chal() { local id; id=$(head -n 1 "$CHAL_FILE"); tail -n +2 "$CHAL_FILE" > "$CHAL_FILE.2" && mv "$CHAL_FILE.2" "$CHAL_FILE"; echo "$id"; }
else
  new_chal() { curl -sS --max-time 10 -X POST "$BASE/v1/attest/challenge" -H 'Content-Type: application/json' -d '{}' \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['challenge_id'])"; }
fi

verify() { # $1=chal_id $2...=pem files
  local cid="$1"; shift
  local chain; chain=$(pem2json "$@")
  curl -sS --max-time 15 -X POST "$BASE/v1/attest/verify" -H 'Content-Type: application/json' \
    -d "{\"challenge_id\":\"$cid\",\"chain\":$chain}"
}

echo "== 基线 =="
C=$(new_chal); R=$(verify "$C" "$DIR/leaf_ok.pem" "$DIR/intermediate.pem")
expect "完整链 → L3" OK "$R"
R2=$(verify "$C" "$DIR/leaf_ok.pem" "$DIR/intermediate.pem")
expect "同一 challenge_id 重放 → challenge_used" challenge_used "$R2"

echo "== 单变体负例（每个都用新 challenge）=="
for v in sig_mismatch:leaf_sigmismatch challenge_mismatch:leaf_chalmismatch software_key:leaf_lvl0 \
         device_unlocked:leaf_unlocked boot_unverified:leaf_boot2 os_too_old:leaf_osold \
         version_too_old:leaf_verold pkg_mismatch:leaf_pkgbad not_attested:leaf_no709 \
         not_attested:leaf_noext not_attested:leaf_nodigest; do
  want="${v%%:*}"; f="${v#*:}"
  C=$(new_chal); R=$(verify "$C" "$DIR/$f.pem" "$DIR/intermediate.pem")
  expect "$f → $want" "$want" "$R"
done

C=$(new_chal); R=$(verify "$C" "$DIR/leaf_ok.pem")
expect "砍成只剩叶子 → chain_broken" chain_broken "$R"

C=$(new_chal)
python3 - "$DIR" <<'PY' > /tmp/hd_tamper.json
import json,sys,os
d=open(os.path.join(sys.argv[1],'leaf_ok.pem')).read().replace('-----BEGIN CERTIFICATE-----','').replace('-----END CERTIFICATE-----','').replace('\n','')
b=bytearray(__import__('base64').b64decode(d))
# 在签名摘要 OCTET STRING 内容附近找个位置改一字节（challenge 区段：第 ~35 字节偏移粗改 KeyDescription）
# 更稳：直接改 challenge 字节 —— CHALLENGE 是 00..1f，改第一个 0x00 → 0x01 会命中 challenge 或 uniqueId。
# 改证书 tbs 内某个中部字节，大概率命中 challenge 授权块
b[len(b)//2] ^= 0xff  # 改 tbs 中部一字节（EC 叶子较短，别用硬编码偏移）
import base64
der=base64.b64encode(bytes(b)).decode()
pem='-----BEGIN CERTIFICATE-----\n'+'\n'.join(der[i:i+64] for i in range(0,len(der),64))+'\n-----END CERTIFICATE-----'
print(json.dumps([pem]))
PY
CHAIN=$(cat /tmp/hd_tamper.json)
R=$(curl -sS --max-time 15 -X POST "$BASE/v1/attest/verify" -H 'Content-Type: application/json' \
  -d "{\"challenge_id\":\"$C\",\"chain\":$CHAIN}")
r=$(echo "$R" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('reason',''))")
if [ "$r" = "chain_broken" ] || [ "$r" = "challenge_mismatch" ]; then PASS=$((PASS+1)); echo "  ok   篡改叶子字节 → 拒 ($r)"
else FAIL=$((FAIL+1)); echo "  FAIL 篡改叶子字节 (got $r)"; fi

echo "== 过期 =="
C=$(new_chal); R=$(verify "01NOTEXIST00000000000000000000000" "$DIR/leaf_ok.pem" "$DIR/intermediate.pem")
expect "不存在的 challenge → challenge_not_found" challenge_not_found "$R"
EXPIRED_ID="01EXPIREDTEST00000000000000000"
cd /home/z/my-project/tools/huandou-attest
npx wrangler d1 execute huandou-attest-db --local --command "INSERT OR REPLACE INTO attest_challenge (id, challenge, install_id, created_at, expires_at) VALUES ('$EXPIRED_ID', x'$(printf 'ab%.0s' {1..32})', 't', 1, 1)" >/dev/null 2>&1
R=$(curl -sS --max-time 15 -X POST "$BASE/v1/attest/verify" -H 'Content-Type: application/json' \
  -d "{\"challenge_id\":\"$EXPIRED_ID\",\"chain\":$(pem2json "$DIR/leaf_ok.pem" "$DIR/intermediate.pem")}")
expect "过期 challenge → challenge_expired" challenge_expired "$R"

echo "== 分步验证 =="
C=$(new_chal)
INIT=$(curl -sS --max-time 15 -X POST "$BASE/v1/attest/verify_step" -H 'Content-Type: application/json' \
  -d "{\"init\":true,\"challenge_id\":\"$C\",\"chain\":$(pem2json "$DIR/leaf_ok.pem" "$DIR/intermediate.pem")}")
SID=$(echo "$INIT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('session_id',''))")
TOTAL=$(echo "$INIT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('total',''))")
if [ -n "$SID" ] && [ "$TOTAL" = "2" ]; then PASS=$((PASS+1)); echo "  ok   分步 init（total=2）"
else FAIL=$((FAIL+1)); echo "  FAIL 分步 init: $INIT"; fi
S1=$(curl -sS --max-time 15 -X POST "$BASE/v1/attest/verify_step" -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$SID\",\"chain\":$(pem2json "$DIR/leaf_ok.pem" "$DIR/intermediate.pem")}")
DONE1=$(echo "$S1" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('done',''),d.get('step',''))")
S2=$(curl -sS --max-time 15 -X POST "$BASE/v1/attest/verify_step" -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$SID\",\"chain\":$(pem2json "$DIR/leaf_ok.pem" "$DIR/intermediate.pem")}")
expect "分步完成 → L3 (mode=stepwise)" OK "$S2"

echo "== 分步换链防调包 =="
C=$(new_chal)
INIT=$(curl -sS --max-time 15 -X POST "$BASE/v1/attest/verify_step" -H 'Content-Type: application/json' \
  -d "{\"init\":true,\"challenge_id\":\"$C\",\"chain\":$(pem2json "$DIR/leaf_ok.pem" "$DIR/intermediate.pem")}")
SID=$(echo "$INIT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('session_id',''))")
R=$(curl -sS --max-time 15 -X POST "$BASE/v1/attest/verify_step" -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$SID\",\"chain\":$(pem2json "$DIR/leaf_pkgbad.pem" "$DIR/intermediate.pem")}")
expect "分步中途换链 → chain_broken" chain_broken "$R"

echo "== 分步逐级验签失败 =="
echo "== 冒充根链（语义全过、第 1 级验签必挂）=="
C=$(new_chal); R=$(verify "$C" "$DIR/leaf_ok.pem" "$DIR/intermediate.pem" "$DIR/rogue_root.pem")
expect "单发冒充根 → chain_broken" chain_broken "$R"
C=$(new_chal)
INIT=$(curl -sS --max-time 15 -X POST "$BASE/v1/attest/verify_step" -H 'Content-Type: application/json' \
  -d "{\"init\":true,\"challenge_id\":\"$C\",\"chain\":$(pem2json "$DIR/leaf_ok.pem" "$DIR/intermediate.pem" "$DIR/rogue_root.pem")}")
SID=$(echo "$INIT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('session_id',''))")
if [ -n "$SID" ]; then PASS=$((PASS+1)); echo "  ok   分步冒充根 init 通过（total=3）"
else FAIL=$((FAIL+1)); echo "  FAIL 分步冒充根 init: $INIT"; fi
S1=$(curl -sS --max-time 15 -X POST "$BASE/v1/attest/verify_step" -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$SID\",\"chain\":$(pem2json "$DIR/leaf_ok.pem" "$DIR/intermediate.pem" "$DIR/rogue_root.pem")}")
echo "      (第0级：叶子←中间，应当通过) $S1"
S2=$(curl -sS --max-time 15 -X POST "$BASE/v1/attest/verify_step" -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$SID\",\"chain\":$(pem2json "$DIR/leaf_ok.pem" "$DIR/intermediate.pem" "$DIR/rogue_root.pem")}")
expect "分步第1级（中间←冒充根）→ chain_broken" chain_broken "$S2"

echo ""
echo "结果: $PASS 过 / $FAIL 败"
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
