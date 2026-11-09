#!/usr/bin/env bash
# run_bind.sh — §10 设备凭据 + 配置下发 集成测试（本地 dev / 线上通用）
# 用法: BASE=http://127.0.0.1:8790 CHAL_SOURCE=local SECRET=dev-test-secret-0123456789abcdef bash run_bind.sh
set -u
BASE="${BASE:-http://127.0.0.1:8790}"
SECRET="${SECRET:-dev-test-secret-0123456789abcdef}"
DIR="$(cd "$(dirname "$0")/fixtures" && pwd)"
PASS=0; FAIL=0

ok()   { PASS=$((PASS+1)); echo "  ok   $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL $1: $2"; }

# 预插 v49 challenge（真链 challenge=fdada2e1...）供 bind 消费
CHAL_HEX="fdada2e1ef6b50c47321e932158bef8e1d9fb0ca89e830b8558f0444859b9998"
BIND_ID="01BINDTEST000000000000000000000"
BIND_ID2="01BINDTEST000000000000000000001"
BIND_ID3="01BINDTEST000000000000000000002"
if [ "${CHAL_SOURCE:-local}" = "local" ]; then
  cd /home/z/my-project/tools/huandou-attest
  SQL="DELETE FROM attest_challenge WHERE id LIKE '01BIND%';"
  for id in "$BIND_ID" "$BIND_ID2" "$BIND_ID3"; do
    SQL+="INSERT OR REPLACE INTO attest_challenge (id, challenge, install_id, created_at, expires_at, consumed) VALUES ('$id', x'$CHAL_HEX', 'bindtest', strftime('%s','now'), strftime('%s','now')+600, 0);"
  done
  echo "$SQL" > /tmp/hd_bind_seed.sql
  npx wrangler d1 execute huandou-attest-db --local --file /tmp/hd_bind_seed.sql >/dev/null 2>&1
fi

post() { curl -sS --max-time 20 -X POST "$BASE$1" -H 'Content-Type: application/json' --data "$2"; }
code() { curl -sS --max-time 20 -o /dev/null -w '%{http_code}' "$@"; }

CHAIN=$(python3 -c "
import json
print(json.dumps([open('$DIR/real/v49_c%d.pem' % i).read() for i in (1,2,3,4)]))")

echo "== bind 主流程 =="
R=$(post /v1/attest/bind "{\"challenge_id\":\"$BIND_ID\",\"chain\":$CHAIN}")
TOKEN=$(echo "$R" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('device_token',''))" 2>/dev/null)
V=$(echo "$R" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('version_code','-'), d.get('level','-'), d.get('ok'))")
EXP=$(echo "$R" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('exp',0))")
NOW=$(date +%s)
if [ -n "$TOKEN" ] && [ "$V" = "49 1 True" ]; then ok "bind → token + level=1 version=49"; else fail "bind" "$R"; fi
D1=$(echo "$TOKEN" | cut -d. -f1 | python3 -c "
import sys,base64,json
s=sys.stdin.read().strip()
s += '='*(-len(s)%4)
print(json.loads(base64.urlsafe_b64decode(s))['d'])" 2>/dev/null)
if [ ${#D1} -ge 10 ]; then ok "device_id 服务端生成（$D1）"; else fail "device_id" "$TOKEN"; fi
DIFF=$((EXP-NOW))
if [ "$DIFF" -gt 600000 ] && [ "$DIFF" -le 605000 ]; then ok "exp ≈ 7 天（$DIFF s）"; else fail "exp" "$DIFF"; fi

echo "== config 下发 =="
C=$(curl -sS --max-time 20 "$BASE/v1/config" -H "Authorization: Bearer $TOKEN")
CFG_OK=$(echo "$C" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('ok'), 'etag' in d, 'config' in d)" 2>/dev/null)
if [ "$CFG_OK" = "True True True" ]; then ok "token → config 200（含 etag/config）"; else fail "config" "$C"; fi

echo "== config 拒绝路径（403 空体）=="
C2=$(curl -sS --max-time 20 "$BASE/v1/config")
H2=$(curl -sS --max-time 20 -o /dev/null -w '%{http_code} %{size_download}' "$BASE/v1/config")
if [ "${H2%% *}" = "403" ]; then ok "无 Authorization → 403"; else fail "无 Authorization" "$H2"; fi
TAMPER="X${TOKEN:1}"
H3=$(curl -sS --max-time 20 -o /dev/null -w '%{http_code}' "$BASE/v1/config" -H "Authorization: Bearer $TAMPER")
if [ "$H3" = "403" ]; then ok "token 改一字符 → 403"; else fail "token 篡改" "$H3"; fi
H4=$(code "$BASE/v1/config" -H "Authorization: Bearer ${TOKEN%.*}.AAAAAA")
if [ "$H4" = "403" ]; then ok "签名坏 → 403"; else fail "签名坏" "$H4"; fi

echo "== 过期 token（本地伪造，需 SECRET）=="
FT=$(python3 -c "
import hmac, hashlib, base64, json, time
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
p = b64u(json.dumps({'d':'$D1','l':1,'v':49,'e':int(time.time())-100}).encode())
s = b64u(hmac.new('$SECRET'.encode(), p.encode(), hashlib.sha256).digest())
print(p + '.' + s)")
H5=$(curl -sS --max-time 20 -o /dev/null -w '%{http_code}' "$BASE/v1/config" -H "Authorization: Bearer $FT")
if [ "$H5" = "403" ]; then ok "exp 过去式 → 403"; else fail "过期 token" "$H5"; fi

echo "== 注入字段（§10.4 最后一条）=="
R2=$(post /v1/attest/bind "{\"challenge_id\":\"$BIND_ID2\",\"chain\":$CHAIN,\"device_id\":\"hacker\",\"level\":2,\"version_code\":999}")
D2=$(echo "$R2" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('level','-'), d.get('version_code','-'), d.get('device_token','')[:10] if d.get('ok') else '')" 2>/dev/null)
if echo "$R2" | grep -q '"level":1' && echo "$R2" | grep -q '"version_code":49'; then ok "注入 device_id/level=2/version=999 → 全部按证书值"; else fail "注入字段" "$R2"; fi

echo "== 重复 bind 复用 device_id =="
D2B=$(echo "$R2" | python3 -c "import json,sys; d=json.load(sys.stdin); t=d['device_token'].split('.')[0]; t += '='*(-len(t)%4); import base64; print(json.loads(base64.urlsafe_b64decode(t))['d'])" 2>/dev/null)
if [ "$D2B" = "$D1" ]; then ok "同设备重复 bind → device_id 复用（$D1）"; else fail "复用" "$D2B vs $D1"; fi

echo "== 吊销 =="
if [ "${CHAL_SOURCE:-local}" = "local" ]; then
  npx wrangler d1 execute huandou-attest-db --local --command "UPDATE attest_devices SET revoked=1 WHERE device_id='$D1'" >/dev/null 2>&1
  H6=$(curl -sS --max-time 20 -o /dev/null -w '%{http_code}' "$BASE/v1/config" -H "Authorization: Bearer $TOKEN")
  if [ "$H6" = "403" ]; then ok "吊销后 config → 403"; else fail "吊销 config" "$H6"; fi
  R3=$(post /v1/attest/bind "{\"challenge_id\":\"$BIND_ID3\",\"chain\":$CHAIN}")
  RR=$(echo "$R3" | python3 -c "import json,sys; print(json.load(sys.stdin).get('reason',''))")
  if [ "$RR" = "device_revoked" ]; then ok "吊销后重新 bind → 拒"; else fail "吊销 rebind" "$RR"; fi
  npx wrangler d1 execute huandou-attest-db --local --command "UPDATE attest_devices SET revoked=0 WHERE device_id='$D1'" >/dev/null 2>&1
else
  echo "  (远程模式跳过吊销写库)"
fi

echo ""
echo "结果: $PASS 过 / $FAIL 败"
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
