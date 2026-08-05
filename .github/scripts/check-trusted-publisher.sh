#!/usr/bin/env bash
# 在不上传任何东西的前提下，确认 PyPI 可信发布已经配好。
#
# 做法就是 gh-action-pypi-publish 内部做的那件事：拿 GitHub 签发的 OIDC
# 身份令牌，去索引的 mint-token 接口换一个短期上传令牌。换到了就说明
# owner / repo / workflow 文件名 / environment 四项声明和索引上登记的
# 完全对得上。换到的令牌立刻丢掉，不做任何上传。
#
# 为什么值得单独跑一次：不这么查的话，配置错了要等流水线跑满十分钟、
# 构建完、TestPyPI 也传完，才在最后一步失败——而那时 tag 已经用掉了。
#
# 必须在目标 environment 的 job 里跑：令牌里的 environment 声明是随
# job 的 environment 走的，在别处换到的令牌证明不了目标环境能用。
#
# 需要的环境变量：
#   INDEX_HOST        pypi.org | test.pypi.org
#   INDEX_LABEL       给人看的名字
#   SETUP_STEP        没配好时要指给用户看的那一步
#   ENVIRONMENT_NAME  本 job 所处的 environment，仅用于报错信息
set -euo pipefail

fail() {
  echo "::error::$1"
  {
    echo "## ❌ ${INDEX_LABEL} 可信发布尚未配好"
    echo
    echo "$1"
    echo
    echo "### 怎么修"
    echo
    echo "去 **${SETUP_STEP}**，在 <https://${INDEX_HOST}/manage/account/publishing/> 按这些值填："
    echo
    echo "| 字段 | 值 |"
    echo "|---|---|"
    echo "| PyPI Project Name | \`tg-attest\` |"
    echo "| Owner | \`${GITHUB_REPOSITORY%%/*}\` |"
    echo "| Repository name | \`${GITHUB_REPOSITORY##*/}\` |"
    echo "| Workflow name | \`release.yml\` |"
    echo "| Environment name | \`${ENVIRONMENT_NAME}\` |"
    echo
    echo "项目还不存在也能配——那叫 pending publisher，首次上传时自动建项目。"
    echo
    echo "配好之后重跑本次 workflow 即可，**不需要重新打 tag**：没有任何东西被发布出去。"
  } >> "$GITHUB_STEP_SUMMARY"
  exit 1
}

# id-token: write 没给的话，这两个变量根本不存在
if [ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] || [ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]; then
  fail "这个 job 拿不到 OIDC 令牌请求端点，说明缺少 \`permissions: id-token: write\`。"
fi

echo "查询 ${INDEX_LABEL} 期望的 audience…"
AUDIENCE=$(curl -sS --fail-with-body "https://${INDEX_HOST}/_/oidc/audience" \
           | python3 -c 'import json,sys; print(json.load(sys.stdin)["audience"])') \
  || fail "取不到 ${INDEX_LABEL} 的 audience，可能是索引临时不可用。"
echo "  audience = ${AUDIENCE}"

echo "向 GitHub 申请 OIDC 身份令牌…"
OIDC=$(curl -sS --fail-with-body \
        -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
        "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${AUDIENCE}" \
       | python3 -c 'import json,sys; print(json.load(sys.stdin)["value"])') \
  || fail "GitHub 没有签发 OIDC 令牌。"
echo "  已拿到身份令牌"

# 把声明打出来，配错时一眼能看出是哪一项对不上
python3 - "$OIDC" <<'PY'
import base64, json, sys
payload = sys.argv[1].split(".")[1]
payload += "=" * (-len(payload) % 4)
c = json.loads(base64.urlsafe_b64decode(payload))
print("  令牌声明：")
for k in ("repository", "workflow_ref", "environment", "ref", "sub"):
    if k in c:
        print(f"    {k} = {c[k]}")
PY

echo "拿它去 ${INDEX_LABEL} 换上传令牌…"
HTTP=$(curl -sS -o /tmp/mint.json -w '%{http_code}' \
        -X POST "https://${INDEX_HOST}/_/oidc/mint-token" \
        -H 'Content-Type: application/json' \
        -d "{\"token\": \"${OIDC}\"}")

if [ "$HTTP" != "200" ]; then
  echo "  HTTP ${HTTP}"
  sed -e 's/^/  /' /tmp/mint.json || true
  DETAIL=$(python3 -c '
import json
try:
    d = json.load(open("/tmp/mint.json"))
    m = d.get("message") or d
    if isinstance(m, dict): m = m.get("errors") or m
    print(str(m)[:400])
except Exception:
    print("（响应不是 JSON）")
')
  fail "${INDEX_LABEL} 拒绝了这个身份令牌（HTTP ${HTTP}）：${DETAIL}"
fi

# 令牌到手即丢，绝不打印——它能上传。
python3 -c '
import json, sys
d = json.load(open("/tmp/mint.json"))
if not d.get("token"):
    sys.exit("::error::mint-token 返回 200 但没有令牌")
print("  换到上传令牌，长度", len(d["token"]), "，随即丢弃")
'
rm -f /tmp/mint.json

echo "✅ ${INDEX_LABEL} 可信发布已配好"
{
  echo "### ✅ ${INDEX_LABEL} 可信发布已验证"
  echo
  echo "environment \`${ENVIRONMENT_NAME}\` 成功换到上传令牌，未上传任何内容。"
} >> "$GITHUB_STEP_SUMMARY"
