#!/usr/bin/env python3
"""tg-attest 披露包独立验证工具。

审计/监管方用法（不需要账本，不需要联系出具方）：

    python -m tg_attest.cli decision_0007.json --ca /path/to/tsa_ca.pem

关于 --ca：信任根必须由你自己获得，不要用出具方给的。
  · DigiCert / Sectigo 等：根已在系统信任库，直接
        --ca /etc/ssl/certs/ca-certificates.crt
  · eIDAS 合格时间戳：从 EU 可信列表 (EUTL) 核对 QTSP 后取其根证书。
        https://eidas.ec.europa.eu/efda/trust-services/
  · 不提供 --ca 时本工具拒绝给出「通过」，这是刻意行为。

退出码：0 = 通过，1 = 未通过。可直接用于 CI 或批量抽检。
"""
import argparse
import json
import sys

from .verify import verify_bundle


def _recheck_qualified(bundle: dict, snapshot_path: str, r) -> None:
    """用审计方自己的快照复算合格状态，与包内声明比对。

    这是不变量 3 落到本功能上的样子：审计方不该相信包里写的那个 True。
    但要注意复算的前提——快照得是**当时那一份**。可信列表没有官方历史
    归档，今天下载的列表回答的是今天的问题。所以不一致未必是造假，
    也可能只是资质在这段时间里被撤销了，而那恰恰是本字段存在的理由。
    工具只报「不一致」，不替你下结论。
    """
    import base64

    from .anchor import check_qualified

    tok = bundle.get("tsa_token")
    if not tok:
        return
    v = check_qualified(base64.b64decode(tok), snapshot_path)
    r.attestations["eIDAS 合格状态（用你提供的快照独立复算）"] = {
        "tsa_qualified": v.qualified, "eutl_ref": v.ref, "reason": v.reason,
    }
    claimed = (bundle.get("eutl_attestation") or {}).get("tsa_qualified")
    if claimed is not None and v.qualified is not None and claimed != v.qualified:
        r.attestations["⚠ 声明与复算不一致"] = {
            "tsa_qualified": None,
            "eutl_ref": None,
            "reason": f"包内声明 {claimed}，用本快照复算得 {v.qualified}。"
                      "可信列表没有官方历史归档，两者不一致可能是资质在此期间"
                      "变化所致，也可能是声明不实——本工具不替你判断。",
        }


def main() -> int:
    p = argparse.ArgumentParser(description="验证 tg-attest 决策披露包")
    p.add_argument("bundle", help="披露包 JSON 文件")
    p.add_argument("--ca", help="信任根 PEM（须自行独立获得）")
    p.add_argument("--json", action="store_true", help="以 JSON 输出结果")
    p.add_argument("--eutl", metavar="SNAPSHOT",
                   help="EUTL 快照路径。给了就独立复算包内的 eIDAS 合格状态声明，"
                        "而不是照抄它。快照须由你自己构建："
                        "python -m tg_attest.eutl_build")
    args = p.parse_args()

    bundle = json.load(open(args.bundle, encoding="utf-8"))
    ca = open(args.ca, "rb").read() if args.ca else None
    r = verify_bundle(bundle, ca)
    if args.eutl:
        _recheck_qualified(bundle, args.eutl, r)

    if args.json:
        # missing 必须出现在输出里。它是「必需检查没跑到」的那一类失败，
        # 和「跑了但没通过」是两回事，排查方向也不同。
        print(json.dumps({"ok": r.ok, "checks": r.checks, "missing": r.missing,
                          "gen_time": r.gen_time, "tsa": r.tsa_subject,
                          "errors": r.errors, "attestations": r.attestations},
                         ensure_ascii=False, indent=2))
    else:
        rec = bundle["record"]
        print(f"决策 seq={rec['seq']}  决策时间 {rec['decided_at']}")
        print(f"  执行者 {rec['actor'].get('id')}  模型 {rec['model'].get('id')}")
        print(f"  证据 {len(rec['evidence'])} 条，闸门 {len(rec['gates'])} 道")
        print(r)
        if r.ok:
            print(f"\n结论：该记录在 {r.gen_time} 之前即以此形态存在。")
            print(f"      时间由 {r.tsa_subject} 签署。")
    return 0 if r.ok else 1


if __name__ == "__main__":
    sys.exit(main())
