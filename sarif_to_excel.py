# -*- coding: utf-8 -*-
import json, pandas as pd, argparse

def load_rows(sarif):
    rows = []
    for run in sarif.get("runs", []):
        rules = { r.get("id"): r for r in run.get("tool",{}).get("driver",{}).get("rules", []) }
        for res in run.get("results", []):
            rid   = res.get("ruleId")
            lvl   = res.get("level")
            msg   = (res.get("message") or {}).get("text")
            loc   = (res.get("locations") or [{}])[0]
            phy   = (loc.get("physicalLocation") or {})
            file  = (phy.get("artifactLocation") or {}).get("uri")
            region= (phy.get("region") or {})
            line  = region.get("startLine")

            # 규칙 메타에서 CWE 태그 추출(있을 때)
            rule_meta = rules.get(rid, {}) or {}
            tags = (rule_meta.get("properties") or {}).get("tags", []) or []
            cwe = next((t for t in tags if isinstance(t,str) and t.upper().startswith("CWE-")), None)

            rows.append({"ruleId": rid, "cwe": cwe, "level": lvl,
                         "file": file, "line": line, "message": msg})
    return rows

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sarif", required=True, help="results.sarif 경로")
    ap.add_argument("--out", default="snyk_summary.xlsx", help="출력 엑셀 파일명")
    args = ap.parse_args()

    with open(args.sarif, encoding="utf-8") as f:
        sarif = json.load(f)

    rows = load_rows(sarif)
    if not rows:
        raise SystemExit("SARIF results 가 비었습니다.")

    df = pd.DataFrame(rows)
    by_level = df.groupby("level").size().reset_index(name="count").sort_values("count", ascending=False)
    by_rule  = df.groupby("ruleId").size().reset_index(name="count").sort_values("count", ascending=False)
    by_file  = df.groupby("file").size().reset_index(name="count").sort_values("count", ascending=False)
    by_cwe   = df.groupby("cwe").size().reset_index(name="count").sort_values("count", ascending=False)

    with pd.ExcelWriter(args.out) as xw:
        df.to_excel(xw, "all_results", index=False)
        by_level.to_excel(xw, "by_level", index=False)
        by_rule.to_excel(xw, "by_rule", index=False)
        by_file.to_excel(xw, "by_file", index=False)
        by_cwe.to_excel(xw, "by_cwe", index=False)

    print(f"saved: {args.out}")

if __name__ == "__main__":
    main()