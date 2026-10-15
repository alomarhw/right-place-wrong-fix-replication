"""e4_human_agreement.py — agreement of the blind author audit with the two LLM raters (no model calls).

Reads the author's labels (a CSV with case,cve_id,label,note; default results/e4_human_audit_labels.csv),
the hidden key (results/e4_human_audit_key.json: arm, repeat and both raters' labels per case) and the
oracle VPR / touch-but-rejected share per arm (results/e4_allrepeats.json). Reports raw agreement and
Cohen's kappa per rater on the four labels, on acceptable (equivalent or plausible) vs. not, and on
equivalent vs. not, plus per-arm VPR adjusted by the author's labels.

Usage: python e4_human_agreement.py [labels.csv]   -> results/e4_human_audit_agreement.json
"""
import csv
import json
import sys
from pathlib import Path

from e4_judge import LABELS, kappa

RATERS = ("claude-opus-5-5", "claude-opus-4-8")


def main():
    labels_csv = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("results/e4_human_audit_labels.csv")
    human = {r["case"]: r["label"].strip() for r in csv.DictReader(open(labels_csv))}
    key = json.loads(Path("results/e4_human_audit_key.json").read_text())
    arms = json.loads(Path("results/e4_allrepeats.json").read_text())["arms"]
    assert all(human.get(k["case"]) in LABELS for k in key), "every case needs one of " + ", ".join(LABELS)
    h = [human[k["case"]] for k in key]
    acc = lambda xs: ["acceptable" if x in ("equivalent", "plausible") else "not" for x in xs]  # noqa: E731
    eqv = lambda xs: ["equivalent" if x == "equivalent" else "not" for x in xs]  # noqa: E731
    res = {"labels_file": labels_csv.name, "n": len(key), "human_counts": {c: h.count(c) for c in LABELS}, "vs": {},
           "by_arm": {}}
    for m in RATERS:
        r = [k["labels"][m] for k in key]
        res["vs"][m] = {"agree": sum(x == y for x, y in zip(h, r)) / len(h), "kappa4": kappa(h, r, LABELS),
                        "kappa_acc": kappa(acc(h), acc(r), ["acceptable", "not"]),
                        "kappa_eq": kappa(eqv(h), eqv(r), ["equivalent", "not"]),
                        "rater_counts": {c: r.count(c) for c in LABELS},
                        "disagreements": [{"case": k["case"], "author": x, "rater": y}
                                          for k, x, y in zip(key, h, r) if x != y]}
    for arm, a in arms.items():
        hs = [x for k, x in zip(key, h) if k["arm"] == arm]
        eq, ok = hs.count("equivalent"), sum(x in ("equivalent", "plausible") for x in hs)
        res["by_arm"][arm] = {"n": len(hs), "equivalent": eq, "acceptable": ok,
                              "vpr_with_equivalent": a["oracle_vpr"] + a["touch_rejected_share"] * eq / len(hs),
                              "vpr_with_acceptable": a["oracle_vpr"] + a["touch_rejected_share"] * ok / len(hs)}
    Path("results/e4_human_audit_agreement.json").write_text(json.dumps(res, indent=1))
    print(json.dumps({"counts": res["human_counts"],
                      "vs": {m: {k: round(v, 3) for k, v in d.items() if isinstance(v, float)} for m, d in res["vs"].items()},
                      "by_arm": res["by_arm"]}, indent=1))


if __name__ == "__main__":
    main()
