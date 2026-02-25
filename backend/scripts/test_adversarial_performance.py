#!/usr/bin/env python3
"""
Adversarial suite performance test with per-attack recall tracking.
"""

import os, sys, io

os.environ.setdefault("PYTHONIOENCODING", "utf-8")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import logging; logging.disable(logging.CRITICAL)
import warnings; warnings.filterwarnings("ignore")

from app.testing.adversarial_generator import AdversarialGenerator
from app.testing.evaluator import NodeEvaluator, ConfusionMatrix, EvaluationRecord

OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "perf_results.txt")

# Minimum recall thresholds per attack type
ATTACK_RECALL_TARGETS = {
    "homoglyph_url": 0.95,
    "homoglyph_sender": 0.95,
    "base64_payload": 0.95,
    "domain_age_spoof": 0.97,
    "legit_with_malicious_link": 1.00,
}

def main():
    out = io.StringIO()
    def p(msg=""): print(msg); out.write(msg + "\n")

    p("=" * 60)
    p("  PhishNet Adversarial Suite — Performance Test")
    p("=" * 60)

    gen = AdversarialGenerator()
    samples = gen.generate_full_adversarial_suite(count_per_type=3)
    p(f"\n[1] Generated {len(samples)} adversarial samples")

    attack_types = {}
    for s in samples:
        at = s.metadata.get("attack_type", "unknown") if s.metadata else "unknown"
        attack_types[at] = attack_types.get(at, 0) + 1
    p("\n    Attack Types:")
    for at, c in sorted(attack_types.items()):
        p(f"      {at:35s} x{c}")

    p(f"\n[2] Running through analyzer...")
    evaluator = NodeEvaluator()
    records = []
    errors = 0
    sample_attack_map = {}

    for sample in samples:
        at = sample.metadata.get("attack_type", "unknown") if sample.metadata else "unknown"
        try:
            ns = evaluator.analyze_sample(sample)
            gt = sample.ground_truth
            pred = ns.predicted_verdict
            correct = (
                (pred in ("PHISHING", "SUSPICIOUS") and gt in ("PHISHING", "SUSPICIOUS"))
                or (pred == "SAFE" and gt == "SAFE")
            )
            rec = EvaluationRecord(
                sample_id=sample.id, ground_truth=gt,
                category=sample.category or "", difficulty=sample.difficulty or "",
                node_scores=ns, correct=correct,
            )
            records.append(rec)
            sample_attack_map[sample.id] = at
        except Exception as e:
            errors += 1
            p(f"    [ERR] {sample.id}: {e}")

    p(f"    Analyzed {len(records)}, errors {errors}")

    # Confusion matrix
    cm = ConfusionMatrix()
    for rec in records:
        gt_ph = rec.ground_truth in ("PHISHING", "SUSPICIOUS")
        pred_ph = rec.node_scores.predicted_verdict in ("PHISHING", "SUSPICIOUS")
        if gt_ph and pred_ph: cm.tp += 1
        elif gt_ph and not pred_ph: cm.fn += 1
        elif not gt_ph and pred_ph: cm.fp += 1
        else: cm.tn += 1

    p(f"\n[3] Confusion Matrix:")
    p(f"    TP={cm.tp}  FN={cm.fn}  FP={cm.fp}  TN={cm.tn}")
    p(f"    Precision : {cm.precision:.4f}")
    p(f"    Recall    : {cm.recall:.4f}")
    p(f"    F1 Score  : {cm.f1_score:.4f}")
    p(f"    FPR       : {cm.false_positive_rate:.4f}")
    p(f"    FNR       : {cm.false_negative_rate:.4f}")
    p(f"    Accuracy  : {cm.accuracy:.4f}")

    # Node accuracy
    p(f"\n[4] Node-Level Accuracy:")
    node_acc = evaluator.evaluate_node_accuracy(records)
    for node, acc in node_acc.items():
        p(f"    {node:15s} {acc:.1f}%")

    # Per-attack recall
    p(f"\n[5] Per-Attack Recall:")
    attack_stats = {}
    for rec in records:
        at = sample_attack_map.get(rec.sample_id, "unknown")
        if at not in attack_stats:
            attack_stats[at] = {"tp": 0, "fn": 0, "total": 0}
        gt_ph = rec.ground_truth in ("PHISHING", "SUSPICIOUS")
        pred_ph = rec.node_scores.predicted_verdict in ("PHISHING", "SUSPICIOUS")
        if gt_ph:
            attack_stats[at]["total"] += 1
            if pred_ph:
                attack_stats[at]["tp"] += 1
            else:
                attack_stats[at]["fn"] += 1

    all_pass = True
    for at in sorted(attack_stats.keys()):
        s = attack_stats[at]
        recall = s["tp"] / s["total"] if s["total"] > 0 else 0
        target = ATTACK_RECALL_TARGETS.get(at, 0.90)
        status = "PASS" if recall >= target else "FAIL"
        if status == "FAIL": all_pass = False
        p(f"    {at:35s} {recall:.2f} (target>={target:.2f}) [{status}]")

    # Sample details
    p(f"\n[6] Sample Details (misses only):")
    for rec in records:
        if not rec.correct:
            ns = rec.node_scores
            at = sample_attack_map.get(rec.sample_id, "?")
            p(f"    [MISS] {rec.sample_id[:26]:26s} "
              f"GT={rec.ground_truth:10s} P={ns.predicted_verdict:10s} "
              f"S={ns.sender_score:3d} C={ns.content_score:3d} "
              f"L={ns.link_score:3d} A={ns.auth_score:3d} "
              f"At={ns.attachment_score:3d} T={ns.weighted_total:3d} "
              f"({at})")

    p(f"\n{'='*60}")
    p(f"  OVERALL: FNR={cm.false_negative_rate:.4f} "
      f"{'PASS' if cm.false_negative_rate < 0.07 else 'FAIL'} (target <0.07)")
    p(f"  RECALL : {cm.recall:.4f} "
      f"{'PASS' if cm.recall > 0.93 else 'FAIL'} (target >0.93)")
    p(f"  PER-ATK: {'ALL PASS' if all_pass else 'SOME FAIL'}")
    p(f"{'='*60}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(out.getvalue())
    print(f"\nResults saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
