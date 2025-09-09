import json
import re
from sklearn.metrics import precision_score, recall_score, f1_score

def extract_predictions(prediction_file):
    with open(prediction_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    found = set()
    for entry in data["vulnerability_findings"]:
        matches = re.findall(cve_pattern, entry)
        found.update(matches)
    return sorted(found)

def extract_groundtruth(gt_file):
    with open(gt_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    return sorted({entry["cve"] for entry in data if "cve" in entry})

def evaluate(preds, gt_cves):
    y_true = [1 if cve in gt_cves else 0 for cve in preds]
    y_pred = [1] * len(preds)  # all are predicted positives
    tp = sum([1 for cve in preds if cve in gt_cves])
    fp = len(preds) - tp
    fn = len(gt_cves) - tp

    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = f1_score(y_true, y_pred, zero_division=0)

    return {
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "Precision": round(precision, 3),
        "Recall": round(recall, 3),
        "F1 Score": round(f1, 3)
    }

def print_results(label, scores):
    print(f"\n {label}")
    for k, v in scores.items():
        print(f"{k}: {v}")

if __name__ == "__main__":
    PRED_FILE = "vulnerability_list.json"
    CORE_GT_FILE = "vulnerability_groundtruth_300.json"
    EXTENDED_GT_FILE = "vulnerability_groundtruth_extended.json"

    predictions = extract_predictions(PRED_FILE)
    core_gt = extract_groundtruth(CORE_GT_FILE)
    extended_gt = extract_groundtruth(EXTENDED_GT_FILE)

    core_scores = evaluate(predictions, core_gt)
    extended_scores = evaluate(predictions, extended_gt)

    print_results("Core Ground Truth 評分", core_scores)
    print_results("Extended Ground Truth 評分", extended_scores)
