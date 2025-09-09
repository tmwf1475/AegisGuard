from sentence_transformers import SentenceTransformer, util
import json

def load_data(prediction_path, groundtruth_path):
    with open(prediction_path, "r", encoding="utf-8") as f:
        predictions = json.load(f)["vulnerability_findings"]

    with open(groundtruth_path, "r", encoding="utf-8") as f:
        groundtruth = json.load(f)

    gt_cves = {entry["cve"] for entry in groundtruth if "cve" in entry}
    gt_names = [entry["name"] for entry in groundtruth if "name" in entry]

    return predictions, gt_cves, gt_names

def evaluate(predictions, gt_cves, gt_names, similarity_threshold=0.8):
    model = SentenceTransformer('all-MiniLM-L6-v2')

    pred_clean = [p for p in predictions if "CVE" in p]
    pred_embeddings = model.encode(pred_clean, convert_to_tensor=True)
    gt_embeddings = model.encode(gt_names, convert_to_tensor=True)

    tp_exact = [p for p in pred_clean if any(cve in p for cve in gt_cves)]
    semantic_tp = []

    for i, emb in enumerate(pred_embeddings):
        if pred_clean[i] in tp_exact:
            continue
        score = util.pytorch_cos_sim(emb, gt_embeddings)[0]
        if score.max().item() > similarity_threshold:
            semantic_tp.append(pred_clean[i])

    fp = [p for p in pred_clean if p not in tp_exact and p not in semantic_tp]
    fn = [cve for cve in gt_cves if not any(cve in p for p in pred_clean)]

    tp_total = len(tp_exact) + len(semantic_tp)
    precision = tp_total / (tp_total + len(fp)) if (tp_total + len(fp)) > 0 else 0
    recall = tp_total / (tp_total + len(fn)) if (tp_total + len(fn)) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print("=== 評分指標 ===")
    print(f"Exact Match TP: {len(tp_exact)}")
    print(f"Semantic Match TP: {len(semantic_tp)}")
    print(f"False Positives: {len(fp)}")
    print(f"False Negatives: {len(fn)}")
    print(f"Precision: {precision:.3f}")
    print(f"Recall: {recall:.3f}")
    print(f"F1 Score: {f1:.3f}")

if __name__ == "__main__":
    preds, gt_cves, gt_names = load_data("vulnerability_list.json", "vulnerability_groundtruth_300.json")
    evaluate(preds, gt_cves, gt_names)
