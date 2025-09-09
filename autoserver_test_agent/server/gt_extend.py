import json
import re
import requests
import time

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cve/1.0/"

# 輸入：模型輸出路徑（含預測中提到的 CVE） & 現有 Ground Truth 檔案
PREDICTION_FILE = "vulnerability_list.json"
GROUNDTRUTH_FILE = "vulnerability_groundtruth_300.json"
OUTPUT_FILE = "vulnerability_groundtruth_extended.json"

def extract_cves_from_predictions(prediction_path):
    with open(prediction_path, "r", encoding="utf-8") as f:
        preds = json.load(f)
    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    cves = set()
    for item in preds["vulnerability_findings"]:
        matches = re.findall(cve_pattern, item)
        cves.update(matches)
    return sorted(list(cves))

def load_existing_gt(gt_path):
    with open(gt_path, "r", encoding="utf-8") as f:
        gt = json.load(f)
    return {entry["cve"]: entry for entry in gt if "cve" in entry}

def query_cve_info(cve_id):
    try:
        response = requests.get(NVD_API_URL + cve_id)
        if response.status_code == 200:
            data = response.json()
            desc = data["result"]["CVE_Items"][0]["cve"]["description"]["description_data"][0]["value"]
            return desc
        else:
            print(f"Failed to fetch {cve_id}: HTTP {response.status_code}")
            return None
    except Exception as e:
        print(f"Error querying {cve_id}: {e}")
        return None

def extend_groundtruth(pred_cves, existing_gt):
    new_entries = []
    for cve in pred_cves:
        if cve in existing_gt:
            continue
        print(f"Fetching info for {cve}...")
        description = query_cve_info(cve)
        if description:
            new_entries.append({
                "name": description[:80] + "...",
                "cve": cve,
                "type": "Unknown",
                "source": "Extended GT"
            })
        time.sleep(1.2)  # 避免過快造成 API rate limit
    return new_entries

def save_combined_gt(existing_gt_dict, new_entries, output_path):
    combined = list(existing_gt_dict.values()) + new_entries
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2)
    print(f"✅ Extended Ground Truth saved to: {output_path}")

if __name__ == "__main__":
    pred_cves = extract_cves_from_predictions(PREDICTION_FILE)
    print(f"🔍 Extracted {len(pred_cves)} CVE(s) from model predictions.")
    
    gt_dict = load_existing_gt(GROUNDTRUTH_FILE)
    new_gt = extend_groundtruth(pred_cves, gt_dict)
    print(f"➕ Added {len(new_gt)} new CVEs to Ground Truth.")

    save_combined_gt(gt_dict, new_gt, OUTPUT_FILE)
