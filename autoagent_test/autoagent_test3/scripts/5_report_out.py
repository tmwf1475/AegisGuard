import json
from datetime import datetime

def load_report(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return json.load(file)

def parse_disk_partitions(disk_data):
    lines = disk_data.split('\n')
    return [line.strip() for line in lines if line.strip()]

def generate_readable_report(data):
    report = [f"系統安全報告 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "=============================="]
    
    # 硬碟分區資訊
    report.append("**硬碟分區狀態**:")
    partitions = parse_disk_partitions(data['system_info'].get('disk_partitions', '無資料'))
    report.extend(f"- {part}" for part in partitions)
    report.append("")
    
    # Docker 狀態
    docker_status = data['system_info'].get('docker_images', '無資料')
    report.append("**Docker 狀態:** " + ("未安裝或無法存取" if "Error" in docker_status else docker_status))
    report.append("")
    
    # 其他重要系統資訊
    essential_keys = ['os_version', 'kernel_version', 'cpu_info', 'memory_info']
    for key in essential_keys:
        if key in data['system_info']:
            report.append(f"**{key.replace('_', ' ').title()}**: {data['system_info'][key]}")
    
    report.append("==============================")
    report.append("**建議修復措施:**")
    report.extend([
        "1. **檢查並確保 systemctl 可正常運作**: 若無法使用，執行 `sudo apt-get install --reinstall systemd`。",
        "2. **檢查可疑的磁碟分區 (如 1K 大小的 sda2)**: 使用 `sudo fdisk -l` 查看並移除異常分區。",
        "3. **啟用防火牆**: 執行 `sudo ufw enable`，並適當設定規則。",
        "4. **確保 Docker 安裝正常**: 若需使用，執行 `sudo apt-get install docker.io` 來安裝。",
        "5. **保持系統更新**: 執行 `sudo apt-get update && sudo apt-get upgrade -y` 來確保安全性。"
    ])
    
    return '\n'.join(report)

def main():
    file_path = "/home/st335/CTIAgent/autoagent_test2/data/vulnerability_report.json"
    data = load_report(file_path)
    readable_report = generate_readable_report(data)
    
    output_file = "/home/st335/CTIAgent/autoagent_test2/data/vulnerability_report.txt"
    with open(output_file, 'w', encoding='utf-8') as file:
        file.write(readable_report)
    
    print(f"可讀性報告已生成: {output_file}")

if __name__ == "__main__":
    main()
