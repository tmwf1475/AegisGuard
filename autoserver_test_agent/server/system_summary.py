import json
from pymongo import MongoClient
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any
from pydantic import ValidationError
from mcp_schema_models import MCPSystemContext, CPUInfo, MemoryInfo, DiskPartition, NetworkInterface, InstalledPackage, RunningService

MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "mcp"
COLLECTION_NAME = "context_packages"

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
collection = db[COLLECTION_NAME]

raw_documents = list(collection.find())
system_contexts = []

for doc in raw_documents:
    try:
        summary_dict: Dict[str, Any] = {
            "os_info": {
                "name": doc.get("os", doc.get("os_version", "")),
                "platform": doc.get("os_version", ""),
                "version": doc.get("kernel", doc.get("kernel_version", ""))
            },
            "cpu": {
                "architecture": doc.get("arch"),
                "model_name": doc.get("cpu_model"),
                "cores": doc.get("cpu_cores"),
                "threads": doc.get("cpu_threads")
            },
            "memory": {
                "total": doc.get("memory_total"),
                "available": doc.get("memory_available"),
                "used": doc.get("memory_used"),
                "percent": doc.get("memory_percent")
            },
            "disk": [
                DiskPartition(**dp) if isinstance(dp, dict) else dp
                for dp in doc.get("disk_partitions", doc.get("disk_info", []))
            ],
            "network": [
                NetworkInterface(**ni) if isinstance(ni, dict) else ni
                for ni in doc.get("network", {}).get("interfaces", [])
            ],
            "installed_packages": [
                InstalledPackage(**pkg) if isinstance(pkg, dict) else InstalledPackage(name=pkg)
                for pkg in doc.get("installed_packages", doc.get("installed_software", []))
            ],
            "running_services": [
                RunningService(**svc) if isinstance(svc, dict) else RunningService(pid=0, name=svc)
                for svc in doc.get("services", doc.get("running_services", []))
            ],
            "other": {
                k: v for k, v in doc.items() if k not in [
                    "os", "kernel", "kernel_version", "arch",
                    "installed_packages", "installed_software",
                    "services", "running_services",
                    "disk_partitions", "disk_info",
                    "network", "memory",
                    "cpu_model", "cpu_cores", "cpu_threads",
                    "memory_total", "memory_available", "memory_used", "memory_percent"
                ]
            }
        }

        summary = MCPSystemContext(**summary_dict)
        system_contexts.append(summary)
    except ValidationError as e:
        print(f"[!] Validation error for document _id={doc.get('_id')}: {e}")
    except Exception as e:
        print(f"[!] Failed to normalize document with _id {doc.get('_id')}: {e}")

# 儲存為 MCP 格式 JSON
output_path = "/home/st335/CTIAgent/advagent/outputs/system_summary.json"
Path(output_path).parent.mkdir(parents=True, exist_ok=True)
with open(output_path, "w", encoding="utf-8") as f:
    json.dump([ctx.model_dump() for ctx in system_contexts], f, indent=2, ensure_ascii=False)

print(f"Successfully output {len(system_contexts)} system summaries to {output_path}")
