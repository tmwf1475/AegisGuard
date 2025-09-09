from fastapi import APIRouter, Request, HTTPException
from server.database import context_collection
from pydantic import BaseModel, ValidationError
from typing import List, Optional
import gzip
import json

router = APIRouter()

class Service(BaseModel):
    pid: int
    name: str

class MITREMatch(BaseModel):
    match: str
    technique_id: str

class SnapshotSchema(BaseModel):
    timestamp: str
    hostname: str
    ip: str
    os: str
    kernel: str
    arch: str
    user: str

    # Optional fields with defaults
    uptime: Optional[str] = ""
    cpu_usage: Optional[float] = 0.0
    memory_usage: Optional[float] = 0.0
    disk_usage: Optional[str] = ""
    services: Optional[List[Service]] = []
    startup_services: Optional[List[str]] = []
    network_connections: Optional[List[str]] = []
    logs: Optional[str] = ""
    lynis_report: Optional[str] = "Not Included"
    chkrootkit_report: Optional[str] = "Not Included"
    rkhunter_report: Optional[str] = "Not Included"
    firewall_status: Optional[str] = ""
    disk_partitions: Optional[List[str]] = []
    installed_hotfixes: Optional[List[str]] = []
    cve_patches: Optional[str] = ""
    kernel_security: Optional[List[str]] = []
    kernel_upgrades: Optional[List[str]] = []
    installed_software: Optional[List[str]] = []
    java_version: Optional[str] = ""
    python_packages: Optional[str] = ""
    docker_images: Optional[List[str]] = []
    system_logs: Optional[str] = ""
    users: Optional[List[str]] = []
    linpeas: Optional[str] = ""
    mitre_matches: Optional[List[MITREMatch]] = []

@router.post("/monitor/snapshot")
async def receive_snapshot(request: Request):
    try:
        encoding = request.headers.get("Content-Encoding", "").lower()
        raw_body = await request.body()
        print(f"[DEBUG] Raw body length: {len(raw_body)} bytes")

        if "gzip" in encoding:
            print(f"[DEBUG] Starts with gzip magic? {raw_body[:2] == b'\x1f\x8b'}")
            try:
                decompressed = gzip.decompress(raw_body)
                print(f"[DEBUG] Decompressed length: {len(decompressed)} bytes")
                print(f"[DEBUG] Decompressed preview: {decompressed[:300]}")
                if not decompressed.strip().startswith(b"{"):
                    print(" Decompressed content does not start with '{'. Might be malformed.")
                context_dict = json.loads(decompressed.decode("utf-8"))
            except (OSError, gzip.BadGzipFile) as gzip_error:
                print(" Gzip decompression failed:", gzip_error)
                raise HTTPException(status_code=400, detail="Invalid gzip format")
            except json.JSONDecodeError as json_error:
                print(" JSON decode failed:", json_error)
                raise HTTPException(status_code=400, detail="Malformed JSON after gzip decompression")
        else:
            try:
                context_dict = json.loads(raw_body.decode("utf-8"))
            except Exception as json_error:
                print(" JSON parse failed:", json_error)
                print(f"[DEBUG] Raw (non-gzip) preview: {raw_body[:300]}")
                raise HTTPException(status_code=400, detail="Malformed JSON")

        try:
            context = SnapshotSchema(**context_dict)
        except ValidationError as val_error:
            print(" Schema validation failed:", val_error)
            raise HTTPException(status_code=422, detail="Schema validation error")

        print(f"[✓] Received snapshot from: {context.hostname or context.ip}")
        context_collection.insert_one(context.dict())
        print("✓ Stored in MongoDB")

        return {
            "msg": " Context received",
            "hostname": context.hostname or context.ip
        }

    except Exception as e:
        print(" Unexpected failure during request parsing")
        print(f"[DEBUG] Raw body preview: {raw_body[:300]}")
        print(" Exception:", e)
        raise HTTPException(status_code=400, detail="Invalid or malformed request body")
