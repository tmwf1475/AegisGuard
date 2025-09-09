from typing import List, Optional, Union, Dict
from datetime import datetime
from pydantic import BaseModel, Field

# === Embedded Models ===
class CPUInfo(BaseModel):
    model_name: Optional[str] = None
    cores: Optional[int] = None
    threads: Optional[int] = None
    architecture: Optional[str] = None

class MemoryInfo(BaseModel):
    total: Optional[int] = None
    available: Optional[int] = None
    used: Optional[int] = None
    percent: Optional[float] = None

class DiskPartition(BaseModel):
    device: str
    mountpoint: str
    fstype: Optional[str] = None
    total: Optional[int] = None
    used: Optional[int] = None
    free: Optional[int] = None
    percent: Optional[float] = None

class NetworkInterface(BaseModel):
    name: str
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    is_up: Optional[bool] = None

class InstalledPackage(BaseModel):
    name: str
    version: Optional[str] = None
    source: Optional[str] = None

class RunningService(BaseModel):
    pid: int
    name: str
    status: Optional[str] = None
    path: Optional[str] = None

# === MCP System Summary Context ===
class MCPSystemContext(BaseModel):
    mcp_type: str = Field(default="SystemContext")
    hostname: str = Field(default="metasploitable3-ubuntu")
    os_version: str = Field(default="Ubuntu 14.04")
    kernel_version: Optional[str] = None
    architecture: Optional[str] = None
    open_ports: List[Union[int, str]] = []
    running_processes: List[str] = []
    running_services: List[RunningService] = []
    installed_packages: List[InstalledPackage] = []
    firewall_status: Optional[str] = None
    disk_partitions: Optional[List[DiskPartition]] = []
    network_interfaces: Optional[List[NetworkInterface]] = []
    users: Optional[List[str]] = []
    timestamp: Optional[str] = Field(default_factory=lambda: datetime.utcnow().isoformat())
    tags: Optional[List[str]] = []
    source: Optional[str] = "autoagent"
    uptime: Optional[str] = None
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    disk_usage: Optional[str] = None
    java_version: Optional[str] = None
    python_packages: Optional[str] = None
    docker_images: Optional[List[str]] = []
    mitre_matches: Optional[List[dict]] = []
    cpu_info: Optional[CPUInfo] = None
    memory_info: Optional[MemoryInfo] = None
    system_logs: Optional[str] = None
    sudoers: Optional[List[str]] = []
    crontab: Optional[List[str]] = []
    startup_services: Optional[List[str]] = []
    kernel_security: Optional[List[str]] = []
    kernel_upgrades: Optional[List[str]] = []
    cve_patches: Optional[str] = None
    logs: Optional[str] = None

# === Detected Vulnerability ===
class DetectedVulnerability(BaseModel):
    mcp_type: str = Field(default="DetectedVulnerability")
    description: str
    cve_reference: Optional[str] = None
    risk_level_code: Optional[str] = None  # L0~L4
    risk_level: Optional[str] = None       # Info ~ Critical
    cvss_score: Optional[Union[str, float]] = None
    cvss_vector: Optional[str] = None
    exploitability: Optional[str] = None
    reference_links: Optional[List[str]] = []
    classified_time: Optional[str] = Field(default_factory=lambda: datetime.utcnow().isoformat())
    repair_suggestion: Optional[str] = None
    source: Optional[str] = "LLM"


# === Vulnerability Detection Report ===
class VulnerabilityDetection(BaseModel):
    mcp_type: str = Field(default="VulnerabilityDetection")
    generated_time: str
    target_system: Dict[str, str]
    vulnerability_findings: List[str]

class VulnerabilityRiskClassification(BaseModel):
    mcp_type: str = Field(default="VulnerabilityRiskClassification")
    source: str
    generated_time: str
    target_system: Dict[str, str]
    vulnerability_risks: List[DetectedVulnerability]
    summary_statistics: Optional[Dict[str, int]] = None  # e.g., {"L4": 12, "L3": 25, ...}
    classification_strategy: Optional[str] = None        # e.g., "LLM+RuleBased-RiskNormalization-v2"

