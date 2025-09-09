from pydantic import BaseModel
from typing import List, Dict

class Service(BaseModel):
    name: str
    port: int
    status: str

class SystemContext(BaseModel):
    hostname: str
    os: str
    cpu_usage: float
    memory_usage: float
    services: List[Service]
    logs: List[str]
