from enum import Enum
from datetime import datetime, timezone
from uuid import uuid4
from pydantic import BaseModel, Field
from typing import Optional

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class VulnClass(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    PII_LEAKAGE = "pii_leakage"

    @property
    def cwe_id(self) -> str:
        return {
            VulnClass.PROMPT_INJECTION: "CWE-1287",  
            VulnClass.PII_LEAKAGE: "CWE-359",      
        }[self]

class Finding(BaseModel):
    id: str
    vuln_class: VulnClass
    severity: Severity
    description: str
    location: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def cwe_id(self) -> str:
        return self.vuln_class.cwe_id

class ScanReport(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid4()))
    target: Optional[str] = None
    findings: list[Finding] = Field(default_factory=list)
    vectordb_name: Optional[str] = None
    vectordb_version: Optional[str] = None
    engine_version: Optional[str] = None
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))