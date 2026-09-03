import re
from uuid import uuid4
from ..schema import Finding, VulnClass, Severity
from .base import BaseDetector

class PIILeakageDetector(BaseDetector):
    """
    STUB: regex pattern-match for obvious PII (email, phone number).
    To be replaced by a fine-tuned spacy NER model
    """
    EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    PHONE_PATTERN = re.compile(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b") 

    def analyze_query(self, query: str) -> list[Finding]:
        return self._scan_text(query, location=None)

    def analyze_chunk(self, chunk: str, chunk_id: str = "") -> list[Finding]:
        return self._scan_text(chunk, location=chunk_id)

    def _scan_text(self, text: str, location: str | None) -> list[Finding]:
        findings = []
        for match in self.EMAIL_PATTERN.finditer(text):
            findings.append(
                Finding(
                    id=str(uuid4()),
                    vuln_class=VulnClass.PII_LEAKAGE,
                    severity=Severity.CRITICAL,
                    description=f"Detected email address: '{match.group()}",
                    location=location,
                )
            )
        for match in self.PHONE_PATTERN.finditer(text):
            findings.append(
                Finding(
                    id=str(uuid4()),
                    vuln_class=VulnClass.PII_LEAKAGE,
                    severity=Severity.MEDIUM,
                    description=f"Detected phone number: '{match.group()}",
                    location=location,
                )
            )

        return findings
