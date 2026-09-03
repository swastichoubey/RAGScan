from .schema import Finding, ScanReport
from .aggregator import FindingAggregator
from .detectors.prompt_injection import PromptInjectionDetector
from .detectors.pii_leakage import PIILeakageDetector

class Scanner:
    def __init__(self, config_path: str | None = None): #reserved for future config support
        self._detectors = [
            PromptInjectionDetector(),
            PIILeakageDetector(),
        ]
        self._aggregator = FindingAggregator()

    def scan_query(self, query: str) -> list[Finding]:
        findings: list[Finding] = []
        for detector in self._detectors:
            findings.extend(detector.analyze_query(query))
        self._aggregator.add(findings)
        return findings

    def scan_chunk(self, chunk: str, chunk_id: str = "") -> list[Finding]:
        findings: list[Finding] = []
        for detector in self._detectors:
            findings.extend(detector.analyze_chunk(chunk, chunk_id))
        self._aggregator.add(findings)
        return findings

    def build_report(
            self,
            target: str | None = None,
            vectordb_name: str | None = None,
            vectordb_version: str | None = None,
            engine_version: str | None = None,
    ) -> ScanReport:
        return self._aggregator.build_report(
            target=target,
            vectordb_name=vectordb_name,
            vectordb_version=vectordb_version,
            engine_version=engine_version,
        )