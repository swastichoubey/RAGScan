from .schema import Finding, ScanReport

class FindingAggregator:
    def __init__(self):
        self._findings: list[Finding] = []

    def add(self, findings: list[Finding]) -> None:
        self._findings.extend(findings)

    def build_report(
            self,
            target: str | None = None,
            vectordb_name: str | None = None,
            vectordb_version: str | None = None,
            engine_version: str | None = None,
    ) -> ScanReport:
        return ScanReport(
            target=target,
            findings=self._findings,
            vectordb_name=vectordb_name,
            vectordb_version=vectordb_version,
            engine_version=engine_version,
        )