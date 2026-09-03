from abc import ABC, abstractmethod
from ..schema import Finding

class BaseDetector(ABC):
    @abstractmethod
    def analyze_query(self, query: str) -> list[Finding]:
        ...

    @abstractmethod
    def analyze_chunk(self, chunk: str, chunk_id: str = "") -> list[Finding]:
        ...