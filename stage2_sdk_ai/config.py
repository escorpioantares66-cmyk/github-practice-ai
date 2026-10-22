import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class AIConfig:
    api_key: str = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
    model: str = "gpt-4o-mini"
    timeout: float = 30.0
    max_retries: int = 3
    concurrency: int = 3
    max_cost_per_day: float = 5.0
    cache_ttl_seconds: int = 3600

    def __post_init__(self):
        if not self.api_key and os.getenv("CI") != "true":
            raise ValueError("OPENAI_API_KEY missing - set env, never hardcode")
        if self.max_cost_per_day <= 0:
            raise ValueError("max_cost_per_day must be >0")

    def masked_key(self) -> str:
        if len(self.api_key) < 8:
            return "***"
        return f"{self.api_key[:4]}...{self.api_key[-4:]}"
