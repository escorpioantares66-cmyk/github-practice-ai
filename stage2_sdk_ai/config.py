from dataclasses import dataclass

@dataclass(frozen=True)
class AIConfig:
    api_key: str
    base_url: str = "https://api.openai.com/v1"

    @property
    def masked_key(self) -> str:
        k = self.api_key
        return f"{k[:7]}...{k[-4:]}" if len(k) > 11 else "***"
