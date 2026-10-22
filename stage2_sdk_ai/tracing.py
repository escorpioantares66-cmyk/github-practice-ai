from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field


@dataclass
class Span:
    name: str
    start: float = field(default_factory=time.time)
    end: float = 0
    status: str = "ok"
    meta: dict = field(default_factory=dict)

    def finish(self):
        self.end = time.time()

    @property
    def duration_ms(self) -> float:
        return (self.end - self.start) * 1000 if self.end else 0

class Tracer:
    def __init__(self):
        self.spans: list[Span] = []

    @contextmanager
    def span(self, name: str, **meta):
        s = Span(name=name, meta=meta)
        self.spans.append(s)
        try:
            yield s
            s.status = "ok"
        except Exception as e:
            s.status = f"error:{e}"
            raise
        finally:
            s.finish()

    def summary(self) -> str:
        return " | ".join([f"{s.name}:{s.duration_ms:.1f}ms:{s.status}" for s in self.spans])

    def clear(self):
        self.spans.clear()
