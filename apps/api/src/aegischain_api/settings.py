"""Environment-based configuration. Secrets come from the environment, never from files in git."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


class ConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    api_key: str
    database_url: str = "sqlite:///./aegischain.db"
    policy_dir: Path = Path("configs/policies")
    osv_cache_dir: Path | None = None
    max_upload_bytes: int = 50 * 1024 * 1024
    cors_origins: tuple[str, ...] = ()
    offline: bool = False

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Settings:
        env = dict(os.environ) if env is None else env
        key = env.get("AEGISCHAIN_API_KEY", "")
        if len(key) < 16:
            raise ConfigurationError(
                "AEGISCHAIN_API_KEY must be set to a secret of at least 16 characters"
            )
        cache = env.get("AEGISCHAIN_OSV_CACHE_DIR")
        return cls(
            api_key=key,
            database_url=env.get("AEGISCHAIN_DATABASE_URL", cls.database_url),
            policy_dir=Path(env.get("AEGISCHAIN_POLICY_DIR", str(cls.policy_dir))),
            osv_cache_dir=Path(cache) if cache else None,
            max_upload_bytes=int(env.get("AEGISCHAIN_MAX_UPLOAD_BYTES", cls.max_upload_bytes)),
            cors_origins=tuple(o for o in env.get("AEGISCHAIN_CORS_ORIGINS", "").split(",") if o),
            offline=env.get("AEGISCHAIN_OFFLINE", "").lower() in ("1", "true", "yes"),
        )
