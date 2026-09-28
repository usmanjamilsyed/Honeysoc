"""Redis connection settings supplied by the runtime environment."""
import os
import redis


def create_client():
    url = os.environ.get("REDIS_URL")
    if not url:
        raise RuntimeError("Set REDIS_URL; use rediss:// for a TLS service.")
    return redis.Redis.from_url(url, socket_connect_timeout=10, socket_timeout=15)
