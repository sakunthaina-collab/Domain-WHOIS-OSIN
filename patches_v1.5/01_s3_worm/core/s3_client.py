# core/s3_client.py
"""Thin S3 wrapper — easy to mock in tests, hide boto3 details.

Design:
  • One class, few methods, explicit error types
  • Checksum verification via HeadObject (ETag) + GetObject (sha256)
  • Object Lock aware (COMPLIANCE / GOVERNANCE)
"""
from __future__ import annotations
import base64
import hashlib
import io
import pathlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional


class S3Error(RuntimeError):
    pass


@dataclass
class PutResult:
    bucket: str
    key: str
    version_id: str
    etag: str
    sha256: str
    retention_mode: str
    retain_until: str


class S3Client:
    """Wraps boto3.client('s3'). Pass `client=` for tests (moto)."""

    def __init__(self, client=None, region: str = "us-east-1"):
        if client is None:
            import boto3
            client = boto3.client("s3", region_name=region)
        self.client = client

    # ── bucket setup (used in tests / one-time admin) ──
    def ensure_worm_bucket(self, bucket: str) -> None:
        """Create bucket with Object Lock enabled (idempotent)."""
        try:
            self.client.create_bucket(
                Bucket=bucket,
                ObjectLockEnabledForBucket=True,
            )
        except getattr(getattr(self.client, "exceptions", None), "BucketAlreadyOwnedByYou", Exception):
            pass
        except Exception:
            pass

        # default retention (can be overridden per object)
        try:
            self.client.put_object_lock_configuration(
                Bucket=bucket,
                ObjectLockConfiguration={
                    "ObjectLockEnabled": "Enabled",
                    "Rule": {"DefaultRetention": {
                        "Mode": "COMPLIANCE", "Days": 365}},
                },
            )
        except Exception:
            pass

    # ── put with retention ─────────────────────────────
    def put_worm(
        self,
        bucket: str,
        key: str,
        body: bytes,
        mode: str = "COMPLIANCE",
        days: int = 2555,
        content_type: str = "application/json",
    ) -> PutResult:
        if mode not in ("COMPLIANCE", "GOVERNANCE"):
            raise S3Error(f"invalid retention mode: {mode!r}")
        if days < 1:
            raise S3Error(f"retention days must be >= 1, got {days}")
        retain_until = (
            datetime.now(timezone.utc) + timedelta(days=days)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        sha = hashlib.sha256(body).hexdigest()

        try:
            resp = self.client.put_object(
                Bucket=bucket,
                Key=key,
                Body=io.BytesIO(body),
                ContentType=content_type,
                ContentMD5=_b64_md5(body),
                ChecksumSHA256=_b64_sha256(body),
                ObjectLockMode=mode,
                ObjectLockRetainUntilDate=retain_until,
            )
        except Exception as e:
            raise S3Error(f"put_object failed: {e}") from e

        return PutResult(
            bucket=bucket,
            key=key,
            version_id=resp.get("VersionId", ""),
            etag=resp.get("ETag", "").strip('"'),
            sha256=sha,
            retention_mode=mode,
            retain_until=retain_until,
        )

    # ── verify checksum + retention ────────────────────
    def verify_checksum(
        self, bucket: str, key: str, expected_sha256: str
    ) -> tuple[bool, str]:
        try:
            obj = self.client.get_object(Bucket=bucket, Key=key)
            body = obj["Body"].read()
        except Exception as e:
            return False, f"get_object failed: {e}"
        got = hashlib.sha256(body).hexdigest()
        if got != expected_sha256:
            return False, f"sha256 mismatch: want {expected_sha256}, got {got}"
        return True, "ok"

    def verify_retention(self, bucket: str, key: str) -> tuple[bool, str]:
        try:
            r = self.client.get_object_retention(Bucket=bucket, Key=key)
        except Exception as e:
            return False, f"get_object_retention failed: {e}"
        mode = r.get("Retention", {}).get("Mode")
        until = r.get("Retention", {}).get("RetainUntilDate")
        if not mode or not until:
            return False, "no retention set"
        return True, f"{mode} until {until.isoformat()}"

    # ── list locked objects (for auditor) ──────────────
    def list_locked_objects(self, bucket: str, prefix: str = "") -> list[dict]:
        out = []
        paginator = self.client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                out.append({
                    "key": obj["Key"],
                    "size": obj["Size"],
                    "last_modified": obj["LastModified"],
                })
        return out


def _b64_sha256(data: bytes) -> str:
    """S3 ChecksumSHA256 expects base64-encoded SHA256."""
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


def _b64_md5(data: bytes) -> str:
    """S3 ContentMD5 expects base64-encoded MD5."""
    return base64.b64encode(hashlib.md5(data).digest()).decode()
