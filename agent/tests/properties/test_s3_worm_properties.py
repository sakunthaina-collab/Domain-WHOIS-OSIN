"""Property tests for S3WormAdapter."""
from __future__ import annotations
import pytest
from hypothesis import given, settings, strategies as st, HealthCheck

settings.register_profile(
    "dev",
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile("dev")


def _patch_moto_for_retention():
    try:
        import moto.s3.responses as r
        from moto.s3.exceptions import AccessDeniedByLock
    except ImportError:
        return

    if getattr(r.S3Response, "_worm_patched", False):
        return

    orig_get = r.S3Response._key_response_get

    def _patched_get(self, query, key_name):
        if "retention" in query:
            version_id = self._get_param("versionId")
            key = self.backend.get_object(self.bucket_name, key_name, version_id=version_id)
            if not key or not getattr(key, "lock_mode", None):
                return 404, {}, "<Error><Code>NoSuchObjectLockConfiguration</Code><Message>The specified object does not have a ObjectLock configuration</Message></Error>"
            body = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                f'<Mode>{key.lock_mode}</Mode>'
                f'<RetainUntilDate>{key.lock_until}</RetainUntilDate>'
                '</Retention>'
            )
            return 200, {}, body
        return orig_get(self, query, key_name)

    r.S3Response._key_response_get = _patched_get

    orig_del = r.S3Response._key_response_delete

    def _patched_del(self, bucket_name, query, key_name):
        key = self.backend.get_object(bucket_name, key_name)
        if key and hasattr(key, "is_locked") and key.is_locked(governance_bypass=False):
            raise AccessDeniedByLock()
        return orig_del(self, bucket_name, query, key_name)

    r.S3Response._key_response_delete = _patched_del
    r.S3Response._worm_patched = True


@pytest.fixture(scope="module")
def s3_client():
    moto = pytest.importorskip("moto")
    _patch_moto_for_retention()
    try:
        from moto import mock_aws as mock_s3
    except ImportError:
        from moto import mock_s3

    with mock_s3():
        import boto3
        c = boto3.client("s3", region_name="us-east-1")
        c.create_bucket(Bucket="test-worm-bucket", ObjectLockEnabledForBucket=True)
        from core.s3_client import S3Client
        yield S3Client(client=c)


# ── P1: any valid retention_days works ─────────────────────
@given(days=st.integers(min_value=1, max_value=3650))
def test_any_positive_retention_days_works(s3_client, days):
    result = s3_client.put_worm(
        "test-worm-bucket", f"k/{days}.json", b"x",
        mode="COMPLIANCE", days=days)
    assert result.retain_until
    ok, msg = s3_client.verify_retention(
        "test-worm-bucket", f"k/{days}.json")
    assert ok, msg


# ── P2: any non-positive retention_days rejected ───────────
@given(days=st.integers(min_value=-1000, max_value=0))
def test_non_positive_retention_rejected(s3_client, days):
    with pytest.raises(Exception, match="retention days"):
        s3_client.put_worm(
            "test-worm-bucket", "k/x.json", b"x",
            mode="COMPLIANCE", days=days)


# ── P3: any body size 0..100KB → checksum matches ──────────
@given(body=st.binary(min_size=0, max_size=100_000))
def test_checksum_roundtrip(s3_client, body):
    key = f"cs/{len(body)}.bin"
    result = s3_client.put_worm(
        "test-worm-bucket", key, body,
        mode="COMPLIANCE", days=1)
    ok, msg = s3_client.verify_checksum(
        "test-worm-bucket", key, result.sha256)
    assert ok, msg


# ── P4: any invalid mode string rejected ───────────────────
@given(mode=st.text(min_size=1, max_size=30))
def test_invalid_modes_rejected(s3_client, mode):
    if mode in ("COMPLIANCE", "GOVERNANCE"):
        pytest.skip("valid mode")
    with pytest.raises(Exception):
        s3_client.put_worm(
            "test-worm-bucket", "k/m.json", b"x",
            mode=mode, days=1)
