"""Unit tests for S3WormAdapter using moto (no real AWS)."""
from __future__ import annotations
import json
import pathlib
import pytest

# ── Patch Moto to support GetObjectRetention and DeleteObject lock checks ──
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


# ── fixtures ────────────────────────────────────────────────
@pytest.fixture
def s3_mock():
    """In-memory S3 via moto, with Object Lock enabled."""
    moto = pytest.importorskip("moto")
    _patch_moto_for_retention()
    try:
        from moto import mock_aws as mock_s3
    except ImportError:
        from moto import mock_s3

    with mock_s3():
        import boto3
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(
            Bucket="test-worm-bucket",
            ObjectLockEnabledForBucket=True,
        )
        yield client


@pytest.fixture
def worm(s3_mock):
    from core.s3_client import S3Client
    from core.anchor import S3WormAdapter
    return S3WormAdapter(
        bucket="test-worm-bucket",
        mode="COMPLIANCE",
        retention_days=1,
        s3_client=S3Client(client=s3_mock),
    )


@pytest.fixture
def sample_rec():
    return {
        "case_id": "TEST-001",
        "head_hash": "a" * 64,
        "entry_count": 5,
        "anchored_at": 1700000000.0,
        "anchored_iso": "2026-11-05T00:00:00Z",
    }


# ── 1. put + read-back ──────────────────────────────────────
def test_put_and_verify(worm, sample_rec, s3_mock):
    result = worm.anchor(sample_rec)
    assert result["bucket"] == "test-worm-bucket"
    assert result["sha256"]
    assert result["retention_mode"] == "COMPLIANCE"

    obj = s3_mock.get_object(Bucket="test-worm-bucket", Key=result["key"])
    body = json.loads(obj["Body"].read().decode("utf-8"))
    assert body["record"]["case_id"] == "TEST-001"


# ── 2. retention mode enforced ──────────────────────────────
def test_retention_compliance_set(worm, sample_rec, s3_mock):
    result = worm.anchor(sample_rec)
    r = s3_mock.get_object_retention(
        Bucket="test-worm-bucket", Key=result["key"])
    assert r["Retention"]["Mode"] == "COMPLIANCE"
    assert r["Retention"]["RetainUntilDate"] is not None


# ── 3. delete is blocked (moto simulates Object Lock) ──────
def test_delete_blocked_by_object_lock(worm, sample_rec, s3_mock):
    result = worm.anchor(sample_rec)
    with pytest.raises(Exception) as exc:
        s3_mock.delete_object(
            Bucket="test-worm-bucket", Key=result["key"])
    assert "lock" in str(exc.value).lower() or \
           "access" in str(exc.value).lower() or \
           "denied" in str(exc.value).lower()


# ── 4. checksum verification ────────────────────────────────
def test_checksum_matches(s3_mock):
    from core.s3_client import S3Client
    client = S3Client(client=s3_mock)
    result = client.put_worm(
        "test-worm-bucket", "test/file.json",
        b'{"hello": "world"}', mode="COMPLIANCE", days=1)
    ok, msg = client.verify_checksum(
        "test-worm-bucket", "test/file.json", result.sha256)
    assert ok, msg


def test_checksum_mismatch_detected(s3_mock):
    from core.s3_client import S3Client
    client = S3Client(client=s3_mock)
    client.put_worm("test-worm-bucket", "t/f.json",
                    b"original", mode="COMPLIANCE", days=1)
    ok, msg = client.verify_checksum(
        "test-worm-bucket", "t/f.json", "0" * 64)
    assert not ok
    assert "sha256 mismatch" in msg


# ── 5. invalid mode rejected ────────────────────────────────
def test_invalid_mode_rejected(s3_mock):
    from core.s3_client import S3Client
    client = S3Client(client=s3_mock)
    with pytest.raises(Exception, match="invalid retention mode"):
        client.put_worm("test-worm-bucket", "k", b"x",
                        mode="INVALID", days=1)


# ── 6. invalid retention days ──────────────────────────────
def test_invalid_retention_days_rejected(s3_mock):
    from core.anchor import S3WormAdapter
    with pytest.raises(ValueError, match="retention_days"):
        S3WormAdapter(bucket="x", retention_days=0)


# ── 7. signature included in payload ───────────────────────
def test_signature_included_in_payload(worm, sample_rec, tmp_path, s3_mock):
    sig = tmp_path / "ledger.asc"
    sig.write_text("-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----", encoding="utf-8")
    result = worm.anchor(sample_rec, sig_path=str(sig))
    obj = s3_mock.get_object(Bucket="test-worm-bucket", Key=result["key"])
    body = json.loads(obj["Body"].read().decode("utf-8"))
    assert "signature_asc" in body
    assert "BEGIN PGP SIGNATURE" in body["signature_asc"]


# ── 8. list_case_anchors ───────────────────────────────────
def test_list_case_anchors(worm, s3_mock):
    for i in range(3):
        rec = {"case_id": "C1", "head_hash": f"{i}" * 64,
               "entry_count": i, "anchored_iso": "x"}
        worm.anchor(rec)
    # different case
    worm.anchor({"case_id": "C2", "head_hash": "f" * 64,
                 "entry_count": 1, "anchored_iso": "x"})
    out = worm.list_case_anchors("C1")
    assert len(out) == 3
    assert all("C1" in o["key"] for o in out)
