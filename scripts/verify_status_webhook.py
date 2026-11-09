import urllib.request
import urllib.error
import json
import hmac
import hashlib
import time

def main():
    print("=== 1. UI SERVER CHECK (Port 8000) ===")
    try:
        with urllib.request.urlopen("http://127.0.0.1:8000/", timeout=5) as res:
            print(f"UI Index: HTTP {res.status} OK")
    except Exception as e:
        print(f"UI Index Error: {e}")

    try:
        with urllib.request.urlopen("http://127.0.0.1:8000/api/overview", timeout=5) as res:
            data = json.loads(res.read().decode())
            print(f"UI API Overview: HTTP {res.status} OK - Active Threats: {data.get('active_threats', 'N/A')}")
    except Exception as e:
        print(f"UI API Overview Error: {e}")

    print("\n=== 2. BACKEND HEALTH CHECK (Port 8001) ===")
    try:
        with urllib.request.urlopen("http://127.0.0.1:8001/health", timeout=5) as res:
            data = json.loads(res.read().decode())
            print(f"Backend Health: HTTP {res.status} OK - Status: {data.get('status')} | Mode: {data.get('mode')} | Version: {data.get('version')}")
    except Exception as e:
        print(f"Backend Health Error: {e}")

    print("\n=== 3. REAL-TIME SIGNED WEBHOOK TEST ===")
    secret = b"development-webhook-secret"
    payload = {
        "event_type": "threat_intel_match",
        "source": "sentinel-soc-sensor",
        "asset_id": "cloud-gateway-prod-01",
        "severity": "high",
        "attributes": {
            "target_ip": "185.199.110.153",
            "threat_type": "Credential Access & Token Abuse",
            "detection_rule": "RULE-AI-SEC-09"
        }
    }
    raw_body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ts = str(int(time.time()))
    event_id = f"evt-test-{ts}"
    msg = f"{ts}.".encode("utf-8") + raw_body
    sig = hmac.new(secret, msg, hashlib.sha256).hexdigest()

    # 3.1 Valid Webhook
    req = urllib.request.Request(
        "http://127.0.0.1:8001/api/v1/webhooks/telemetry",
        data=raw_body,
        headers={
            "Content-Type": "application/json",
            "X-Webhook-Timestamp": ts,
            "X-Webhook-Signature": f"sha256={sig}",
            "X-Event-Id": event_id,
            "X-Actor": "real-time-webhook-tester"
        },
        method="POST"
    )
    inc_id = None
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            inc = json.loads(res.read().decode())
            print(f"Valid Webhook: HTTP {res.status} Created")
            print(f" -> Incident ID: {inc.get('incident_id')}")
            print(f" -> Risk Score: {inc.get('risk_score')}")
            print(f" -> Evidence SHA-256: {inc.get('evidence', [{}])[0].get('raw_response_sha256', 'N/A')[:16]}...")
            print(f" -> Audit Trail Length: {len(inc.get('audit_trail', []))}")
            inc_id = inc.get("incident_id")
    except Exception as e:
        print(f"Valid Webhook Error: {e}")

    # 3.2 Replay Attack Test
    print("\n=== 4. ANTI-REPLAY ATTACK TEST ===")
    try:
        urllib.request.urlopen(req, timeout=5)
        print("Replay Test FAILED: Replayed event was accepted!")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"Replay Test PASSED: HTTP {e.code} - {body.strip()}")

    # 3.3 Forged Signature Test
    print("\n=== 5. FORGED SIGNATURE TEST ===")
    fake_req = urllib.request.Request(
        "http://127.0.0.1:8001/api/v1/webhooks/telemetry",
        data=raw_body,
        headers={
            "Content-Type": "application/json",
            "X-Webhook-Timestamp": ts,
            "X-Webhook-Signature": "sha256=invalid0000000000000000000000000000000000000000000000000000000000",
            "X-Event-Id": f"evt-fake-{ts}",
            "X-Actor": "attacker"
        },
        method="POST"
    )
    try:
        urllib.request.urlopen(fake_req, timeout=5)
        print("Forged Sig Test FAILED: Accepted invalid signature!")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"Forged Sig Test PASSED: HTTP {e.code} - {body.strip()}")

    # 3.4 Evidence Hash Chain Integrity
    if inc_id:
        print("\n=== 6. EVIDENCE HASH CHAIN INTEGRITY ===")
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:8001/api/v1/incidents/{inc_id}/integrity", timeout=5) as res:
                integrity = json.loads(res.read().decode())
                print(f"Integrity Check: HTTP {res.status} OK")
                print(f" -> Incident ID: {integrity.get('incident_id')}")
                print(f" -> Hash Chain: {integrity.get('hash_chain')}")
                print(f" -> Evidence Hashes Present: {integrity.get('evidence_hashes_present')}")
        except Exception as e:
            print(f"Integrity Error: {e}")

if __name__ == "__main__":
    main()
