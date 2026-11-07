"""Backend tests for Trustworthy Agent defensive controls.

Developer: NAKARIN SAKULTHAI
License: MIT License
"""
import unittest

from fastapi.testclient import TestClient

from main import app, store


class BackendSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        store.incidents.clear()
        self.client = TestClient(app)

    def test_health_is_defensive_only(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["mode"], "defensive-only")

    def test_ingest_creates_explainable_incident_and_integrity(self) -> None:
        response = self.client.post(
            "/api/v1/telemetry/events",
            headers={"X-Actor": "unit-test"},
            json={
                "event_type": "telemetry_deviation",
                "source": "ics-telemetry",
                "asset_id": "cold-storage-01",
                "severity": "high",
                "attributes": {"authoritative_source": True, "temperature_before": -18.5, "temperature_after": -15.2},
            },
        )
        self.assertEqual(response.status_code, 201)
        incident = response.json()
        self.assertEqual(incident["signals"][0]["category"], "fact")
        self.assertGreaterEqual(incident["risk_score"], 15)
        integrity = self.client.get(f"/api/v1/incidents/{incident['incident_id']}/integrity")
        self.assertEqual(integrity.status_code, 200)
        self.assertEqual(integrity.json()["hash_chain"], "verified")
        self.assertTrue(integrity.json()["evidence_hashes_present"])

    def test_containment_requires_approval_and_does_not_execute_external_action(self) -> None:
        created = self.client.post("/api/v1/telemetry/events", json={"event_type": "login_anomaly", "source": "auth", "asset_id": "agent-01"}).json()
        incident_id = created["incident_id"]
        request = self.client.post(
            f"/api/v1/incidents/{incident_id}/containment/request",
            json={"action": "revoke_token", "reason": "Anomalous session requires review", "requested_by": "soc-analyst"},
        )
        self.assertEqual(request.status_code, 200)
        self.assertTrue(request.json()["human_approval_required"])
        decision = self.client.post(
            f"/api/v1/incidents/{incident_id}/containment/approve",
            json={"approved": True, "approver": "soc-lead", "note": "Reviewed evidence and approved demo containment"},
        )
        self.assertEqual(decision.status_code, 200)
        self.assertFalse(decision.json()["external_action_executed"])
        self.assertEqual(decision.json()["result"], "demo_containment_recorded")

    def test_offensive_action_is_rejected(self) -> None:
        created = self.client.post("/api/v1/telemetry/events", json={"event_type": "api_chain", "source": "gateway", "asset_id": "agent-01"}).json()
        response = self.client.post(
            f"/api/v1/incidents/{created['incident_id']}/containment/request",
            json={"action": "attack_back", "reason": "This must be rejected", "requested_by": "tester"},
        )
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
