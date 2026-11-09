/**
 * Cloud Functions for Firebase (2nd Gen) — SecOps Cyber Defense Platform
 * Developer: NAKARIN SAKULTHAI
 * License: MIT License
 *
 * Implements defensive-only telemetry ingestion, HMAC-SHA256 signed webhooks,
 * anti-replay protection, SHA-256 evidence digests, tamper-evident audit hash chains,
 * and human approval gates on Google Cloud Functions v2.
 */

import * as crypto from "crypto";
import express, { Request, Response } from "express";
import cors from "cors";
import * as admin from "firebase-admin";
import { onRequest } from "firebase-functions/v2/https";
import { onInit } from "firebase-functions/v2";
import { defineSecret, defineString, defineInt } from "firebase-functions/params";

// Parameterized Configuration (Never call .value() at module top-level scope)
const webhookSecret = defineSecret("WEBHOOK_SECRET");
const defensiveMode = defineString("DEFENSIVE_MODE", { default: "enforced" });
const webhookToleranceSeconds = defineInt("WEBHOOK_TOLERANCE_SECONDS", { default: 300 });

// Global SDK and In-memory State (initialized in onInit)
let isInitialized = false;
const replayMemoryCache = new Set<string>();

onInit(() => {
  if (!admin.apps.length) {
    admin.initializeApp();
  }
  isInitialized = true;
});

// Defensive Guardrails & Constraints
const OFFENSIVE_ACTIONS = new Set(["exploit", "attack_back", "brute_force", "credential_dump", "port_scan"]);
const ALLOWED_EVENT_TYPES = new Set([
  "login_anomaly",
  "remote_command",
  "credential_access_attempt",
  "telemetry_deviation",
  "api_chain",
  "threat_intel_match",
]);
const CONTAINMENT_ACTIONS = new Set(["revoke_token", "quarantine_case", "freeze_transaction", "manual_control"]);

// Types
export interface AuditEntry {
  sequence: number;
  ts: string;
  action: string;
  actor: string;
  metadata: Record<string, string>;
  previous_hash: string;
  entry_hash: string;
}

export interface EvidenceRecord {
  evidence_id: string;
  claim: string;
  source: string;
  retrieved_at: string;
  raw_response_sha256: string;
}

export interface Signal {
  factor: string;
  category: "fact" | "signal" | "inference";
  weight: number;
  detail: string;
  evidence_ids: string[];
}

export interface Incident {
  incident_id: string;
  status: "open" | "pending_approval" | "contained" | "closed";
  severity: "low" | "medium" | "high" | "critical";
  risk_score: number;
  confidence: "low" | "medium" | "high";
  attribution: "unknown" | "unconfirmed";
  signals: Signal[];
  evidence: EvidenceRecord[];
  audit_trail: AuditEntry[];
  pending_approval_id?: string | null;
  requested_action?: string | null;
  created_at: string;
  updated_at: string;
}

// In-Memory Fallback Store (or Firestore in full deployment)
const incidentStore = new Map<string, Incident>();

function sha256(data: string): string {
  return crypto.createHash("sha256").update(data, "utf8").digest("hex");
}

function canonicalJson(obj: unknown): string {
  return JSON.stringify(obj, Object.keys(obj as object).sort());
}

function addAudit(incident: Incident, action: string, actor: string, metadata: Record<string, string> = {}): void {
  const previousHash = incident.audit_trail.length
    ? incident.audit_trail[incident.audit_trail.length - 1].entry_hash
    : "GENESIS";
  const sequence = incident.audit_trail.length + 1;
  const ts = new Date().toISOString();
  const entryHash = sha256(`${sequence}:${ts}:${action}:${actor}:${previousHash}:${canonicalJson(metadata)}`);
  incident.audit_trail.push({
    sequence,
    ts,
    action,
    actor,
    metadata,
    previous_hash: previousHash,
    entry_hash: entryHash,
  });
  incident.updated_at = ts;
}

// Express Application Setup
const app = express();
app.use(cors({ origin: true }));
app.use(express.json({ limit: "1mb" }));

// 1. Health Check
app.get("/health", (_req: Request, res: Response) => {
  res.json({
    status: "ok",
    mode: "defensive-only",
    platform: "Cloud Functions for Firebase v2",
    defensive_mode: defensiveMode.value(),
    initialized: isInitialized,
  });
});

// 2. Telemetry Ingestion Endpoint
app.post("/api/v1/telemetry/events", (req: Request, res: Response) => {
  const body = req.body;
  if (!body || !body.event_type || !ALLOWED_EVENT_TYPES.has(body.event_type)) {
    return res.status(400).json({ error: "Invalid or unsupported event_type" });
  }

  const actor = (req.headers["x-actor"] as string) || "telemetry-ingest";
  const evidenceId = `ev_${crypto.randomBytes(6).toString("hex")}`;
  const now = new Date().toISOString();
  const evidenceDigest = sha256(canonicalJson(body));

  const signal: Signal = {
    factor: body.event_type,
    category: "signal",
    weight: body.severity === "critical" ? 85 : body.severity === "high" ? 65 : 40,
    detail: `Telemetry signal received: ${body.event_type} on asset ${body.asset_id || "unknown"}`,
    evidence_ids: [evidenceId],
  };

  const incident: Incident = {
    incident_id: `INC-${new Date().toISOString().slice(0, 10).replace(/-/g, "")}-${crypto.randomBytes(3).toString("hex").toUpperCase()}`,
    status: "open",
    severity: body.severity || "medium",
    risk_score: signal.weight,
    confidence: "high",
    attribution: "unknown",
    signals: [signal],
    evidence: [
      {
        evidence_id: evidenceId,
        claim: signal.detail,
        source: body.source || "telemetry-sensor",
        retrieved_at: now,
        raw_response_sha256: evidenceDigest,
      },
    ],
    audit_trail: [],
    created_at: now,
    updated_at: now,
  };

  addAudit(incident, "incident_created", actor, { event_type: body.event_type });
  incidentStore.set(incident.incident_id, incident);

  return res.status(201).json(incident);
});

// 3. Real-time Signed Webhook Endpoint (HMAC-SHA256 & Anti-Replay)
app.post("/api/v1/webhooks/telemetry", (req: Request, res: Response) => {
  const timestamp = req.headers["x-webhook-timestamp"] as string;
  const signatureHeader = req.headers["x-webhook-signature"] as string;
  const eventId = req.headers["x-event-id"] as string;

  if (!eventId) {
    return res.status(400).json({ detail: "X-Event-Id is required" });
  }
  if (!timestamp || isNaN(Number(timestamp))) {
    return res.status(401).json({ detail: "webhook rejected: invalid timestamp" });
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const tolerance = webhookToleranceSeconds.value();
  if (Math.abs(nowSec - Number(timestamp)) > tolerance) {
    return res.status(401).json({ detail: "webhook rejected: stale webhook" });
  }

  // Anti-replay check
  if (replayMemoryCache.has(eventId)) {
    return res.status(401).json({ detail: "webhook rejected: replayed event" });
  }

  // Verify HMAC-SHA256 signature
  const rawBody = JSON.stringify(req.body);
  const secret = webhookSecret.value() || "development-webhook-secret";
  const expectedSignature = crypto
    .createHmac("sha256", secret)
    .update(`${timestamp}.${rawBody}`)
    .digest("hex");

  const suppliedSig = (signatureHeader || "").replace(/^sha256=/, "");
  if (!suppliedSig || !crypto.timingSafeEqual(Buffer.from(expectedSignature), Buffer.from(suppliedSig))) {
    return res.status(401).json({ detail: "webhook rejected: invalid signature" });
  }

  replayMemoryCache.add(eventId);

  const actor = (req.headers["x-actor"] as string) || "signed-webhook";
  const evidenceId = `ev_${crypto.randomBytes(6).toString("hex")}`;
  const now = new Date().toISOString();
  const evidenceDigest = sha256(canonicalJson(req.body));

  const incident: Incident = {
    incident_id: `INC-${new Date().toISOString().slice(0, 10).replace(/-/g, "")}-${crypto.randomBytes(3).toString("hex").toUpperCase()}`,
    status: "open",
    severity: req.body.severity || "medium",
    risk_score: 50,
    confidence: "medium",
    attribution: "unknown",
    signals: [
      {
        factor: req.body.event_type || "credential_access_attempt",
        category: "signal",
        weight: 25,
        detail: `Verified webhook signal: ${req.body.event_type}`,
        evidence_ids: [evidenceId],
      },
    ],
    evidence: [
      {
        evidence_id: evidenceId,
        claim: `Webhook telemetry verified via HMAC-SHA256`,
        source: req.body.source || "signed-webhook-producer",
        retrieved_at: now,
        raw_response_sha256: evidenceDigest,
      },
    ],
    audit_trail: [],
    created_at: now,
    updated_at: now,
  };

  addAudit(incident, "incident_created", actor, { event_type: req.body.event_type });
  addAudit(incident, "signed_webhook_verified", actor, { event_id: eventId });
  incidentStore.set(incident.incident_id, incident);

  return res.status(201).json(incident);
});

// 4. Incident Integrity Verification Endpoint
app.get("/api/v1/incidents/:id/integrity", (req: Request, res: Response) => {
  const incident = incidentStore.get(req.params.id);
  if (!incident) {
    return res.status(404).json({ error: "Incident not found" });
  }

  // Verify hash chain
  let chainValid = true;
  for (let i = 0; i < incident.audit_trail.length; i++) {
    const entry = incident.audit_trail[i];
    const prev = i === 0 ? "GENESIS" : incident.audit_trail[i - 1].entry_hash;
    const expected = sha256(
      `${entry.sequence}:${entry.ts}:${entry.action}:${entry.actor}:${prev}:${canonicalJson(entry.metadata)}`
    );
    if (entry.entry_hash !== expected || entry.previous_hash !== prev) {
      chainValid = false;
      break;
    }
  }

  return res.json({
    incident_id: incident.incident_id,
    audit_entries: incident.audit_trail.length,
    hash_chain: chainValid ? "verified" : "tampered",
    evidence_records: incident.evidence.length,
    evidence_hashes_present: incident.evidence.every((e) => Boolean(e.raw_response_sha256)),
  });
});

// 5. Human Approval Gate: Request & Approve Containment
app.post("/api/v1/incidents/:id/containment/request", (req: Request, res: Response) => {
  const incident = incidentStore.get(req.params.id);
  if (!incident) return res.status(404).json({ error: "Incident not found" });

  const action = req.body.action;
  if (OFFENSIVE_ACTIONS.has(action)) {
    return res.status(400).json({ error: `Offensive action '${action}' is strictly prohibited.` });
  }
  if (!CONTAINMENT_ACTIONS.has(action)) {
    return res.status(400).json({ error: `Unknown containment action '${action}'.` });
  }

  const approvalId = `appr_${crypto.randomBytes(4).toString("hex")}`;
  incident.status = "pending_approval";
  incident.pending_approval_id = approvalId;
  incident.requested_action = action;
  addAudit(incident, "containment_requested", (req.headers["x-actor"] as string) || "secops-operator", {
    approval_id: approvalId,
    action,
  });

  return res.json({
    incident_id: incident.incident_id,
    approval_id: approvalId,
    status: incident.status,
    requested_action: action,
    message: "Awaiting human operator approval.",
  });
});

app.post("/api/v1/incidents/:id/containment/approve", (req: Request, res: Response) => {
  const incident = incidentStore.get(req.params.id);
  if (!incident) return res.status(404).json({ error: "Incident not found" });

  if (incident.status !== "pending_approval" || !incident.pending_approval_id) {
    return res.status(409).json({ error: "No pending containment approval found" });
  }

  const { decision, reason } = req.body;
  const operator = (req.headers["x-actor"] as string) || "human-soc-manager";

  if (decision === "approved") {
    incident.status = "contained";
    addAudit(incident, "containment_approved", operator, {
      action: incident.requested_action || "unknown",
      reason: reason || "operator_approved",
    });
  } else {
    incident.status = "open";
    addAudit(incident, "containment_rejected", operator, {
      action: incident.requested_action || "unknown",
      reason: reason || "operator_denied",
    });
  }

  const appliedAction = incident.requested_action;
  incident.pending_approval_id = null;
  incident.requested_action = null;

  return res.json({
    incident_id: incident.incident_id,
    status: incident.status,
    decision,
    applied_action: appliedAction,
    operator,
  });
});

// Export Cloud Function V2 HTTPS Trigger with Parameterized Secrets & Defensive Constraints
export const secopsApi = onRequest(
  {
    cpu: "gcf_gen1",
    concurrency: 80,
    secrets: [webhookSecret],
    timeoutSeconds: 60,
    region: "asia-southeast1",
  },
  app
);
