/**
 * src/api/gmail.ts
 *
 * FIXED VERSION FOR CURRENT BACKEND
 *
 * ACTIVE BACKEND ROUTES (REALITY):
 *   GET  /api/gmail/emails/          → email list
 *   GET  /api/gmail/emails/stats/    → stats
 *   GET  /api/gmail/emails/<id>/     → email detail
 *   POST /api/gmail/scan/            → trigger scan
 *   GET  /api/gmail/auth/status/     → auth status
 *   DELETE /api/gmail/auth/disconnect/
 */

import { api } from "./client";
import type { RiskLevel } from "../app/components/mockData";

// ─────────────────────────────────────────────────────────────
// TYPES
// ─────────────────────────────────────────────────────────────

export interface EmailListItem {
  id: string;
  subject: string;

  senderName: string;
  sender: string;
  domain: string;

  date: string;

  riskLevel: RiskLevel;
  analysis_status?: "pending" | "pending_ai" | "processing" | "done" | "fallback" | "failed";
  analysisSource?: "AI analyzer" | "AI pending" | "AI unavailable" | "Waiting for reputation";
  spamActionStatus?: "none" | "moved" | "failed" | "skipped";
  spamActionAt?: string | null;

  domainReputation: "Trusted" | "Suspicious" | "Malicious";

  snippet?: string;
}

export interface EmailDetail extends EmailListItem {
  body: string;

  domainAge: string;
  lookalikeDomain?: string;

  urgency: number;
  fear: number;
  credentialTheft: number;
  financialFraud: number;
  authorityImpersonation: number;

  aiSummary: string;
  verdict?: string;
  recommendations?: string[];

  aiScore: number;
  domainScore: number;
  threatScore: number;
  analysis_status?: "pending" | "pending_ai" | "processing" | "done" | "fallback" | "failed";
  analysisSource?: "AI analyzer" | "AI pending" | "AI unavailable" | "Waiting for reputation";
  analysisNotice?: string;
  spamActionStatus?: "none" | "moved" | "failed" | "skipped";
  spamActionAt?: string | null;
  spamActionError?: string;
  securitySignals?: Record<string, unknown>;
  attachmentScore?: number;
  attachmentScanSummary?: string;
  scannedAttachments?: ScannedAttachment[];
  urlScanSummary?: string;
  urlScore?: number;
  scannedUrls?: ScannedUrl[];
  hasPhishingUrl?: boolean;
  hasMaliciousUrl?: boolean;
}

export interface ScannedAttachment {
  filename: string;
  mime_type: string;
  size_bytes: number;
  verdict: "Clean" | "Suspicious" | "Malicious" | "Pending" | "Error";
  score: number;
  confidence?: string;
  is_suspicious?: boolean;
  is_malicious?: boolean;
  local_findings?: string[];
  extracted_text_preview?: string;
  stats?: Record<string, number>;
  detections?: Record<string, unknown>;
  fetched_at?: string;
  error?: string;
}

export interface ScannedUrl {
  url: string;
  verdict: "Clean" | "Suspicious" | "Malicious" | "Pending" | "Error";
  score: number;
  confidence?: string;
  is_phishing?: boolean;
  is_malicious?: boolean;
  stats?: Record<string, number>;
  detections?: Record<string, unknown>;
  fetched_at?: string;
  error?: string;
}

export interface EmailStats {
  total: number;
  analyzed: number;
  pendingAi: number;
  suspicious: number;
  high: number;
  critical: number;
  distribution: Record<RiskLevel, number>;
  lastScannedAt: string | null;
}

const emptyStats: EmailStats = {
  total: 0,
  analyzed: 0,
  pendingAi: 0,
  suspicious: 0,
  high: 0,
  critical: 0,
  distribution: {
    Critical: 0,
    High: 0,
    Medium: 0,
    Safe: 0,
  },
  lastScannedAt: null,
};


export interface EmailProgressItem {
  id: string;
  analysis_status?: "pending" | "pending_ai" | "processing" | "done" | "fallback" | "failed";
  analysisSource?: "AI analyzer" | "AI pending" | "AI unavailable" | "Waiting for reputation";
  riskLevel: RiskLevel;
  threatScore: number;
  spamActionStatus?: "none" | "moved" | "failed" | "skipped";
  spamActionAt?: string | null;
  syncedAt: string;
}

export interface EmailProgress {
  emails: EmailProgressItem[];
  stats: EmailStats;
  serverTime: string;
  hasPending: boolean;
}
export interface TrustedSenderRule {
  id: number;
  rule_type: "domain" | "email";
  value: string;
  active: boolean;
  created_at: string;
}
export interface GmailAccountStatus {
  connected: boolean;
  account?: {
    id: number;
    email: string;
    last_synced_at: string | null;
    gmailModifyEnabled?: boolean;
    reconnectRequired?: boolean;
  };
}

export interface ScanResult {
  fetched?: number;
  processed?: number;
  created: number;
  updated: number;
  errors: number;
  message: string;
  scan_id?: string;
  queued?: boolean;
}

export interface ScanStatus {
  state: string;
  fetched: number;
  processed: number;
  created: number;
  updated: number;
  errors: number;
  pending_ai?: number;
  ready: boolean;
}

// ─────────────────────────────────────────────────────────────
// EMAIL LIST
// ─────────────────────────────────────────────────────────────

export interface EmailListParams {
  search?: string;
  risk_level?: RiskLevel | "All";
  ordering?: string;
}

export async function fetchEmails(
    params: EmailListParams = {}
): Promise<{ emails: EmailListItem[]; total: number }> {
  const qs = new URLSearchParams();

  if (params.search) qs.set("search", params.search);
  if (params.risk_level && params.risk_level !== "All") {
    qs.set("risk_level", params.risk_level);
  }
  if (params.ordering) qs.set("ordering", params.ordering);

  const query = qs.toString() ? `?${qs.toString()}` : "";

  return api.get(`/gmail/emails/${query}`);
}

// ─────────────────────────────────────────────────────────────
// STATS
// ─────────────────────────────────────────────────────────────


export async function fetchEmailProgress(): Promise<EmailProgress> {
  return api.get("/gmail/emails/progress/");
}
export async function fetchEmailStats(): Promise<EmailStats> {
  try {
    return await api.get("/gmail/emails/stats/");
  } catch {
    return emptyStats;
  }
}

// ─────────────────────────────────────────────────────────────
// DETAIL
// ─────────────────────────────────────────────────────────────

export async function fetchEmailDetail(id: string): Promise<EmailDetail> {
  return api.get(`/gmail/emails/${id}/`);
}

// ─────────────────────────────────────────────────────────────
// SEARCH (optional backend endpoint)
// ─────────────────────────────────────────────────────────────

export async function searchEmails(query: string) {
  return api.get(`/gmail/emails/?search=${encodeURIComponent(query)}`);
}

// ─────────────────────────────────────────────────────────────
// SCAN
// ─────────────────────────────────────────────────────────────

export async function triggerScan(maxResults = 30): Promise<ScanResult> {
  return api.post("/gmail/scan/", { max_results: maxResults });
}

export async function fetchScanStatus(scanId: string): Promise<ScanStatus> {
  return api.get(`/gmail/scan/${scanId}/status/`);
}

// ─────────────────────────────────────────────────────────────
// AUTH STATUS
// ─────────────────────────────────────────────────────────────

export async function fetchGmailStatus(): Promise<GmailAccountStatus> {
  return api.get("/gmail/auth/status/");
}

// ─────────────────────────────────────────────────────────────
// DISCONNECT
// ─────────────────────────────────────────────────────────────

export async function disconnectGmail(): Promise<void> {
  return api.delete("/gmail/auth/disconnect/");
}

// ─────────────────────────────────────────────────────────────
// TRUSTED SENDERS / DOMAINS
// ─────────────────────────────────────────────────────────────

export async function fetchTrustedSenderRules(): Promise<{ rules: TrustedSenderRule[] }> {
  return api.get("/gmail/trusted-senders/");
}

export async function createTrustedSenderRule(payload: {
  ruleType: "domain" | "email";
  value: string;
  active?: boolean;
}): Promise<TrustedSenderRule> {
  return api.post("/gmail/trusted-senders/", payload);
}

export async function deleteTrustedSenderRule(id: number): Promise<void> {
  return api.delete(`/gmail/trusted-senders/${id}/`);
}
