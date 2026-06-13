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

  aiScore: number;
  domainScore: number;
  threatScore: number;
}

export interface EmailStats {
  total: number;
  suspicious: number;
  high: number;
  critical: number;
  distribution: Record<RiskLevel, number>;
  lastScannedAt: string | null;
}

const emptyStats: EmailStats = {
  total: 0,
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

export interface GmailAccountStatus {
  connected: boolean;
  account?: {
    id: number;
    email: string;
    last_synced_at: string | null;
  };
}

export interface ScanResult {
  created: number;
  updated: number;
  errors: number;
  message: string;
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

export async function triggerScan(maxResults = 50): Promise<ScanResult> {
  return api.post("/gmail/scan/", { max_results: maxResults });
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