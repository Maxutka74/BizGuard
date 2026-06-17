"""
apps/dashboard/models.py

NOTE ON CONTRACT (extracted from frontend):
---------------------------------------------------------------------------
Source: src/app/components/Dashboard.tsx + src/app/components/mockData.ts

The Dashboard screen renders a list of "EmailAnalysis" records and computes
all stats/aggregations CLIENT-SIDE from that single list:

    interface EmailAnalysis {
      id: string;
      subject: string;
      sender: string;
      senderName: string;
      domain: string;
      date: string;                 // ISO datetime
      body: string;
      domainAge: string;            // human readable, e.g. "4 days"
      domainReputation: "Trusted" | "Suspicious" | "Malicious";
      lookalikeDomain: string | null;
      urgency: number;               // 0-100
      fear: number;                  // 0-100
      credentialTheft: number;       // 0-100
      financialFraud: number;        // 0-100
      authorityImpersonation: number;// 0-100
      aiSummary: string;
      aiScore: number;               // 0-100
      domainScore: number;           // 0-100
      threatScore: number;           // 0-100
      riskLevel: "Critical" | "High" | "Medium" | "Safe";
    }

Stats cards derived from the list:
    total      = count(emails)
    suspicious = count(riskLevel != "Safe")
    high       = count(riskLevel in ["High", "Critical"])
    critical   = count(riskLevel == "Critical")

Threat distribution bar:
    for level in ["Critical", "High", "Medium", "Safe"]:
        count(riskLevel == level), pct = count / total * 100

Email list table columns: subject, senderName, domain (colored by
domainReputation/riskLevel), date (day/short-month), riskLevel badge.

The dashboard's own search box and risk filter buttons operate purely on the
already-fetched list, so the backend does not need separate filter
parameters for the dashboard endpoint itself -- it must simply return the
full set of analyzed emails (scoped to the authenticated user) plus the
pre-computed stats/distribution so the frontend doesn't have to recompute
on every page (and so other clients can reuse them).
---------------------------------------------------------------------------

This app is intentionally "read-side" / aggregation-only. It does NOT own
ingestion of raw emails (that belongs to apps.emails / apps.gmail), nor the
actual AI/domain analysis pipeline (apps.analysis / apps.reputation /
apps.threats). Instead it exposes a denormalized, query-friendly model that
mirrors exactly the EmailAnalysis shape the frontend already expects, plus a
small ScanRun model to back the "Rescan" action / "LAST SCANNED" footer.

If/when apps.emails, apps.threats, apps.reputation land with their own
models, EmailAnalysisRecord can be populated by a signal/sync job from those
apps. For now it stands alone so apps.dashboard is fully functional against
the documented frontend contract.
"""

import uuid

from django.conf import settings
from django.db import models


class RiskLevel(models.TextChoices):
    """Matches frontend `RiskLevel` union exactly (mockData.ts)."""
    CRITICAL = "Critical", "Critical"
    HIGH = "High", "High"
    MEDIUM = "Medium", "Medium"
    SAFE = "Safe", "Safe"


class DomainReputation(models.TextChoices):
    """Matches frontend `EmailAnalysis.domainReputation` union exactly."""
    TRUSTED = "Trusted", "Trusted"
    SUSPICIOUS = "Suspicious", "Suspicious"
    MALICIOUS = "Malicious", "Malicious"


class EmailAnalysisRecord(models.Model):
    """
    Denormalized record matching the frontend `EmailAnalysis` interface
    field-for-field. One row per analyzed email, scoped to a user (each
    BizGuard user has their own connected mailbox / dashboard).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="email_analyses",
    )

    # --- Core email fields -------------------------------------------------
    subject = models.CharField(max_length=998, blank=True, default="")
    sender = models.CharField(max_length=320)  # full "email@domain" address
    sender_name = models.CharField(max_length=255, blank=True, default="")
    domain = models.CharField(max_length=255, db_index=True)
    date = models.DateTimeField(db_index=True)
    body = models.TextField(blank=True, default="")

    # --- Domain analysis -----------------------------------------------------
    domain_age = models.CharField(max_length=64, blank=True, default="")
    domain_reputation = models.CharField(
        max_length=16, choices=DomainReputation.choices,
    )
    lookalike_domain = models.CharField(max_length=255, null=True, blank=True)

    # --- AI analysis (0-100 scores) ------------------------------------------
    urgency = models.PositiveSmallIntegerField(default=0)
    fear = models.PositiveSmallIntegerField(default=0)
    credential_theft = models.PositiveSmallIntegerField(default=0)
    financial_fraud = models.PositiveSmallIntegerField(default=0)
    authority_impersonation = models.PositiveSmallIntegerField(default=0)
    ai_summary = models.TextField(blank=True, default="")

    # --- Aggregate scores -----------------------------------------------------
    ai_score = models.PositiveSmallIntegerField(default=0)
    domain_score = models.PositiveSmallIntegerField(default=0)
    threat_score = models.PositiveSmallIntegerField(default=0)
    risk_level = models.CharField(
        max_length=16, choices=RiskLevel.choices, db_index=True,
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-date"]
        indexes = [
            models.Index(fields=["user", "risk_level"]),
            models.Index(fields=["user", "date"]),
        ]

    def __str__(self) -> str:
        return f"{self.subject} ({self.risk_level})"


class ScanRun(models.Model):
    """
    Backs the "Rescan" button and the
    "LAST SCANNED ..." footer text on the dashboard.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="scan_runs",
    )
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    emails_scanned = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["-started_at"]

    def __str__(self) -> str:
        return f"ScanRun({self.user_id}, {self.started_at})"
