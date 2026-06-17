"""
Models for Gmail Integration.

Field names map 1-to-1 with the frontend EmailAnalysis TypeScript interface
defined in src/app/components/mockData.ts so serializers need zero renaming.

  id              → str  (gmail message id, used as PK slug)
  subject         → str
  sender          → str  (full email address)
  senderName      → str
  domain          → str  (extracted sender domain)
  date            → ISO 8601 datetime str
  body            → str  (plain text body / snippet)

  -- Domain analysis (populated by services/domain.py) --
  domainAge       → str  e.g. "4 days" | "6 years"
  domainReputation → "Trusted" | "Suspicious" | "Malicious"
  lookalikeDomain → str | null

  -- AI analysis scores 0-100 (populated by services/analysis.py) --
  urgency               → int
  fear                  → int
  credentialTheft       → int
  financialFraud        → int
  authorityImpersonation → int
  aiSummary             → str

  -- Composite scores --
  aiScore       → int  (0-100)
  domainScore   → int  (0-100)
  threatScore   → int  (0-100, weighted: aiScore*0.7 + domainScore*0.3)
  riskLevel     → "Critical" | "High" | "Medium" | "Safe"
"""

from django.db import models
from django.conf import settings


class EmailAccount(models.Model):
    """One Gmail account connected per user via OAuth."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="email_account",
    )
    email = models.EmailField(unique=True)
    access_token = models.TextField()
    refresh_token = models.TextField(blank=True)
    token_expiry = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    connected_at = models.DateTimeField(auto_now_add=True)
    last_synced_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "gmail_email_account"

    def __str__(self):
        return self.email

    @property
    def is_token_expired(self):
        from django.utils import timezone
        if not self.token_expiry:
            return True
        return timezone.now() >= self.token_expiry


class EmailMessage(models.Model):
    """
    Normalised Gmail message.
    All field names match the frontend EmailAnalysis interface exactly
    so DRF serializers output the correct JSON keys without renaming.
    """

    RISK_LEVEL_CHOICES = [
        ("Critical", "Critical"),
        ("High", "High"),
        ("Medium", "Medium"),
        ("Safe", "Safe"),
    ]

    DOMAIN_REPUTATION_CHOICES = [
        ("Trusted", "Trusted"),
        ("Suspicious", "Suspicious"),
        ("Malicious", "Malicious"),
    ]

    account = models.ForeignKey(
        EmailAccount,
        on_delete=models.CASCADE,
        related_name="messages",
    )

    # ── Core email fields (maps to frontend: id, subject, sender, senderName, domain, date, body)
    # We use gmail_id as the public-facing "id" string returned to the frontend.
    gmail_id = models.CharField(max_length=255, unique=True)
    subject = models.TextField(blank=True)
    sender = models.CharField(max_length=512)        # full "user@domain.com"
    senderName = models.CharField(max_length=512, blank=True)  # noqa: N815
    domain = models.CharField(max_length=255, blank=True)
    date = models.DateTimeField()
    body = models.TextField(blank=True)

    # ── Domain analysis
    domainAge = models.CharField(max_length=100, blank=True)           # noqa: N815  e.g. "4 days"
    domainReputation = models.CharField(                                 # noqa: N815
        max_length=20,
        choices=DOMAIN_REPUTATION_CHOICES,
        default="Trusted",
    )
    lookalikeDomain = models.CharField(max_length=255, blank=True, null=True)  # noqa: N815

    # ── AI analysis scores (0-100)
    urgency = models.IntegerField(default=0)
    fear = models.IntegerField(default=0)
    credentialTheft = models.IntegerField(default=0)       # noqa: N815
    financialFraud = models.IntegerField(default=0)        # noqa: N815
    authorityImpersonation = models.IntegerField(default=0)  # noqa: N815
    aiSummary = models.TextField(blank=True)               # noqa: N815

    # ── Composite scores
    aiScore = models.IntegerField(default=0)       # noqa: N815
    domainScore = models.IntegerField(default=0)   # noqa: N815
    threatScore = models.IntegerField(default=0)   # noqa: N815
    riskLevel = models.CharField(                  # noqa: N815
        max_length=10,
        choices=RISK_LEVEL_CHOICES,
        default="Safe",
    )

    # ── Sync metadata
    synced_at = models.DateTimeField(auto_now=True)
    analysis_done = models.BooleanField(default=False)

    class Meta:
        db_table = "gmail_email_message"
        ordering = ["-date"]
        indexes = [
            models.Index(fields=["account", "date"]),
            models.Index(fields=["account", "riskLevel"]),
            models.Index(fields=["domain"]),
        ]

    def __str__(self):
        return f"[{self.gmail_id}] {self.subject[:60]}"
