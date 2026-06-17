import uuid
from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    username = None

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    email = models.EmailField(unique=True)
    name = models.CharField(max_length=255, blank=True)
    avatar_url = models.URLField(blank=True, null=True)

    google_id = models.CharField(max_length=255, unique=True, null=True, blank=True)
    google_access_token = models.TextField(blank=True, null=True)
    google_refresh_token = models.TextField(blank=True, null=True)
    google_token_expiry = models.DateTimeField(blank=True, null=True)

    gmail_connected = models.BooleanField(default=False)
    last_scan_at = models.DateTimeField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    def to_frontend_dict(self):
        """Shape expected by frontend (id, name, email, avatar)."""
        return {
            "id": str(self.id),
            "email": self.email,
            "name": self.name or self.email.split("@")[0],
            "avatar": self.avatar_url,
            "gmailConnected": self.gmail_connected,
            "lastScanAt": self.last_scan_at.isoformat() if self.last_scan_at else None,
        }
