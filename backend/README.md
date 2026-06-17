# BizGuard – Backend

Django REST API for BizGuard Email Threat Intelligence.

## Apps

| App | Label | Purpose |
|-----|-------|---------|
| `apps.accounts` | `accounts` | Google OAuth, JWT auth, user profile |
| `apps.gmail` | `gmail` | Gmail integration, email sync, scan trigger |
| `apps.analysis` | `analysis` | Gemini AI threat analysis (cached) |
| `apps.reputation` | `reputation` | Domain reputation via VirusTotal |
| `apps.emails` | `emails` | Raw email storage + normalization |
| `apps.threats` | `threats` | Combined threat score aggregation |
| `apps.dashboard` | `dashboard` | Dashboard aggregation + rescan |

## API Endpoints

### Auth (`/api/accounts/`)
| Method | URL | Description |
|--------|-----|-------------|
| GET | `/api/accounts/google/url` | Get Google OAuth URL → redirect user |
| POST | `/api/accounts/google/callback` | Exchange OAuth code → JWT tokens + user |
| GET | `/api/accounts/me` | Get current user profile |
| POST | `/api/accounts/logout` | Blacklist refresh token |
| POST | `/api/accounts/token/refresh` | Refresh JWT access token |

### Gmail (`/api/gmail/`)
| Method | URL | Description |
|--------|-----|-------------|
| GET | `/api/gmail/emails/` | List all scanned emails (Dashboard table) |
| GET | `/api/gmail/emails/stats/` | Stats cards + threat distribution |
| GET | `/api/gmail/emails/{id}/` | Full email detail (EmailDetail.tsx) |
| POST | `/api/gmail/scan/` | Trigger rescan ("Rescan" button) |
| GET | `/api/gmail/auth/init/` | Start Gmail OAuth flow |
| GET | `/api/gmail/auth/callback/` | Gmail OAuth callback |
| DELETE | `/api/gmail/auth/disconnect/` | Disconnect Gmail account |
| GET | `/api/gmail/auth/status/` | Check Gmail connection status |

### Dashboard (`/api/dashboard/`)
| Method | URL | Description |
|--------|-----|-------------|
| GET | `/api/dashboard/` | Full dashboard: stats + emails + distribution |
| POST | `/api/dashboard/rescan/` | Trigger rescan, record ScanRun |

### Analysis (`/api/analysis/`)
| Method | URL | Description |
|--------|-----|-------------|
| POST | `/api/analysis/analyse/` | Analyse email with Gemini (cached) |
| GET | `/api/analysis/{gmail_message_id}/` | Get cached analysis |
| POST | `/api/analysis/batch/` | Bulk fetch cached analyses |

### Reputation (`/api/reputation/`)
| Method | URL | Description |
|--------|-----|-------------|
| GET | `/api/reputation/{domain}/` | Domain reputation lookup |
| POST | `/api/reputation/bulk/` | Batch domain lookup |
| GET | `/api/reputation/{domain}/raw/` | Raw VirusTotal data |

### Emails (`/api/emails/`)
| Method | URL | Description |
|--------|-----|-------------|
| GET | `/api/emails/` | Email list |
| GET | `/api/emails/{id}/` | Email detail |
| POST | `/api/emails/{id}/mark-read/` | Mark as read |
| GET | `/api/emails/search/` | Search emails |
| POST | `/api/emails/ingest/` | Internal: ingest raw Gmail message |

### Threats (`/api/threats/`)
| Method | URL | Description |
|--------|-----|-------------|
| GET | `/api/threats/emails/{id}/threat/` | Threat score for email |
| GET | `/api/threats/threats/stats/` | Threat stats |

## Frontend Contract

The frontend (`EmailAnalysis` TypeScript interface) expects these exact JSON field names:

```typescript
interface EmailAnalysis {
  id: string;
  subject: string;
  sender: string;
  senderName: string;
  domain: string;
  date: string;             // ISO 8601
  body: string;
  domainAge: string;        // e.g. "4 days", "6 years"
  domainReputation: "Trusted" | "Suspicious" | "Malicious";
  lookalikeDomain: string | null;
  urgency: number;          // 0-100
  fear: number;             // 0-100
  credentialTheft: number;  // 0-100
  financialFraud: number;   // 0-100
  authorityImpersonation: number; // 0-100
  aiSummary: string;
  aiScore: number;          // 0-100
  domainScore: number;      // 0-100
  threatScore: number;      // aiScore*0.7 + domainScore*0.3
  riskLevel: "Critical" | "High" | "Medium" | "Safe";
}
```

The **primary API** for the frontend is `/api/gmail/` — it returns emails in this exact shape, serving both the Dashboard list and the EmailDetail view.

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set environment variables (copy .env.example to .env and fill in)
cp .env.example .env

# 3. Run migrations
python manage.py migrate

# 4. Start development server
python manage.py runserver

# 5. Create superuser (optional)
python manage.py createsuperuser
```

## Architecture

```
Frontend (React/Vite)
    │ JWT Bearer Token
    ▼
Django REST API
    ├── /api/accounts/   → JWT auth via Google OAuth
    ├── /api/gmail/      → PRIMARY: email list/detail/scan
    │       ├── Gmail API (fetch raw emails)
    │       ├── Domain Analysis (WHOIS + lookalike detection)
    │       └── AI Analysis (Gemini 1.5 Flash / heuristic fallback)
    ├── /api/dashboard/  → Aggregated stats + rescan
    ├── /api/analysis/   → Gemini analysis cache
    ├── /api/reputation/ → VirusTotal domain cache
    ├── /api/emails/     → Raw email storage
    └── /api/threats/    → Threat score aggregation
```

## Key Design Decisions

1. **`apps.gmail` is the master source** — `EmailMessage` model stores all frontend-facing fields with camelCase names matching TypeScript exactly, so serializers need zero renaming.

2. **Heuristic fallback** — Both AI analysis and domain reputation gracefully degrade when API keys are absent. The system works without Gemini or VirusTotal configured.

3. **App independence** — Apps communicate via Django models and internal service calls, never via tight view coupling.

4. **Frontend-first field names** — All camelCase fields in the DB (`senderName`, `domainAge`, `riskLevel`, etc.) ensure the JSON output exactly matches the frontend TypeScript interface.
