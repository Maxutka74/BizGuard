# BizGuard

BizGuard - СЃРµСЂРІС–СЃ РґР»СЏ Р·Р°С…РёСЃС‚Сѓ Gmail РІС–Рґ С„С–С€РёРЅРіСѓ, С€Р°С…СЂР°Р№СЃС‚РІР°, РЅРµР±РµР·РїРµС‡РЅРёС… URL С– РІРєР»Р°РґРµРЅСЊ. РџСЂРѕС”РєС‚ СЃРєР»Р°РґР°С”С‚СЊСЃСЏ Р·С– СЃРїС–Р»СЊРЅРѕРіРѕ Django backend, РѕСЃРЅРѕРІРЅРѕРіРѕ BizGuard app Р· license gate С‚Р° РѕРєСЂРµРјРѕРіРѕ purchase site РґР»СЏ РїРѕРєСѓРїРєРё Р±С–Р·РЅРµСЃ-РєР»СЋС‡С–РІ.

## РЎС‚СЂСѓРєС‚СѓСЂР°

- `backend/` - Django REST API, Google OAuth, Gmail scan, license keys, billing, Celery tasks.
- `apps/bizguard-app/` - РѕСЃРЅРѕРІРЅРёР№ Р·Р°СЃС‚РѕСЃСѓРЅРѕРє BizGuard РЅР° `http://localhost:5173`.
- `apps/purchase-site/` - СЃР°Р№С‚ РїРѕРєСѓРїРєРё РєР»СЋС‡С–РІ РЅР° `http://localhost:5174`.
- `docker-compose.yml` - Postgres, Redis, backend, Celery, AI worker, Celery Beat С– РґРІР° frontend dev servers.

## Р›РѕРєР°Р»СЊРЅРёР№ Р·Р°РїСѓСЃРє

```powershell
docker compose up -d --build
docker compose exec backend python manage.py migrate
```

URL:

- Purchase site: `http://localhost:5174`
- BizGuard app: `http://localhost:5173`
- Backend API: `http://localhost:8000`

Р›РѕРіРё:

```powershell
docker compose logs -f backend celery_worker celery_ai_worker bizguard_app purchase_site
```

Р—СѓРїРёРЅРєР°:

```powershell
docker compose down
```

## AI analysis

`celery_ai_worker` Р·Р°РїСѓСЃРєР°С”С‚СЊСЃСЏ СЂР°Р·РѕРј Р·С– Р·РІРёС‡Р°Р№РЅРёРј compose, С‚РѕРјСѓ pending-Р»РёСЃС‚Рё РЅРµ РјР°СЋС‚СЊ Р·Р°РІРёСЃР°С‚Рё Р±РµР· worker. РЇРєС‰Рѕ Р»РѕРєР°Р»СЊРЅР° AI-РјРѕРґРµР»СЊ Ollama РЅРµРґРѕСЃС‚СѓРїРЅР°, backend Р·Р°РІРµСЂС€СѓС” Р»РёСЃС‚ deterministic fallback verdict/recommendations С– РЅРµ Р±Р»РѕРєСѓС” РІРµСЃСЊ batch.

Р”Р»СЏ РїРѕРІРЅРѕРіРѕ local AI Р· Ollama Р·Р°РїСѓСЃС‚Рё РїСЂРѕС„С–Р»СЊ:

```powershell
docker compose --profile local-ai up -d --build ollama ollama_pull celery_ai_worker
```

РџС–СЃР»СЏ С†СЊРѕРіРѕ РЅР°С‚РёСЃРЅРё scan Сѓ BizGuard app Р°Р±Рѕ Р·Р°РїСѓСЃС‚Рё queue С‡РµСЂРµР· backend. РћРґРёРЅ РїРѕРІС–Р»СЊРЅРёР№ Р»РёСЃС‚ РЅРµ Р±Р»РѕРєСѓС” С–РЅС€С–: timeout/pending reputation РІС–РґРєР»Р°РґР°С”С‚СЊСЃСЏ, batch С–РґРµ РґР°Р»С–, Р° Р»РёСЃС‚ РѕС‚СЂРёРјСѓС” fallback РїС–СЃР»СЏ РїРѕРІС‚РѕСЂРЅРѕС— РЅРµРІРґР°Р»РѕС— СЃРїСЂРѕР±Рё.

## Google OAuth

РЈ Google Cloud Console РґР»СЏ OAuth Client РґРѕРґР°Р№ Authorized JavaScript origins:

```text
http://localhost:5173
http://localhost:5174
```

Authorized redirect URIs:

```text
http://localhost:5173/auth/callback
http://localhost:5174/auth/callback
http://localhost:8000/api/accounts/google/public-redirect
http://localhost:8000/api/gmail/auth/callback/
```

Purchase site РІРёРєРѕСЂРёСЃС‚РѕРІСѓС” С‚С–Р»СЊРєРё `openid email profile` С– РЅРµ РїРѕС‚СЂРµР±СѓС” license key. РћСЃРЅРѕРІРЅРёР№ BizGuard app РІРёРєРѕСЂРёСЃС‚РѕРІСѓС” Gmail scope, С‚РѕРјСѓ Google Р°РєР°СѓРЅС‚ РјР°С” Р±СѓС‚Рё С‚РµСЃС‚РѕРІРёРј РєРѕСЂРёСЃС‚СѓРІР°С‡РµРј Сѓ local/test mode Р°Р±Рѕ РґРѕРґР°С‚РѕРє РјР°С” РїСЂРѕР№С‚Рё Google verification РґР»СЏ production.

## Stripe test billing

Purchase site РїСЂРѕРґР°С” РѕРґРёРЅ Р±С–Р·РЅРµСЃ-РєР»СЋС‡ РЅР° РїРѕС‚СЂС–Р±РЅСѓ РєС–Р»СЊРєС–СЃС‚СЊ Р°РєС‚РёРІР°С†С–Р№.

Р¦С–РЅРё:

- `free_1_day`: 0 РіСЂРЅ, С‚С–Р»СЊРєРё 1 Р°РєС‚РёРІР°С†С–СЏ.
- `half_year`: 499 РіСЂРЅ Р±Р°Р·Р° Р·Р° РїРµСЂС€Сѓ Р°РєС‚РёРІР°С†С–СЋ + 50 РіСЂРЅ Р·Р° РєРѕР¶РЅСѓ РґРѕРґР°С‚РєРѕРІСѓ.
- `year`: 899 РіСЂРЅ Р±Р°Р·Р° Р·Р° РїРµСЂС€Сѓ Р°РєС‚РёРІР°С†С–СЋ + 80 РіСЂРЅ Р·Р° РєРѕР¶РЅСѓ РґРѕРґР°С‚РєРѕРІСѓ.

Р¤РѕСЂРјСѓР»Р°:

```text
total = base + max(0, activationCount - 1) * extraSeatPrice
```

Р”Р»СЏ Stripe test mode СЃС‚РІРѕСЂРё `.env` Сѓ РєРѕСЂРµРЅС– РїСЂРѕС”РєС‚Сѓ:

```env
BILLING_FAKE_MODE=False
STRIPE_SECRET_KEY=sk_test_...
PURCHASE_SITE_URL=http://localhost:5174
```

РџС–СЃР»СЏ Р·РјС–РЅРё `.env` РїРµСЂРµСЃРѕР·РґР°Р№ backend:

```powershell
docker compose up -d --force-recreate backend
```

РўРµСЃС‚РѕРІР° РєР°СЂС‚Р° Stripe:

```text
4242 4242 4242 4242
```

Р”Р°С‚Р° - Р±СѓРґСЊ-СЏРєР° РјР°Р№Р±СѓС‚РЅСЏ, CVC - Р±СѓРґСЊ-СЏРєРёР№.

## РЇРє РєСѓРїРёС‚Рё Р№ Р°РєС‚РёРІСѓРІР°С‚Рё РєР»СЋС‡

1. Р’С–РґРєСЂРёР№ purchase site: `http://localhost:5174`.
2. РЈРІС–Р№РґРё С‡РµСЂРµР· Google.
3. РћР±РµСЂРё С‚Р°СЂРёС„ С– РєС–Р»СЊРєС–СЃС‚СЊ Р°РєС‚РёРІР°С†С–Р№.
4. РћРїР»Р°С‚Рё С‡РµСЂРµР· Stripe Checkout test mode.
5. РќР° success screen СЃРєРѕРїС–СЋР№ plaintext key. РџРѕРІРЅС–СЃС‚СЋ РєР»СЋС‡ РїРѕРєР°Р·СѓС”С‚СЊСЃСЏ С‚С–Р»СЊРєРё РѕРґРёРЅ СЂР°Р·.
6. Р’С–РґРєСЂРёР№ BizGuard app: `http://localhost:5173`.
7. Р’РІРµРґРё РєР»СЋС‡ РїРµСЂРµРґ Gmail login С– РїС–РґРєР»СЋС‡Рё Google Р°РєР°СѓРЅС‚.

Seat-based Р»РѕРіС–РєР°: С‚РѕР№ СЃР°РјРёР№ Google Р°РєР°СѓРЅС‚ РјРѕР¶Рµ РІС…РѕРґРёС‚Рё РїРѕРІС‚РѕСЂРЅРѕ РІ РјРµР¶Р°С… СЃС‚СЂРѕРєСѓ РґС–С— РєР»СЋС‡Р° Р±РµР· СЃРїРёСЃР°РЅРЅСЏ РЅРѕРІРѕРіРѕ РјС–СЃС†СЏ. Р†РЅС€РёР№ Google Р°РєР°СѓРЅС‚ СЃРїРёСЃСѓС” РѕРґРЅСѓ Р°РєС‚РёРІР°С†С–СЋ. РЇРєС‰Рѕ РјС–СЃС†СЏ РІРёС‡РµСЂРїР°РЅС–, РЅРѕРІРёР№ Р°РєР°СѓРЅС‚ РѕС‚СЂРёРјР°С” `activation_limit_reached`.

## РўР°СЂРёС„Рё BizGuard

- Free: СЂСѓС‡РЅР° РїРµСЂРµРІС–СЂРєР° РѕСЃС‚Р°РЅРЅС–С… 5 Р»РёСЃС‚С–РІ, 1 РґРµРЅСЊ, Р±РµР· background monitoring.
- Half-year: 15 Р»РёСЃС‚С–РІ, monitoring РєРѕР¶РЅС– 30 С…РІ, auto-spam РґР»СЏ Critical, High/Critical alerts.
- Year: 30 Р»РёСЃС‚С–РІ, monitoring РєРѕР¶РЅС– 15 С…РІ, priority AI, auto-spam РґР»СЏ Critical, trusted sender/domain allowlist.

## РџРµСЂРµРІС–СЂРєРё

Backend:

```powershell
docker compose exec backend python manage.py check
docker compose exec backend python manage.py test apps.gmail.tests.test_security_pipeline apps.licenses.tests apps.accounts.tests apps.billing.tests --keepdb
```

Frontend:

```powershell
npm.cmd run build --prefix apps/bizguard-app
npm.cmd run build --prefix apps/purchase-site
```

NPM audit:

```powershell
npm.cmd audit --omit=dev --prefix apps/bizguard-app
npm.cmd audit --omit=dev --prefix apps/purchase-site
```

## Р‘РµР·РїРµРєР° СЃРµРєСЂРµС‚С–РІ

`.env`, `*.env`, Stripe keys, Google client secret, Р»РѕРєР°Р»СЊРЅС– Р±Р°Р·Рё, build artifacts С– `node_modules` РЅРµ РјР°СЋС‚СЊ РїРѕС‚СЂР°РїР»СЏС‚Рё РІ git. РџРµСЂРµРґ commit РїРµСЂРµРІС–СЂСЏР№:

```powershell
git status --short
```
