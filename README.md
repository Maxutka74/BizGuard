# BizGuard

BizGuard — сервіс для захисту Gmail від фішингу, шахрайства, небезпечних URL і вкладень. Проєкт складається зі спільного Django backend, основного BizGuard app із license gate та окремого purchase site для покупки бізнес-ключів.

## Структура

- `backend/` — Django REST API, Google OAuth, Gmail scan, ліцензії, billing, Celery tasks.
- `apps/bizguard-app/` — основний застосунок BizGuard на `http://localhost:5173`.
- `apps/purchase-site/` — сайт покупки ключів на `http://localhost:5174`.
- `docker-compose.yml` — Postgres, Redis, backend, Celery, обидва frontend dev servers.

## Локальний запуск

```powershell
docker compose up -d --build
docker compose exec backend python manage.py migrate
```

URL:

- Purchase site: http://localhost:5174
- BizGuard app: http://localhost:5173
- Backend API: http://localhost:8000

Логи:

```powershell
docker compose logs -f backend bizguard_app purchase_site
```

Зупинка:

```powershell
docker compose down
```

## Google OAuth

У Google Cloud Console для OAuth Client додай Authorized JavaScript origins:

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

Purchase site використовує тільки `openid email profile`. Основний BizGuard app використовує Gmail scope і потребує license key перед Gmail login.

## Stripe test billing

Purchase site продає один бізнес-ключ на потрібну кількість активацій.

Ціни:

- `free_1_day`: 0 грн, тільки 1 активація.
- `half_year`: 499 грн база за першу активацію + 50 грн за кожну додаткову.
- `year`: 899 грн база за першу активацію + 80 грн за кожну додаткову.

Формула:

```text
total = base + max(0, activationCount - 1) * extraSeatPrice
```

Для Stripe test mode створи `.env` у корені проєкту:

```env
BILLING_FAKE_MODE=False
STRIPE_SECRET_KEY=sk_test_...
PURCHASE_SITE_URL=http://localhost:5174
```

Після зміни `.env` пересоздай backend:

```powershell
docker compose up -d --force-recreate backend
```

Тестова карта Stripe:

```text
4242 4242 4242 4242
```

Дата — будь-яка майбутня, CVC — будь-який.

## Як купити й активувати ключ

1. Відкрий purchase site: http://localhost:5174.
2. Увійди через Google.
3. Обери тариф і кількість активацій.
4. Оплати через Stripe Checkout test mode.
5. На success screen скопіюй plaintext ключ. Повністю він показується тільки один раз.
6. Відкрий BizGuard app: http://localhost:5173.
7. Введи ключ перед Gmail login і підключи Google акаунт.

## Перевірки

Backend:

```powershell
docker compose exec backend python manage.py check
docker compose exec backend python manage.py test apps.billing.tests apps.licenses.tests
```

Frontend:

```powershell
npm.cmd run build --prefix apps/purchase-site
npm.cmd run build --prefix apps/bizguard-app
```

## Безпека секретів

`.env`, `*.env`, Stripe keys, Google client secret і локальні артефакти не мають потрапляти в git. Перед commit перевіряй:

```powershell
git status --short
```