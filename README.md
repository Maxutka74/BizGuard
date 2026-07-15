# BizGuard

BizGuard - сервіс для захисту Gmail від фішингу, шахрайства, небезпечних URL і вкладень. Проєкт складається зі спільного Django backend, основного BizGuard app з license gate та окремого purchase site для покупки бізнес-ключів.

## Структура

- `backend/` - Django REST API, Google OAuth, Gmail scan, license keys, billing, Celery tasks.
- `apps/bizguard-app/` - основний застосунок BizGuard на `http://localhost:5173`.
- `apps/purchase-site/` - сайт покупки ключів на `http://localhost:5174`.
- `docker-compose.yml` - Postgres, Redis, backend, Celery, AI worker, Celery Beat і два frontend dev servers.

## Локальний запуск

```powershell
docker compose up -d --build
docker compose exec backend python manage.py migrate
```

URL:

- Purchase site: `http://localhost:5174`
- BizGuard app: `http://localhost:5173`
- Backend API: `http://localhost:8000`

Логи:

```powershell
docker compose logs -f backend celery_worker celery_ai_worker bizguard_app purchase_site
```

Зупинка:

```powershell
docker compose down
```

## AI analysis

`celery_ai_worker` запускається разом зі звичайним compose, тому pending-листи не мають зависати без worker. Якщо локальна AI-модель Ollama недоступна, backend завершує лист deterministic fallback verdict/recommendations і не блокує весь batch.

Для повного local AI з Ollama запусти профіль:

```powershell
docker compose --profile local-ai up -d --build ollama ollama_pull celery_ai_worker
```

Після цього натисни scan у BizGuard app або запусти queue через backend. Один повільний лист не блокує інші: timeout/pending reputation відкладається, batch іде далі, а лист отримує fallback після повторної невдалої спроби.

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

Purchase site використовує тільки `openid email profile` і не потребує license key. Основний BizGuard app використовує Gmail scope, тому Google акаунт має бути тестовим користувачем у local/test mode або додаток має пройти Google verification для production.

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

Дата - будь-яка майбутня, CVC - будь-який.

## Як купити й активувати ключ

1. Відкрий purchase site: `http://localhost:5174`.
2. Увійди через Google.
3. Обери тариф і кількість активацій.
4. Оплати через Stripe Checkout test mode.
5. На success screen скопіюй plaintext key. Повністю ключ показується тільки один раз.
6. Відкрий BizGuard app: `http://localhost:5173`.
7. Введи ключ перед Gmail login і підключи Google акаунт.

Seat-based логіка: той самий Google акаунт може входити повторно в межах строку дії ключа без списання нового місця. Інший Google акаунт списує одну активацію. Якщо місця вичерпані, новий акаунт отримає `activation_limit_reached`.

## Тарифи BizGuard

- Free: ручна перевірка останніх 5 листів, 1 день, без background monitoring.
- Half-year: 15 листів, monitoring кожні 30 хв, auto-spam для Critical, High/Critical alerts.
- Year: 30 листів, monitoring кожні 15 хв, priority AI, auto-spam для Critical, trusted sender/domain allowlist.

## Перевірки

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

## Безпека секретів

`.env`, `*.env`, Stripe keys, Google client secret, локальні бази, build artifacts і `node_modules` не мають потрапляти в git. Перед commit перевіряй:

```powershell
git status --short
```
