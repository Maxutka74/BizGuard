# BizGuard frontend apps

- `apps/bizguard-app` - main BizGuard application with license gate and Gmail OAuth scope.
- `apps/purchase-site` - purchase site with public Google OAuth (`openid email profile`) and no Gmail access.

## Local URLs

- Purchase site: http://localhost:5174
- BizGuard app: http://localhost:5173
- Backend API: http://localhost:8000

## Start everything with Docker Compose

```powershell
docker compose up -d --build
docker compose exec backend python manage.py migrate
```

## Billing / Stripe test mode

Business keys are sold as one license key with `activationCount` seats.

Plan prices:

- `free_1_day`: 0 UAH, 1 activation only.
- `half_year`: 499 UAH base + 50 UAH per extra activation.
- `year`: 899 UAH base + 80 UAH per extra activation.

Paid plans redirect to Stripe Checkout when `BILLING_FAKE_MODE=False`. Free plan creates a direct local checkout session.

```env
BILLING_FAKE_MODE=False
STRIPE_SECRET_KEY=sk_test_...
PURCHASE_SITE_URL=http://localhost:5174
```

Stripe test card: `4242 4242 4242 4242`, any future date, any CVC.

## Google OAuth redirect URIs

Add these in Google Cloud Console:

```text
http://localhost:5173/auth/callback
http://localhost:5174/auth/callback
http://localhost:8000/api/accounts/google/public-redirect
```

Purchase site login uses the backend redirect endpoint by default. BizGuard app still uses Gmail scope and license gate.