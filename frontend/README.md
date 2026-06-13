# BizGuard — Frontend ↔ Django Integration

Цей пакет замінює mock-дані реальними API-запитами до Django бекенду.

---

## Що змінено

| Файл | Що зроблено |
|------|-------------|
| `src/api/client.ts` | **Новий** — базовий HTTP-клієнт з JWT, авто-рефрешем токена |
| `src/api/auth.ts` | **Новий** — `/api/accounts/` ендпоінти (login, me, logout) |
| `src/api/gmail.ts` | **Новий** — `/api/gmail/` ендпоінти (emails, stats, scan) |
| `src/app/hooks/useAuth.ts` | **Новий** — хук стану авторизації |
| `src/app/components/AuthCallback.tsx` | **Новий** — обробляє `/auth/callback?code=...` від Google |
| `src/app/App.tsx` | **Замінений** — реальний auth flow замість `useState("login")` |
| `src/app/components/Dashboard.tsx` | **Замінений** — `mockEmails` → `fetchEmails()` + `fetchEmailStats()` |
| `src/app/components/EmailDetail.tsx` | **Замінений** — prop `email` → `emailId`, завантажує через API |
| `src/app/components/LoginPage.tsx` | **Оновлений** — додано `errorMessage` prop |
| `vite.config.ts` | **Оновлений** — proxy `/api → http://localhost:8000` |

---

## Встановлення

### 1. Скопіюй файли

```
# Замінити існуючі файли у фронтенді:
cp src/api/client.ts         <frontend>/src/api/client.ts
cp src/api/auth.ts           <frontend>/src/api/auth.ts
cp src/api/gmail.ts          <frontend>/src/api/gmail.ts
cp src/app/hooks/useAuth.ts  <frontend>/src/app/hooks/useAuth.ts
cp src/app/components/AuthCallback.tsx  <frontend>/src/app/components/AuthCallback.tsx
cp src/app/App.tsx           <frontend>/src/app/App.tsx
cp src/app/components/Dashboard.tsx    <frontend>/src/app/components/Dashboard.tsx
cp src/app/components/EmailDetail.tsx  <frontend>/src/app/components/EmailDetail.tsx
cp src/app/components/LoginPage.tsx    <frontend>/src/app/components/LoginPage.tsx
cp vite.config.ts            <frontend>/vite.config.ts
```

### 2. Налаштуй Django бекенд

```bash
cd bizguard/

# Скопіюй .env файл
cp .env.example .env

# Встанови залежності
pip install -r requirements.txt

# Запусти міграції
python manage.py migrate

# Запусти сервер
python manage.py runserver 8000
```

### 3. Запусти фронтенд

```bash
cd frontend/
pnpm install    # або npm install
pnpm dev        # Запуститься на http://localhost:5173
```

Vite автоматично проксує `/api/*` → `http://localhost:8000`.

---

## Google OAuth налаштування

У `.env` потрібно вказати:

```env
GOOGLE_OAUTH_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_OAUTH_CLIENT_SECRET=your-client-secret
GOOGLE_OAUTH_REDIRECT_URI=http://localhost:5173/auth/callback
```

У Google Cloud Console додай Authorized redirect URI:
```
http://localhost:5173/auth/callback
```

---

## Як працює auth flow

```
1. Користувач натискає "Continue with Google"
   → handleLogin() → GET /api/accounts/google/url
   → Редірект на Google consent screen

2. Google редіректить на http://localhost:5173/auth/callback?code=...
   → AuthCallback.tsx перехоплює URL
   → POST /api/accounts/google/callback { code, redirect_uri }
   → Django: обмін code → tokens → повертає { access, refresh, user }
   → Токени зберігаються в localStorage

3. Наступні запити: Authorization: Bearer <access_token>
   → 401 → авто-рефреш через /api/accounts/token/refresh
   → При помилці рефрешу → clear localStorage → reload
```

---

## Продакшн (Nginx + Gunicorn)

```nginx
server {
    listen 80;
    root /path/to/frontend/dist;

    # Фронтенд (React SPA)
    location / {
        try_files $uri $uri/ /index.html;
    }

    # API проксі до Django
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

```bash
# Збірка фронтенду
pnpm build

# Запуск Django через gunicorn
gunicorn config.wsgi:application --bind 0.0.0.0:8000
```

У продакшн `.env` змінити:
```env
DEBUG=False
ALLOWED_HOSTS=yourdomain.com
CORS_ALLOWED_ORIGINS=https://yourdomain.com
GOOGLE_OAUTH_REDIRECT_URI=https://yourdomain.com/auth/callback
```
