# Google OAuth: Local/Test mode і Production

## Local/Test mode

Для локального BizGuard без публічного домену Google OAuth має працювати у режимі `Testing`.

Що потрібно:

1. У Google Cloud Console відкрий project із `GOOGLE_OAUTH_CLIENT_ID` BizGuard.
2. Перейди в `Google Auth Platform` -> `Audience`.
3. Залиши `Publishing status = Testing`.
4. У `Test users` додай Gmail акаунти, якими будеш входити локально.
5. У OAuth Client додай redirect URI:
   - для BizGuard app: `http://localhost:5173/auth/callback`
   - для purchase site: `http://localhost:8000/api/accounts/google/public-redirect`
6. У backend `.env` локально тримай:
   - `GOOGLE_OAUTH_REDIRECT_URI=http://localhost:5173/auth/callback`
   - `GOOGLE_PUBLIC_OAUTH_REDIRECT_URI=http://localhost:8000/api/accounts/google/public-redirect`
   - `FRONTEND_URL=http://localhost:5173`
   - `PURCHASE_SITE_URL=http://localhost:5174`
7. Якщо Google показує `Експерти Google не перевірили цей додаток`, відкрий додаткові налаштування і продовж до BizGuard. Це нормально для localhost + Gmail restricted scope.

BizGuard лишає `gmail.modify`, бо без нього не буде читання листів і auto-spam для Critical листів.

## Production verification

Цей чеклист виправляє помилку Google:

`Доступ заблоковано: додаток BizGuard не пройшов процедуру підтвердження від Google` / `Error 403: access_denied`.

## Що означає ця помилка

Це не помилка Django або React. Google блокує авторизацію ще до callback у BizGuard, бо OAuth consent screen у Google Cloud знаходиться у режимі `Testing`. У цьому режимі можуть входити тільки акаунти з `Test users`.

## Що зробити зараз

1. Відкрий Google Cloud Console і вибери project, де створений `GOOGLE_OAUTH_CLIENT_ID` BizGuard.
2. Перейди в `Google Auth Platform` або `APIs & Services` -> `OAuth consent screen`.
3. У `Audience` / `User type` вибери `External`, якщо мають входити звичайні Gmail/Google акаунти.
4. Заповни branding: назва додатка, support email, developer email, production domain, privacy policy.
5. У `Publishing status` натисни `Publish app` / `Push to production`.
6. Якщо Google далі блокує через `gmail.modify`, подай app на Google OAuth verification і security assessment для restricted Gmail scope.

Поки app лишається у `Testing`, звичайний акаунт на кшталт `tiktoknik520@gmail.com` не увійде, якщо його немає в `Test users`. Це обмеження Google, а не BizGuard.
## Як вимкнути testing mode

1. Відкрий Google Cloud Console.
2. Вибери той самий project, де створений `GOOGLE_OAUTH_CLIENT_ID` для BizGuard.
3. Перейди в `APIs & Services` -> `OAuth consent screen`.
4. Перевір `User type`:
   - `External`, якщо мають входити будь-які Gmail/Google акаунти.
   - `Internal` працює тільки для акаунтів твого Google Workspace домену.
5. Заповни обов'язкові поля consent screen:
   - App name: `BizGuard`.
   - User support email.
   - Developer contact email.
   - Authorized domains для production домену.
6. У секції `Publishing status` натисни `Publish app` / `Push to production`.
7. Перевір OAuth client:
   - `APIs & Services` -> `Credentials` -> твій OAuth 2.0 Client ID.
   - Authorized JavaScript origins: production frontend origin, наприклад `https://yourdomain.com`.
   - Authorized redirect URIs: `https://yourdomain.com/auth/callback`.
8. У `.env` backend вистав:

```env
GOOGLE_OAUTH_CLIENT_ID=your-production-client-id.apps.googleusercontent.com
GOOGLE_OAUTH_CLIENT_SECRET=your-production-client-secret
GOOGLE_OAUTH_REDIRECT_URI=https://yourdomain.com/auth/callback
CORS_ALLOWED_ORIGINS=https://yourdomain.com
CSRF_TRUSTED_ORIGINS=https://yourdomain.com
DEBUG=False
```

## Важливо про Gmail scopes

BizGuard зараз просить `https://www.googleapis.com/auth/gmail.modify`, бо paid plans мають auto-spam для Critical листів. Це restricted Gmail scope. Для повністю публічного production доступу Google може вимагати OAuth app verification, а для restricted scopes також security assessment.

Поки verification не завершений, варіанти такі:

- Тимчасово додавати потрібні акаунти в `Test users`.
- Опублікувати app у production, щоб прибрати саме test-user lock.
- Пройти Google OAuth verification для Gmail restricted scope.
- Якщо auto-spam не потрібен на ранньому production етапі, можна окремо зробити режим без `gmail.modify`, але тоді перенесення Critical листів у Spam працювати не буде.

## Що вже зроблено в коді

- Backend не має whitelist по email.
- Google login URL примусово відкриває вибір акаунта через `prompt=select_account consent`.
- Gmail reconnect flow теж відкриває вибір акаунта через `prompt=select_account consent`.

## Official references

- Google OAuth app verification requirements: https://support.google.com/cloud/answer/13464321
- Google Auth Platform branding and audience: https://support.google.com/cloud/answer/15549049
- Gmail API scopes and sensitivity: https://developers.google.com/workspace/gmail/api/auth/scopes

