import React, { useEffect, useMemo, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import {
  ArrowRight,
  Check,
  Copy,
  CreditCard,
  KeyRound,
  LockKeyhole,
  LogOut,
  MailCheck,
  Minus,
  Plus,
  ShieldCheck,
  Sparkles,
  UserCircle,
} from 'lucide-react'
import './styles.css'

type Tab = 'home' | 'plans' | 'profile'
type PlanId = 'free_1_day' | 'half_year' | 'year'

type User = {
  id: string
  email: string
  first_name?: string
  last_name?: string
  picture?: string | null
}

type Order = {
  id: string
  plan: PlanId
  planLabel: string
  provider: string
  provider_session_id?: string | null
  status: 'pending' | 'paid' | 'canceled' | 'failed'
  amount: number
  baseAmount: number
  extraSeatAmount: number
  unitExtraSeatAmount: number
  activationCount: number
  currency: string
  generatedLicense?: null | {
    keyPrefix: string
    plan: string
    planLabel: string
    maxActivations: number
    activationCount: number
    remainingActivations: number
  }
  createdAt: string
  paidAt?: string | null
}

type ProfilePayload = {
  user: { id: string; email: string; name?: string; avatar?: string | null }
  orders: Order[]
}

const BIZGUARD_APP_URL = import.meta.env.VITE_BIZGUARD_APP_URL || 'http://localhost:5173'
const LEGACY_REDIRECT_URI = `${window.location.origin}/auth/callback`
const MAX_ACTIVATIONS = 1000

const plans: Array<{
  id: PlanId
  title: string
  price: string
  period: string
  badge: string
  description: string
  features: string[]
  accent: 'soft' | 'blue' | 'green'
  baseAmount: number
  extraSeatAmount: number
}> = [
  {
    id: 'free_1_day',
    title: 'Free',
    price: '0 грн',
    period: '1 день доступу',
    badge: 'Тест сервісу',
    description: 'Швидко спробувати BizGuard на невеликій кількості листів.',
    accent: 'soft',
    baseAmount: 0,
    extraSeatAmount: 0,
    features: ['1 активація', '5 останніх листів', 'Ручна перевірка Gmail', 'Базовий AI-вердикт', 'Без real-time моніторингу'],
  },
  {
    id: 'half_year',
    title: '6 місяців',
    price: '499 грн',
    period: 'пів року захисту',
    badge: 'Оптимальний старт',
    description: 'Регулярний захист для особистої пошти та малих команд.',
    accent: 'blue',
    baseAmount: 49900,
    extraSeatAmount: 5000,
    features: ['15 останніх листів', 'Моніторинг кожні 30 хв', 'Auto-spam для Critical', 'Панель High/Critical загроз'],
  },
  {
    id: 'year',
    title: '1 рік',
    price: '899 грн',
    period: 'максимальний захист',
    badge: 'Найкращий вибір',
    description: 'Пріоритетний AI-аналіз, allowlist і глибша перевірка загроз.',
    accent: 'green',
    baseAmount: 89900,
    extraSeatAmount: 8000,
    features: ['30 останніх листів', 'Моніторинг кожні 15 хв', 'Priority AI batch', 'Дозволені домени та allowlist'],
  },
]

let csrfToken: string | null = null

async function apiFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  const method = (options.method || 'GET').toUpperCase()
  const headers = new Headers(options.headers || {})
  if (!(options.body instanceof FormData)) headers.set('Content-Type', 'application/json')
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    csrfToken = csrfToken || (await getCsrf())
    if (csrfToken) headers.set('X-CSRFToken', csrfToken)
  }
  const response = await fetch(path, { ...options, headers, credentials: 'include' })
  if (!response.ok) {
    let message = 'Запит не виконано. Спробуйте ще раз.'
    try {
      const data = await response.json()
      message = data.detail || message
    } catch {
      // ignore non-json responses
    }
    throw new Error(message)
  }
  return response.json()
}

async function getCsrf() {
  const response = await fetch('/api/accounts/csrf', { credentials: 'include' })
  const data = await response.json()
  return data.csrfToken as string
}

function App() {
  const [activeTab, setActiveTab] = useState<Tab>('home')
  const [user, setUser] = useState<User | null>(null)
  const [orders, setOrders] = useState<Order[]>([])
  const [activationCounts, setActivationCounts] = useState<Record<PlanId, number>>({
    free_1_day: 1,
    half_year: 1,
    year: 1,
  })
  const [loading, setLoading] = useState(true)
  const [busyPlan, setBusyPlan] = useState<PlanId | null>(null)
  const [error, setError] = useState('')
  const [successKey, setSuccessKey] = useState<string | null>(null)
  const [successOrder, setSuccessOrder] = useState<Order | null>(null)
  const completingSessionRef = useRef<string | null>(null)
  const route = window.location.pathname

  const paidOrders = useMemo(() => orders.filter((order) => order.status === 'paid'), [orders])

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const auth = params.get('auth')
    const authError = params.get('auth_error')
    const state = params.get('state') || ''

    if (auth === 'success') {
      finishBackendGoogleLogin(state)
      return
    }
    if (authError) {
      handleBackendGoogleError(authError, state)
      return
    }
    if (route === '/auth/callback') {
      finishLegacyGoogleLogin()
      return
    }
    if (route === '/payment/success') {
      completePayment().finally(() => setLoading(false))
      return
    }
    restoreProfile().finally(() => setLoading(false))
  }, [])

  async function restoreProfile() {
    try {
      const me = await apiFetch<User>('/api/accounts/me')
      setUser(me)
      const profile = await apiFetch<ProfilePayload>('/api/billing/profile')
      setOrders(profile.orders)
    } catch {
      setUser(null)
      setOrders([])
    }
  }

  async function finishBackendGoogleLogin(returnedState: string) {
    setLoading(true)
    setError('')
    const expectedState = sessionStorage.getItem('purchase_oauth_state')
    if (expectedState && returnedState && returnedState !== expectedState) {
      setError('Google повернув неочікуваний state. Спробуйте увійти ще раз.')
      window.history.replaceState({}, '', '/')
      setLoading(false)
      return
    }

    window.history.replaceState({}, '', '/')
    await restoreProfile()
    const pendingPlan = sessionStorage.getItem('purchase_pending_plan') as PlanId | null
    const pendingCount = Number(sessionStorage.getItem('purchase_pending_activation_count') || '1')
    const nextTab = (sessionStorage.getItem('purchase_next_tab') as Tab | null) || 'profile'
    sessionStorage.removeItem('purchase_oauth_state')
    sessionStorage.removeItem('purchase_pending_plan')
    sessionStorage.removeItem('purchase_pending_activation_count')
    sessionStorage.removeItem('purchase_next_tab')

    if (pendingPlan) {
      setActiveTab('plans')
      await startCheckout(pendingPlan, pendingCount)
    } else {
      setActiveTab(nextTab)
    }
    setLoading(false)
  }

  function handleBackendGoogleError(code: string, returnedState: string) {
    const expectedState = sessionStorage.getItem('purchase_oauth_state')
    if (expectedState && returnedState && returnedState !== expectedState) {
      setError('Google повернув неочікуваний state. Спробуйте увійти ще раз.')
    } else {
      setError(oauthErrorMessage(code))
    }
    sessionStorage.removeItem('purchase_oauth_state')
    sessionStorage.removeItem('purchase_pending_plan')
    sessionStorage.removeItem('purchase_pending_activation_count')
    sessionStorage.removeItem('purchase_next_tab')
    window.history.replaceState({}, '', '/')
    restoreProfile().finally(() => setLoading(false))
  }

  async function finishLegacyGoogleLogin() {
    setLoading(true)
    setError('')
    const params = new URLSearchParams(window.location.search)
    const code = params.get('code')
    const state = params.get('state')
    const expectedState = sessionStorage.getItem('purchase_oauth_state')
    if (!code) {
      setError('Google не повернув код авторизації.')
      window.history.replaceState({}, '', '/')
      setLoading(false)
      return
    }
    if (expectedState && state && state !== expectedState) {
      setError('Google повернув неочікуваний state. Спробуйте увійти ще раз.')
      window.history.replaceState({}, '', '/')
      setLoading(false)
      return
    }

    try {
      const payload = await apiFetch<{ user: User }>('/api/accounts/google/public-callback', {
        method: 'POST',
        body: JSON.stringify({ code, redirect_uri: LEGACY_REDIRECT_URI }),
      })
      setUser(payload.user)
      window.history.replaceState({}, '', '/')
      await restoreProfile()
      const pendingPlan = sessionStorage.getItem('purchase_pending_plan') as PlanId | null
      const pendingCount = Number(sessionStorage.getItem('purchase_pending_activation_count') || '1')
      sessionStorage.removeItem('purchase_oauth_state')
      sessionStorage.removeItem('purchase_pending_plan')
      sessionStorage.removeItem('purchase_pending_activation_count')
      sessionStorage.removeItem('purchase_next_tab')
      if (pendingPlan) {
        setActiveTab('plans')
        await startCheckout(pendingPlan, pendingCount)
      } else {
        setActiveTab('profile')
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Не вдалося увійти через Google.')
    } finally {
      setLoading(false)
    }
  }

  async function loginWithGoogle(nextTab: Tab = 'profile', pendingPlan?: PlanId, pendingActivationCount = 1) {
    setError('')
    const state = crypto.randomUUID ? crypto.randomUUID() : String(Date.now())
    sessionStorage.setItem('purchase_oauth_state', state)
    sessionStorage.setItem('purchase_next_tab', nextTab)
    if (pendingPlan) {
      sessionStorage.setItem('purchase_pending_plan', pendingPlan)
      sessionStorage.setItem('purchase_pending_activation_count', String(pendingActivationCount))
    }
    try {
      const payload = await apiFetch<{ url: string }>(`/api/accounts/google/public-url?state=${encodeURIComponent(state)}`)
      window.location.href = payload.url
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Не вдалося почати Google login.')
    }
  }

  async function logout() {
    await apiFetch('/api/accounts/logout', { method: 'POST', body: JSON.stringify({}) }).catch(() => null)
    setUser(null)
    setOrders([])
    setActiveTab('home')
  }

  async function buyPlan(plan: PlanId) {
    const activationCount = activationCounts[plan] || 1
    if (!user) {
      await loginWithGoogle('plans', plan, activationCount)
      return
    }
    await startCheckout(plan, activationCount)
  }

  async function startCheckout(plan: PlanId, activationCount = 1) {
    setBusyPlan(plan)
    setError('')
    try {
      const payload = await apiFetch<{ checkoutUrl: string }>('/api/billing/checkout', {
        method: 'POST',
        body: JSON.stringify({ plan, activationCount }),
      })
      window.location.href = payload.checkoutUrl
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Не вдалося створити оплату.')
      setBusyPlan(null)
    }
  }

  async function completePayment() {
    const sessionId = new URLSearchParams(window.location.search).get('session_id')
    if (!sessionId) {
      setLoading(false)
      return
    }
    if (completingSessionRef.current === sessionId) return
    completingSessionRef.current = sessionId
    setLoading(true)
    await restoreProfile()
    try {
      const payload = await apiFetch<{ order: Order; plaintextKey: string | null; alreadyCompleted: boolean }>(
        '/api/billing/complete',
        { method: 'POST', body: JSON.stringify({ sessionId }) },
      )
      if (payload.plaintextKey) setSuccessKey(payload.plaintextKey)
      setSuccessOrder(payload.order)
      await restoreProfile()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Не вдалося завершити оплату.')
    }
  }

  function goTab(tab: Tab) {
    if (window.location.pathname !== '/') window.history.replaceState({}, '', '/')
    setActiveTab(tab)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  function updateActivationCount(plan: PlanId, value: number) {
    const next = plan === 'free_1_day' ? 1 : Math.min(MAX_ACTIVATIONS, Math.max(1, Math.floor(value || 1)))
    setActivationCounts((current) => ({ ...current, [plan]: next }))
  }

  return (
    <main className="site-shell">
      <Header user={user} activeTab={activeTab} onTab={goTab} onLogin={() => loginWithGoogle()} onLogout={logout} />
      {error && <div className="notice error">{error}</div>}
      {loading ? <LoadingView /> : null}
      {!loading && route === '/payment/cancel' ? <CancelView onPlans={() => goTab('plans')} /> : null}
      {!loading && route === '/payment/success' ? (
        <SuccessView order={successOrder} plaintextKey={successKey} onProfile={() => goTab('profile')} />
      ) : null}
      {!loading && route !== '/payment/success' && route !== '/payment/cancel' ? (
        <>
          {activeTab === 'home' && <HomeView user={user} onLogin={() => loginWithGoogle()} onPlans={() => goTab('plans')} />}
          {activeTab === 'plans' && (
            <PlansView
              user={user}
              busyPlan={busyPlan}
              activationCounts={activationCounts}
              onActivationCount={updateActivationCount}
              onBuy={buyPlan}
            />
          )}
          {activeTab === 'profile' && <ProfileView user={user} orders={orders} paidOrders={paidOrders} onLogin={() => loginWithGoogle()} />}
        </>
      ) : null}
    </main>
  )
}

function Header({ user, activeTab, onTab, onLogin, onLogout }: { user: User | null; activeTab: Tab; onTab: (tab: Tab) => void; onLogin: () => void; onLogout: () => void }) {
  return (
    <header className="topbar">
      <button className="brand" onClick={() => onTab('home')}>
        <ShieldCheck size={22} />
        <span>BizGuard</span>
      </button>
      <nav className="tabs" aria-label="Навігація сайту покупки">
        <button className={activeTab === 'home' ? 'active' : ''} onClick={() => onTab('home')}>Головна</button>
        <button className={activeTab === 'plans' ? 'active' : ''} onClick={() => onTab('plans')}>Тарифи</button>
        <button className={activeTab === 'profile' ? 'active' : ''} onClick={() => onTab('profile')}>Профіль</button>
      </nav>
      {user ? (
        <button className="icon-button" onClick={onLogout} title="Вийти">
          <LogOut size={18} />
          Вийти
        </button>
      ) : (
        <button className="primary small" onClick={onLogin}>Увійти через Google</button>
      )}
    </header>
  )
}

function HomeView({ user, onLogin, onPlans }: { user: User | null; onLogin: () => void; onPlans: () => void }) {
  return (
    <section className="hero screen-panel">
      <div className="hero-copy">
        <span className="eyebrow"><LockKeyhole size={16} /> AI-захист Gmail без зайвого шуму</span>
        <h1>Купіть бізнес-ключ BizGuard і підключіть захист пошти</h1>
        <p>
          BizGuard перевіряє нові листи, домени, URL і вкладення, формує зрозумілі українські вердикти та дозволяє
          купити один ключ на потрібну кількість активацій для команди.
        </p>
        <div className="hero-actions">
          <button className="primary" onClick={onPlans}>Обрати тариф <ArrowRight size={18} /></button>
          {user ? <a className="ghost" href={BIZGUARD_APP_URL}>Перейти в BizGuard app</a> : <button className="ghost" onClick={onLogin}>Увійти через Google</button>}
        </div>
      </div>
      <div className="product-preview" aria-label="Попередній перегляд BizGuard dashboard">
        <div className="preview-header"><MailCheck size={18} /> Живий захист листів</div>
        <div className="preview-row safe"><span>accounts.google.com</span><b>Безпечний</b></div>
        <div className="preview-row danger"><span>secure-account-login.example</span><b>Критичний</b></div>
        <div className="preview-row"><span>mail.grammarly.com</span><b>Безпечний</b></div>
        <div className="preview-meter"><span style={{ width: '72%' }} /></div>
      </div>
    </section>
  )
}

function PlansView({
  user,
  busyPlan,
  activationCounts,
  onActivationCount,
  onBuy,
}: {
  user: User | null
  busyPlan: PlanId | null
  activationCounts: Record<PlanId, number>
  onActivationCount: (plan: PlanId, value: number) => void
  onBuy: (plan: PlanId) => void
}) {
  return (
    <section className="screen-panel plans-section">
      <div className="section-title">
        <span><CreditCard size={18} /> Тарифні плани</span>
        <p>Введіть кількість активацій для бізнесу. Базова ціна включає першу активацію, додаткові місця рахуються автоматично.</p>
      </div>
      <div className="plans-grid">
        {plans.map((plan) => {
          const activationCount = activationCounts[plan.id] || 1
          const total = plan.baseAmount + Math.max(0, activationCount - 1) * plan.extraSeatAmount
          const extraSeats = Math.max(0, activationCount - 1)
          return (
            <article className={`plan-card ${plan.accent}`} key={plan.id}>
              <div className="plan-head">
                <span>{plan.badge}</span>
                <h2>{plan.title}</h2>
                <strong>{formatMoney(total, 'uah')}</strong>
                <p>{plan.period}</p>
              </div>
              <p className="plan-description">{plan.description}</p>
              <div className="seat-box">
                <label htmlFor={`seats-${plan.id}`}>Кількість активацій</label>
                {plan.id === 'free_1_day' ? (
                  <div className="seat-fixed">1 активація</div>
                ) : (
                  <div className="seat-control">
                    <button type="button" onClick={() => onActivationCount(plan.id, activationCount - 1)} aria-label="Зменшити кількість"><Minus size={16} /></button>
                    <input
                      id={`seats-${plan.id}`}
                      type="number"
                      min="1"
                      max={MAX_ACTIVATIONS}
                      value={activationCount}
                      onChange={(event) => onActivationCount(plan.id, Number(event.target.value))}
                    />
                    <button type="button" onClick={() => onActivationCount(plan.id, activationCount + 1)} aria-label="Збільшити кількість"><Plus size={16} /></button>
                  </div>
                )}
                <div className="price-breakdown">
                  <span>База: {formatMoney(plan.baseAmount, 'uah')}</span>
                  <span>Додаткові активації: {extraSeats} × {formatMoney(plan.extraSeatAmount, 'uah')}</span>
                  <b>Разом: {formatMoney(total, 'uah')}</b>
                </div>
              </div>
              <ul>
                {plan.features.map((feature) => <li key={feature}><Check size={16} /> {feature}</li>)}
              </ul>
              <button className="primary full" onClick={() => onBuy(plan.id)} disabled={busyPlan === plan.id}>
                {busyPlan === plan.id ? 'Створення оплати...' : user ? 'Купити ключ' : 'Увійти і купити'}
              </button>
            </article>
          )
        })}
      </div>
    </section>
  )
}

function ProfileView({ user, orders, paidOrders, onLogin }: { user: User | null; orders: Order[]; paidOrders: Order[]; onLogin: () => void }) {
  return (
    <section className="screen-panel profile-section">
      <div className="section-title">
        <span><UserCircle size={18} /> Профіль</span>
        <p>Покупки, статуси оплат і ключі без повного plaintext після першого показу.</p>
      </div>
      {!user ? (
        <div className="empty-panel profile-empty">
          <div>
            <h2>Увійдіть, щоб бачити куплені ключі</h2>
            <p>Авторизація на сайті покупки використовує тільки Google profile/email і не просить доступ до Gmail.</p>
          </div>
          <button className="primary" onClick={onLogin}>Увійти через Google</button>
        </div>
      ) : (
        <div className="profile-grid">
          <aside className="profile-card">
            {user.picture ? <img src={user.picture} alt="" /> : <div className="avatar-fallback">{user.email.slice(0, 1).toUpperCase()}</div>}
            <div>
              <b>{user.first_name || user.email}</b>
              <span>{user.email}</span>
              <small>Оплачених ключів: {paidOrders.length}</small>
            </div>
            <a className="ghost full" href={BIZGUARD_APP_URL}>Перейти в BizGuard app</a>
          </aside>
          <div className="orders-card">
            {orders.length === 0 ? (
              <div className="empty-orders">
                <KeyRound size={26} />
                <b>Покупок ще немає</b>
                <span>Оберіть тариф, оплатіть його і тут з’явиться preview ключа.</span>
              </div>
            ) : orders.map((order) => <OrderRow key={order.id} order={order} />)}
          </div>
        </div>
      )}
    </section>
  )
}

function OrderRow({ order }: { order: Order }) {
  const license = order.generatedLicense
  return (
    <div className="order-row">
      <div className="order-main">
        <b>{order.planLabel}</b>
        <span>{formatMoney(order.amount, order.currency)} · {order.activationCount} активац. · {statusLabel(order.status)} · {new Date(order.createdAt).toLocaleDateString('uk-UA')}</span>
        <small className="muted">База {formatMoney(order.baseAmount, order.currency)} · додатково {formatMoney(order.extraSeatAmount, order.currency)}</small>
      </div>
      {license ? (
        <div className="license-preview">
          <code>{license.keyPrefix}...</code>
          <small>{license.activationCount}/{license.maxActivations} використано · залишилось {license.remainingActivations}</small>
        </div>
      ) : (
        <span className="muted">Ключ буде після оплати</span>
      )}
    </div>
  )
}

function SuccessView({ order, plaintextKey, onProfile }: { order: Order | null; plaintextKey: string | null; onProfile: () => void }) {
  return (
    <section className="result-page success">
      <Sparkles size={30} />
      <h1>Оплата успішна</h1>
      <p>Ключ потрібно ввести в BizGuard app перед Gmail login. Повний ключ показується тільки тут.</p>
      {plaintextKey ? <KeyBox value={plaintextKey} /> : <div className="notice">Повний ключ уже показувався раніше. У профілі доступний тільки prefix.</div>}
      {order ? (
        <p className="muted">
          Тариф: {order.planLabel} · {order.activationCount} активац. · {formatMoney(order.amount, order.currency)}
        </p>
      ) : null}
      <div className="hero-actions center">
        <a className="primary" href={BIZGUARD_APP_URL}>Перейти в BizGuard app</a>
        <button className="ghost" onClick={onProfile}>Відкрити профіль</button>
      </div>
    </section>
  )
}

function KeyBox({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    await navigator.clipboard.writeText(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 1600)
  }
  return (
    <div className="key-box">
      <KeyRound size={18} />
      <code>{value}</code>
      <button className="icon-only" onClick={copy} title="Скопіювати ключ"><Copy size={17} /></button>
      {copied ? <span>Скопійовано</span> : null}
    </div>
  )
}

function CancelView({ onPlans }: { onPlans: () => void }) {
  function back() {
    window.history.replaceState({}, '', '/')
    onPlans()
  }
  return (
    <section className="result-page">
      <h1>Оплату скасовано</h1>
      <p>Можна повернутись до тарифів і спробувати ще раз.</p>
      <button className="primary" onClick={back}>Повернутись до тарифів</button>
    </section>
  )
}

function LoadingView() {
  return <div className="loading">Завантаження...</div>
}

function oauthErrorMessage(code: string) {
  return {
    access_denied: 'Google заблокував або скасував вхід.',
    missing_code: 'Google не повернув код авторизації.',
    google_oauth_failed: 'Не вдалося завершити Google авторизацію. Перевірте OAuth redirect URI у Google Cloud.',
    google_callback_failed: 'Не вдалося завершити вхід через Google. Спробуйте ще раз.',
  }[code] || 'Не вдалося увійти через Google.'
}

function statusLabel(status: Order['status']) {
  return {
    pending: 'Очікує оплати',
    paid: 'Оплачено',
    canceled: 'Скасовано',
    failed: 'Помилка оплати',
  }[status]
}

function formatMoney(amount: number, currency: string) {
  if (currency.toLowerCase() === 'uah') return `${Math.round(amount / 100)} грн`
  return `${(amount / 100).toFixed(2)} ${currency.toUpperCase()}`
}

createRoot(document.getElementById('root')!).render(<App />)