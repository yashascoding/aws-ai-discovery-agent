import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../services/api'

function readableError(error: any): string {
  const detail = error?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        const field = Array.isArray(item.loc) ? item.loc[item.loc.length - 1] : null
        const message = typeof item.msg === 'string' ? item.msg : 'Invalid value'
        return field ? `${String(field)}: ${message}` : message
      })
      .join('. ')
  }
  return 'Unable to continue. Check the entered details and backend connection.'
}

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [email, setEmail] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [register, setRegister] = useState(false)
  const navigate = useNavigate()

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError('')
    setBusy(true)
    try {
      let response
      if (register) {
        response = await api.post('/auth/register', {
          username: username.trim(),
          email: email.trim().toLowerCase(),
          password,
        })
      } else {
        const form = new FormData()
        form.append('username', username.trim())
        form.append('password', password)
        response = await api.post('/auth/token', form, {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        })
      }
      localStorage.setItem('token', response.data.access_token)
      navigate(register ? '/aws-account' : '/')
    } catch (submitError: any) {
      setError(readableError(submitError))
    } finally {
      setBusy(false)
    }
  }

  return <div className="login-wrap">
    <aside className="login-aside">
      <div>
        <NavBrand />
        <div style={{ marginTop: 'clamp(50px,12vh,140px)' }}>
          <div className="eyebrow">Responsible AI inventory</div>
          <h1>Know what’s running.<br /><em>Govern what matters.</em></h1>
          <p>Discover AI capable services and bring evidence, ownership, and oversight into one clear registry.</p>
        </div>
      </div>
      <div className="stat-note">AWS discovery is read only. Usage and cost are shown with their evidence limits.</div>
    </aside>
    <main className="login-form-wrap">
      <form className="login-form" onSubmit={submit}>
        <div className="eyebrow">Workspace access</div>
        <h2>{register ? 'Create your account' : 'Welcome back'}</h2>
        <p className="stat-note">{register ? 'Create a workspace login, then connect your AWS account.' : 'Sign in to review your connected AWS account.'}</p>
        <div className="field">
          <label htmlFor="username">{register ? 'Username' : 'Username or email'}</label>
          <input id="username" autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} required minLength={register ? 3 : undefined} maxLength={80} />
        </div>
        {register && <div className="field">
          <label htmlFor="email">Email</label>
          <input id="email" type="email" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} required maxLength={255} />
        </div>}
        <div className="field">
          <label htmlFor="password">Password {register && '(12–72 characters)'}</label>
          <input id="password" type="password" autoComplete={register ? 'new-password' : 'current-password'} value={password} onChange={(event) => setPassword(event.target.value)} required minLength={register ? 12 : undefined} maxLength={register ? 72 : undefined} />
        </div>
        {error && <div className="error-box" role="alert">{error}</div>}
        <button className="primary" style={{ width: '100%', marginTop: 8 }} disabled={busy}>
          {busy ? 'Please wait…' : register ? 'Create account' : 'Sign in'}
        </button>
        <p style={{ marginTop: 18, textAlign: 'center', fontSize: '.88rem', color: 'var(--muted)' }}>
          {register ? 'Already have an account? ' : 'New here? '}
          <button type="button" className="text-link" onClick={() => { setRegister(!register); setError('') }}>
            {register ? 'Sign in' : 'Create an account'}
          </button>
        </p>
      </form>
    </main>
  </div>
}
function NavBrand(){return <div className="brand" style={{padding:0}}><span className="brand-mark">AR</span>AI Registry</div>}
