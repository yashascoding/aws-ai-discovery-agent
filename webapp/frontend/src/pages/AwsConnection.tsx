import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../services/api'

export default function AwsConnection() {
  const [connection, setConnection] = useState<any>(null)
  const [authorizationUrl, setAuthorizationUrl] = useState('')
  const [code, setCode] = useState('')
  const [account, setAccount] = useState<any>(null)
  const [scan, setScan] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [signingIn, setSigningIn] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const navigate = useNavigate()

  useEffect(() => {
    api.get('/aws-connection').then(({ data }) => {
      setConnection(data)
      if (data.connected) setAccount(data)
      else if (data.error) setError(`AWS sign-in needs refreshing: ${data.error}`)
    }).catch((err) => setError(err.response?.data?.detail || 'Could not load AWS sign-in')).finally(() => setLoading(false))
  }, [])

  const startSignIn = async () => {
    setError(''); setMessage(''); setSigningIn(true)
    try {
      const { data } = await api.post('/aws-connection/login/start')
      setAuthorizationUrl(data.authorization_url)
      setMessage('Sign in on the AWS page. AWS will show a one-time code; enter that code here to finish connecting.')
      window.open(data.authorization_url, '_blank', 'noopener,noreferrer')
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Could not start AWS sign-in.')
    } finally { setSigningIn(false) }
  }

  const finishSignIn = async () => {
    setError(''); setMessage(''); setSigningIn(true)
    try {
      const { data } = await api.post('/aws-connection/login/complete', { code })
      setAccount(data); setConnection({ ...connection, connected: true, account_id: data.account_id, caller_arn: data.caller_arn }); setCode(''); setAuthorizationUrl('')
      setMessage(`Verified AWS account ${data.account_id}. You can now analyze its AI activity.`)
    } catch (err: any) {
      setError(err.response?.data?.detail || 'AWS sign-in could not be verified. Start again and use the newest code.')
    } finally { setSigningIn(false) }
  }

  const analyze = async () => {
    setError(''); setMessage(''); setScan(null); setAnalyzing(true)
    try {
      const { data } = await api.post('/discovery/scan')
      setMessage('Scan started. Reading AWS resource, activity, and available usage evidence…')
      for (let attempt = 0; attempt < 120; attempt++) {
        await new Promise(resolve => setTimeout(resolve, 5000))
        const scans = await api.get('/discovery/scans')
        const current = scans.data.find((item: any) => item.scan_id === data.scan_id)
        if (current && ['succeeded', 'partially succeeded', 'failed'].includes(current.status)) {
          setScan(current)
          setMessage(current.status === 'failed' ? 'The scan could not finish. Review the error summary below.' : 'AWS analysis is complete.')
          break
        }
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Could not start the AWS analysis.')
    } finally { setAnalyzing(false) }
  }

  if (loading) return <p>Checking AWS connection…</p>
  return <>
    <header className="page-head"><div><div className="eyebrow">AWS account</div><h1>Sign in and analyze</h1><p className="lede">Sign in securely with AWS, verify the account, then scan its AI resources and available activity evidence.</p></div></header>
    {message && <div className="scan-state good" role="status">{message}</div>}
    {error && <div className="scan-state bad" role="alert">{error}</div>}

    <section className="panel" style={{ maxWidth: 860 }}>
      <div className="panel-head"><div><div className="eyebrow">AWS authentication</div><h2>{account ? 'AWS account connected' : 'Connect your AWS account'}</h2></div><span className={`badge ${account ? 'good' : 'neutral'}`}>{account ? 'Verified' : 'Not connected'}</span></div>
      <div className="panel-body">
        {account ? <>
          <div className="detail-row"><span>AWS account</span><strong>{account.account_id}</strong></div>
          <div className="detail-row"><span>Signed in as</span><strong>{account.caller_arn}</strong></div>
          <p className="stat-note" style={{ margin: '16px 0' }}>AWS issued temporary credentials for this sign-in. No AWS password or access key is stored in the registry database.</p>
          <button className="primary" onClick={analyze} disabled={analyzing}>{analyzing ? 'Analyzing AWS…' : 'Analyze AI usage now'}</button>
          <button style={{ marginLeft: 8 }} onClick={startSignIn} disabled={signingIn}>{signingIn ? 'Opening AWS…' : 'Switch AWS account'}</button>
        </> : <>
          <p>Continue to AWS to sign in with the account you want analyzed. AWS supports root, IAM, and federated sign-in here; your password and MFA stay on AWS.</p>
          <button className="primary" onClick={startSignIn} disabled={signingIn}>{signingIn ? 'Starting secure sign-in…' : 'Continue to AWS sign-in'}</button>
          {authorizationUrl && <div style={{ marginTop: 22 }}>
            <p><strong>1.</strong> Complete sign-in on the AWS page.</p>
            <p><strong>2.</strong> Copy the one-time authorization code AWS displays and paste it below.</p>
            <p><a href={authorizationUrl} target="_blank" rel="noreferrer">Open AWS sign-in page ↗</a></p>
            <div className="toolbar"><input aria-label="AWS one-time authorization code" placeholder="Paste the one-time code from AWS" value={code} onChange={e => setCode(e.target.value)} style={{ flex: 1 }} /><button className="primary" onClick={finishSignIn} disabled={signingIn || !code.trim()}>{signingIn ? 'Verifying…' : 'Verify AWS account'}</button></div>
          </div>}
        </>}
      </div>
    </section>

    {scan && <section className={`scan-state ${scan.status === 'failed' ? 'bad' : scan.error_count ? 'warn' : 'good'}`} style={{ maxWidth: 860, marginTop: 18 }}>
      <strong>{scan.status === 'failed' ? 'Analysis failed' : `Analysis ${scan.status}`}</strong>
      <div>Account {scan.account_id || account?.account_id} · {scan.resources_discovered} resources discovered · {scan.error_count} service errors</div>
      {scan.errors?.length > 0 && <details style={{ marginTop: 10 }}><summary>View service errors</summary><ul>{scan.errors.slice(0, 10).map((item: any, i: number) => <li key={i}>{item.service || 'AWS'} / {item.operation || 'request'}: {item.message || item.error}</li>)}</ul></details>}
      <button style={{ marginTop: 12 }} onClick={() => navigate('/')}>View usage analysis</button>
    </section>}
  </>
}
