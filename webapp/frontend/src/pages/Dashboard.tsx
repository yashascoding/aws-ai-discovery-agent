import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../services/api'

const count = (n: any) => Number(n ?? 0).toLocaleString()

export default function Dashboard() {
  const [summary, setSummary] = useState<any>(null)
  const [scans, setScans] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)
  const navigate = useNavigate()

  const load = async () => {
    const [summaryRes, scanRes] = await Promise.all([api.get('/dashboard/summary'), api.get('/discovery/scans')])
    setSummary(summaryRes.data)
    setScans(scanRes.data)
  }
  useEffect(() => { load().catch(console.error).finally(() => setLoading(false)) }, [])

  const startScan = async () => {
    setScanning(true)
    try {
      const { data } = await api.post('/discovery/scan')
      for (let attempt = 0; attempt < 60; attempt++) {
        await new Promise((resolve) => setTimeout(resolve, 5000))
        const scanRes = await api.get('/discovery/scans')
        setScans(scanRes.data)
        const current = scanRes.data.find((s: any) => s.scan_id === data.scan_id)
        if (current && ['succeeded', 'partially succeeded', 'failed'].includes(current.status)) { await load(); break }
      }
    } catch (err: any) { alert(err.response?.data?.detail || 'Scan failed') }
    finally { setScanning(false) }
  }

  if (loading) return <p>Loading registry overview…</p>
  const latest = scans[0]
  const trustworthy = latest && ['succeeded', 'partially succeeded'].includes(latest.status) && latest.error_count === 0
  const statusClass = !latest ? '' : latest.status === 'succeeded' && latest.error_count === 0 ? 'good' : latest.status === 'failed' || latest.error_count > 0 ? 'bad' : 'warn'

  return <>
    <header className="page-head">
      <div><div className="eyebrow">Account intelligence</div><h1>AI system registry</h1><p className="lede">A clear view of AI capable resources, their evidence, and the governance work still open.</p></div>
      <div className="actions"><button onClick={() => navigate('/aws-account')}>Connect AWS account</button><button onClick={() => navigate('/registry')}>Browse registry <span aria-hidden="true">↗</span></button><button className="primary" onClick={startScan} disabled={scanning}>{scanning ? 'Scanning AWS…' : 'Run discovery scan'}</button></div>
    </header>

    <div className={`scan-state ${statusClass}`}>
      <strong>{latest ? `Latest scan · ${latest.status}` : 'No discovery scan yet'}</strong>
      <span> {latest?.finished_at ? `· ${new Date(latest.finished_at).toLocaleString()}` : ''}{latest ? ` · ${count(latest.resources_discovered)} resources · ${count(latest.error_count)} errors` : ' · Run a scan to query your AWS account.'}</span>
      {latest && !trustworthy && <div style={{ marginTop: 7 }}>These results may be incomplete. Review scan errors and service coverage before treating zero as an empty account.</div>}
    </div>

    <section className="stat-grid" aria-label="Registry metrics">
      <Stat label="AI assets discovered" value={count(summary?.total_discovered_ai_assets)} note="Current registry records" />
      <Stat label="High risk" value={count(summary?.high_risk_assets)} note="Needs attention" />
      <Stat label="Shadow AI" value={count(summary?.assets_classified_as_shadow_ai)} note="Unmanaged systems" />
      <Stat label="Governance gaps" value={count(summary?.assets_with_unresolved_governance_findings)} note="Owner or purpose missing" />
      <Stat label="Open findings" value={count(summary?.open_findings_total)} note="From latest completed scan" />
      <Stat label="Reported cost" value={`${summary?.cost_currency || ''} ${Number(summary?.reported_cost_total || 0).toFixed(2)}`} note={`Status: ${summary?.cost_collection_status || 'not configured'}`} />
      <Stat label="Usage measures" value={count(summary?.usage_measurement_count)} note={`Status: ${summary?.usage_collection_status || 'not configured'}`} />
      <Stat label="Discovery coverage" value={summary?.discovery_coverage_percent == null ? '—' : `${summary.discovery_coverage_percent}%`} note={`${count(summary?.capabilities_total)} services evaluated`} />
    </section>

    <div className="split section">
      <section className="panel">
        <div className="panel-head"><div><div className="eyebrow">Spend overview</div><h2>Top cost services</h2></div><button className="text-link" onClick={() => navigate('/coverage')}>Full report →</button></div>
        <div className="panel-body">{(summary?.top_cost_services || []).length === 0 ? <p className="empty">No reported cost in the latest completed scan.</p> : <table><thead><tr><th>Service</th><th>Reported amount</th></tr></thead><tbody>{summary.top_cost_services.map((row: any) => <tr key={row.service_name}><td>{row.service_name}</td><td>{summary.cost_currency} {Number(row.amount).toFixed(2)}</td></tr>)}</tbody></table>}<p className="stat-note">Service level totals are not allocated to a resource without a billing identifier.</p></div>
      </section>
      <section className="panel">
        <div className="panel-head"><div><div className="eyebrow">Action queue</div><h2>Top findings</h2></div><button className="text-link" onClick={() => navigate('/coverage')}>Review all →</button></div>
        <div className="panel-body">{(summary?.top_findings || []).length === 0 ? <p className="empty">No open findings from the latest completed scan.</p> : <table><tbody>{summary.top_findings.map((f: any) => <tr key={f.finding_id}><td><span className={`severity ${f.severity}`}>{f.severity}</span></td><td><strong>{f.title}</strong><div className="stat-note">{f.service || 'Organization wide'}</div></td><td>{f.resource_record_id && <button className="text-link" onClick={() => navigate(`/asset/${f.resource_record_id}`)}>Inspect →</button>}</td></tr>)}</tbody></table>}</div>
      </section>
    </div>
    <section className="panel section">
      <div className="panel-head"><div><div className="eyebrow">Run history</div><h2>Discovery activity</h2></div><button className="text-link" onClick={() => navigate('/coverage')}>Explore coverage →</button></div>
      <div className="panel-body table-wrap"><table><thead><tr><th>Started</th><th>Status</th><th>Region</th><th>Resources</th><th>Errors</th></tr></thead><tbody>{scans.slice(0,5).map((s) => <tr key={s.scan_id}><td>{s.started_at ? new Date(s.started_at).toLocaleString() : '—'}</td><td><span className={`badge ${s.status === 'succeeded' && !s.error_count ? 'good' : s.status === 'failed' || s.error_count ? 'bad' : 'warn'}`}>{s.status}</span></td><td>{(s.regions || []).join(', ') || '—'}</td><td>{count(s.resources_discovered)}</td><td>{count(s.error_count)}</td></tr>)}</tbody></table>{scans.length === 0 && <p className="empty">No scans have been run.</p>}</div>
    </section>
  </>
}

function Stat({ label, value, note }: { label: string; value: string; note: string }) { return <div className="stat"><div className="stat-label">{label}</div><div className="stat-value">{value}</div><div className="stat-note">{note}</div></div> }
