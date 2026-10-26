import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../services/api'

export default function Registry() {
  const [assets, setAssets] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [q, setQ] = useState('')
  const [service, setService] = useState('')
  const navigate = useNavigate()
  const load = async () => { setLoading(true); try { const params: any = {}; if (q) params.q = q; if (service) params.service = service; setAssets((await api.get('/assets/', { params })).data) } catch (e) { console.error(e) } finally { setLoading(false) } }
  useEffect(() => { load() }, [])
  return <>
    <header className="page-head"><div><div className="eyebrow">Inventory / AWS resources</div><h1>Asset registry</h1><p className="lede">Discovered AI systems and AI capable infrastructure recorded across your account.</p></div><span className="badge neutral">{assets.length} records</span></header>
    <section className="panel">
      <div className="panel-head"><div><h2>Registered assets</h2><p className="stat-note">Select a record to review its evidence and governance details.</p></div></div>
      <div className="panel-body">
        <div className="toolbar"><input aria-label="Search assets" placeholder="Search name or resource ID" value={q} onChange={(e) => setQ(e.target.value)} /><input aria-label="Filter by service" placeholder="Filter by AWS service" value={service} onChange={(e) => setService(e.target.value)} /><button onClick={load}>Apply filters</button></div>
        {loading ? <p>Loading registry…</p> : <div className="table-wrap"><table><thead><tr><th>Resource</th><th>Service / type</th><th>Region</th><th>Owner</th><th>Risk assessment</th><th></th></tr></thead><tbody>
          {assets.length === 0 && <tr><td colSpan={6} className="empty">No assets match this view.</td></tr>}
          {assets.map((a) => <tr key={a.record_id}><td><strong>{a.resource_name || a.resource_id}</strong><div className="stat-note">{a.resource_id}</div></td><td>{a.aws_service}<div className="stat-note">{a.resource_type}</div></td><td>{a.aws_region || 'Global'}</td><td>{a.owner || <span className="badge neutral">Unassigned</span>}</td><td><span className={`badge ${a.risk_assessment_level ? 'warn' : 'neutral'}`}>{a.risk_assessment_level || 'Not assessed'}</span></td><td><button className="text-link" onClick={() => navigate(`/asset/${a.record_id}`)}>Open record →</button></td></tr>)}
        </tbody></table></div>}
      </div>
    </section>
  </>
}
