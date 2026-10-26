import { BrowserRouter, Routes, Route, Navigate, NavLink, useLocation } from 'react-router-dom'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Registry from './pages/Registry'
import AssetDetail from './pages/AssetDetail'
import Coverage from './pages/Coverage'
import AwsConnection from './pages/AwsConnection'

function Shell({ children }: { children: React.ReactNode }) {
  const location = useLocation()
  const title = location.pathname === '/' ? 'Overview' : location.pathname.startsWith('/asset/') ? 'Asset record' : location.pathname.slice(1)
  return <div className="app-frame">
    <aside className="sidebar">
      <NavLink to="/" className="brand"><span className="brand-mark">AR</span>AI Registry</NavLink>
      <div className="nav-label">Workspace</div>
      <nav>
        <NavLink end to="/" className={({ isActive }) => `side-link ${isActive ? 'active' : ''}`}><span className="side-icon">01</span>Overview</NavLink>
        <NavLink to="/registry" className={({ isActive }) => `side-link ${isActive ? 'active' : ''}`}><span className="side-icon">02</span>Asset registry</NavLink>
        <NavLink to="/coverage" className={({ isActive }) => `side-link ${isActive ? 'active' : ''}`}><span className="side-icon">03</span>Coverage &amp; findings</NavLink>
        <NavLink to="/aws-account" className={({ isActive }) => `side-link ${isActive ? 'active' : ''}`}><span className="side-icon">04</span>AWS connection</NavLink>
      </nav>
      <div className="sidebar-foot">Read-only AWS discovery<br />Governance intelligence</div>
    </aside>
    <main className="main">
      <div className="topline"><span className="eyebrow">AI governance / {title}</span><span className="topline-meta">Account inventory · Read-only</span></div>
      {children}
    </main>
  </div>
}

function PrivateRoute({ children }: { children: React.ReactElement }) {
  const token = localStorage.getItem('token')
  return token ? <Shell>{children}</Shell> : <Navigate to="/login" />
}

export default function App() {
  return <BrowserRouter><Routes>
    <Route path="/login" element={<Login />} />
    <Route path="/" element={<PrivateRoute><Dashboard /></PrivateRoute>} />
    <Route path="/registry" element={<PrivateRoute><Registry /></PrivateRoute>} />
    <Route path="/asset/:record_id" element={<PrivateRoute><AssetDetail /></PrivateRoute>} />
    <Route path="/coverage" element={<PrivateRoute><Coverage /></PrivateRoute>} />
    <Route path="/aws-account" element={<PrivateRoute><AwsConnection /></PrivateRoute>} />
  </Routes></BrowserRouter>
}
