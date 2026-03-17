import { useState, useEffect, useCallback } from 'react';
import api from '../api';
import { useAuth } from '../context/AuthContext';
import UrlCard from '../components/UrlCard';

function Dashboard() {
  const { user, logout } = useAuth();
  const [urls, setUrls] = useState([]);
  const [stats, setStats] = useState({ totalLinks: 0, totalClicks: 0 });
  const [form, setForm] = useState({ originalUrl: '', customCode: '' });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const [fetching, setFetching] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [urlsRes, statsRes] = await Promise.all([
        api.get('/api/my-urls'),
        api.get('/api/stats'),
      ]);
      setUrls(urlsRes.data);
      setStats(statsRes.data);
    } catch {
      // swallow
    } finally {
      setFetching(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);
    try {
      const payload = { originalUrl: form.originalUrl };
      if (form.customCode.trim()) payload.customCode = form.customCode.trim();
      await api.post('/api/shorten', payload);
      setForm({ originalUrl: '', customCode: '' });
      setSuccess('✅ Short link created successfully!');
      setTimeout(() => setSuccess(''), 4000);
      fetchData();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to shorten URL');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id) => {
    await api.delete(`/api/urls/${id}`);
    fetchData();
  };

  return (
    <div className="app">
      {/* Navbar */}
      <nav className="navbar">
        <a className="navbar-brand" href="#">
          <div className="navbar-logo">🔗</div>
          <span className="navbar-title">SnapLink</span>
        </a>
        <div className="navbar-actions">
          <span className="nav-user">👤 <span>{user?.username}</span></span>
          <button className="btn btn-ghost btn-sm" onClick={logout}>Sign out</button>
        </div>
      </nav>

      <div className="dashboard">
        {/* Stats */}
        <div className="stats-grid">
          <div className="stat-card blue">
            <div className="stat-icon">🔗</div>
            <div className="stat-value">{stats.totalLinks}</div>
            <div className="stat-label">Total Links</div>
          </div>
          <div className="stat-card pink">
            <div className="stat-icon">📈</div>
            <div className="stat-value">{stats.totalClicks}</div>
            <div className="stat-label">Total Clicks</div>
          </div>
          <div className="stat-card cyan">
            <div className="stat-icon">⚡</div>
            <div className="stat-value">{stats.totalLinks > 0 ? (stats.totalClicks / stats.totalLinks).toFixed(1) : '0'}</div>
            <div className="stat-label">Avg. Clicks / Link</div>
          </div>
        </div>

        {/* Shorten form */}
        <div className="shorten-card">
          <h2>✂️ Shorten a URL</h2>
          <p>Paste your long link below to get a powerful short link in seconds</p>

          {error && <div className="alert alert-error" style={{ marginBottom: 16 }}>⚠️ {error}</div>}
          {success && <div className="alert alert-success" style={{ marginBottom: 16 }}>{success}</div>}

          <form className="shorten-form" onSubmit={handleSubmit}>
            <div className="shorten-row">
              <div className="form-group">
                <label className="form-label">Long URL *</label>
                <input
                  className="form-input"
                  placeholder="https://example.com/very/long/url/that/needs/shortening"
                  value={form.originalUrl}
                  onChange={(e) => setForm({ ...form, originalUrl: e.target.value })}
                  required
                />
              </div>
              <div className="form-group">
                <label className="form-label">Custom alias (optional)</label>
                <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                  <span style={{ color: 'var(--text-dim)', fontSize: '0.85rem', whiteSpace: 'nowrap' }}>:3001/</span>
                  <input
                    className="form-input"
                    placeholder="my-link"
                    value={form.customCode}
                    onChange={(e) => setForm({ ...form, customCode: e.target.value })}
                  />
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn btn-primary" type="submit" disabled={loading} style={{ minWidth: 160, padding: '12px 28px' }}>
                {loading ? <><span className="spinner" /> Shortening…</> : '⚡ Shorten URL'}
              </button>
            </div>
          </form>
        </div>

        {/* URL List */}
        <div>
          <div className="url-list-header">
            <h2>My Links</h2>
            <span className="url-count">{urls.length} link{urls.length !== 1 ? 's' : ''}</span>
          </div>
          {fetching ? (
            <div style={{ textAlign: 'center', padding: 60, color: 'var(--text-dim)' }}>
              <div className="spinner" style={{ margin: '0 auto', width: 32, height: 32, borderWidth: 3 }} />
            </div>
          ) : urls.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-icon">🔗</div>
              <h3>No links yet</h3>
              <p>Paste a long URL above to create your first short link!</p>
            </div>
          ) : (
            <div className="url-list">
              {urls.map((url) => (
                <UrlCard key={url.id} url={url} onDelete={handleDelete} />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default Dashboard;
