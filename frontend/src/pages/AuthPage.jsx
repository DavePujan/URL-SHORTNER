import { useState } from 'react';
import api from '../api';
import { useAuth } from '../context/AuthContext';

function AuthPage() {
  const { login } = useAuth();
  const [tab, setTab] = useState('login');
  const [form, setForm] = useState({ username: '', email: '', password: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const endpoint = tab === 'login' ? '/auth/login' : '/auth/register';
      const payload = tab === 'login'
        ? { username: form.username, password: form.password }
        : { username: form.username, email: form.email, password: form.password };
      const res = await api.post(endpoint, payload);
      login(res.data.token, res.data.user);
    } catch (err) {
      setError(err.response?.data?.error || 'Something went wrong');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-wrapper">
      {/* Left panel */}
      <div className="auth-left">
        <div className="auth-left-logo">
          <div className="auth-left-logo-icon">🔗</div>
          <span className="auth-left-logo-text">SnapLink</span>
        </div>
        <h1>Make your links <span>powerful</span> and trackable</h1>
        <p>Shorten, brand, and track your links. Get powerful insights into every click.</p>
        <div className="auth-features">
          {[
            { icon: '⚡', title: 'Instant shortening', desc: 'Create short links in milliseconds' },
            { icon: '📊', title: 'Click analytics', desc: 'Track every click with detailed stats' },
            { icon: '🎯', title: 'Custom aliases', desc: 'Create branded, memorable short links' },
            { icon: '🔒', title: 'Secure & private', desc: 'JWT-protected links only visible to you' },
          ].map((f) => (
            <div className="auth-feature" key={f.title}>
              <div className="auth-feature-icon">{f.icon}</div>
              <div className="auth-feature-text">
                <strong>{f.title}</strong>
                <span>{f.desc}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Right panel */}
      <div className="auth-right">
        <div className="auth-form-container animate-slide-up">
          <div className="auth-tabs">
            <button className={`auth-tab${tab === 'login' ? ' active' : ''}`} onClick={() => { setTab('login'); setError(''); }}>Sign In</button>
            <button className={`auth-tab${tab === 'register' ? ' active' : ''}`} onClick={() => { setTab('register'); setError(''); }}>Sign Up</button>
          </div>

          <h2 className="auth-form-title">{tab === 'login' ? 'Welcome back 👋' : 'Create account 🚀'}</h2>
          <p className="auth-form-sub">{tab === 'login' ? 'Sign in to manage your links' : 'Start shortening links for free'}</p>

          {error && <div className="alert alert-error" style={{ marginBottom: 16 }}>⚠️ {error}</div>}

          <form className="auth-form" onSubmit={handleSubmit}>
            <div className="form-group">
              <label className="form-label">Username</label>
              <input className="form-input" name="username" placeholder="Enter username" value={form.username} onChange={handleChange} required autoFocus />
            </div>
            {tab === 'register' && (
              <div className="form-group">
                <label className="form-label">Email</label>
                <input className="form-input" name="email" type="email" placeholder="your@email.com" value={form.email} onChange={handleChange} required />
              </div>
            )}
            <div className="form-group">
              <label className="form-label">Password</label>
              <input className="form-input" name="password" type="password" placeholder="••••••••" value={form.password} onChange={handleChange} required minLength={6} />
            </div>
            <button className="btn btn-primary" type="submit" disabled={loading} style={{ marginTop: 4, padding: '13px' }}>
              {loading ? <span className="spinner" /> : (tab === 'login' ? '→ Sign In' : '→ Create Account')}
            </button>
          </form>

          <div className="auth-divider" style={{ marginTop: 20 }}><span>or</span></div>
          <p style={{ textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.85rem', marginTop: 12 }}>
            {tab === 'login' ? "Don't have an account? " : 'Already have an account? '}
            <button className="btn btn-ghost btn-sm" style={{ display: 'inline', padding: '2px 8px', border: 'none', color: 'var(--primary-light)' }} onClick={() => { setTab(tab === 'login' ? 'register' : 'login'); setError(''); }}>
              {tab === 'login' ? 'Sign up free' : 'Sign in'}
            </button>
          </p>
        </div>
      </div>
    </div>
  );
}

export default AuthPage;
