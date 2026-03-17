import { useState } from 'react';
import { QRCodeSVG } from 'qrcode.react';

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="copy-btn-wrap">
      {copied && <span className="copy-tooltip">Copied!</span>}
      <button className="btn btn-ghost btn-icon" onClick={handleCopy} title="Copy link">
        {copied ? '✓' : '📋'}
      </button>
    </div>
  );
}

function QRModal({ url, onClose }) {
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal animate-slide-up" onClick={(e) => e.stopPropagation()}>
        <h3>QR Code</h3>
        <p>{url.shortCode}</p>
        <div className="modal-qr">
          <QRCodeSVG value={url.shortUrl} size={180} />
        </div>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginBottom: 16, wordBreak: 'break-all' }}>{url.shortUrl}</p>
        <div className="modal-actions">
          <button className="btn btn-ghost" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}

function UrlCard({ url, onDelete }) {
  const [showQR, setShowQR] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const handleDelete = async () => {
    if (!confirm('Delete this link?')) return;
    setDeleting(true);
    await onDelete(url.id);
    setDeleting(false);
  };

  const ago = (date) => {
    const d = new Date(date);
    const diff = Date.now() - d.getTime();
    const m = Math.floor(diff / 60000);
    if (m < 1) return 'just now';
    if (m < 60) return `${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h ago`;
    return `${Math.floor(h / 24)}d ago`;
  };

  return (
    <>
      <div className="url-card">
        <div className="url-info">
          <div className="url-short">
            <a href={url.shortUrl} target="_blank" rel="noopener noreferrer">{url.shortUrl}</a>
            <span className="url-short-badge">SHORT</span>
          </div>
          <div className="url-original" title={url.originalUrl}>{url.originalUrl}</div>
          <div className="url-meta">
            <span className="url-meta-item">🕐 {ago(url.createdAt)}</span>
          </div>
        </div>
        <div className="url-actions">
          <span className="clicks-badge">📈 {url.clicks || 0} clicks</span>
          <CopyButton text={url.shortUrl} />
          <button className="btn btn-ghost btn-icon" onClick={() => setShowQR(true)} title="Show QR code">▦</button>
          <button className="btn btn-danger btn-icon" onClick={handleDelete} disabled={deleting} title="Delete">
            {deleting ? <span className="spinner" /> : '🗑'}
          </button>
        </div>
      </div>
      {showQR && <QRModal url={url} onClose={() => setShowQR(false)} />}
    </>
  );
}

export default UrlCard;
