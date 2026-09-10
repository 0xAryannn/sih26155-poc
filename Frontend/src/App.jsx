import React, { useState } from 'react';
import './App.css';

export default function App() {
  const [files, setFiles] = useState([]);
  const [screen, setScreen] = useState('upload');
  const [loading, setLoading] = useState(false);
  const [vendorData, setVendorData] = useState([]);
  const [auditData, setAuditData] = useState(null);
  const [sessionId, setSessionId] = useState(null);
  const [activeDevice, setActiveDevice] = useState(0);
  const [resultTab, setResultTab] = useState('failed');

  const vendors = [
    'CISCO',
    'FORTINET',
    'PALO ALTO',
    'JUNIPER',
    'CHECK POINT',
    'ARISTA',
    'F5 NETWORKS',
  ];

  /* =========================
     UPLOAD FILE(S) TO BACKEND
     ========================= */
  const handleAnalyze = async () => {
    if (files.length === 0) return;
    setLoading(true);

    const formData = new FormData();
    for (const f of files) {
      formData.append('files', f);
    }

    try {
      const res = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
      });
      const data = await res.json();

      if (data.status === 'ok') {
        setVendorData(data.files);
        setScreen('vendor');
      }
    } catch (err) {
      console.error('Upload failed:', err);
    } finally {
      setLoading(false);
    }
  };

  /* =========================
     RUN AUDIT
     ========================= */
  const handleAudit = async () => {
    setLoading(true);

    try {
      const res = await fetch('/api/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          files: vendorData.map((v) => v.filename),
        }),
      });
      const data = await res.json();

      if (data.status === 'ok') {
        setAuditData(data);
        setSessionId(data.session_id);
        setActiveDevice(0);
        setResultTab('failed');
        setScreen('result');
      }
    } catch (err) {
      console.error('Audit failed:', err);
    } finally {
      setLoading(false);
    }
  };

  /* =========================
     DOWNLOAD PDF
     ========================= */
  const handleDownloadPDF = () => {
    if (sessionId) {
      window.open(`/api/report/pdf/${sessionId}`, '_blank');
    }
  };

  /* =========================
     RESULT SCREEN
     ========================= */
  if (screen === 'result' && auditData) {
    const device = auditData.devices[activeDevice];
    const summary = auditData.summary;
    const scorePercent = Math.round(
      (device.security_score / device.max_score) * 100
    );

    return (
      <div className="main-container">
        {/* Navbar */}
        <nav className="glass-nav">
          <div className="logo-section">
            <div className="logo-icon"></div>
            <span className="logo-text">NETAUDIT</span>
          </div>
          <div className="nav-actions">
            <button
              className="secondary-btn"
              onClick={() => {
                setScreen('upload');
                setFiles([]);
                setVendorData([]);
                setAuditData(null);
              }}
            >
              New Audit
            </button>
            <button className="primary-btn" onClick={handleDownloadPDF}>
              Download PDF
            </button>
          </div>
        </nav>

        <section className="result-section">
          {/* Summary Bar */}
          <div className="result-summary-bar">
            <div className="summary-stat">
              <span className="stat-number">{summary.total_devices}</span>
              <span className="stat-label">Devices</span>
            </div>
            <div className="summary-stat stat-pass">
              <span className="stat-number">{summary.total_passed}</span>
              <span className="stat-label">Passed</span>
            </div>
            <div className="summary-stat stat-fail">
              <span className="stat-number">{summary.total_failed}</span>
              <span className="stat-label">Failed</span>
            </div>
            <div className="summary-stat stat-unknown">
              <span className="stat-number">{summary.total_unknown}</span>
              <span className="stat-label">Unknown</span>
            </div>
            <div className="summary-stat">
              <span className="stat-number">
                {summary.total_score}/{summary.total_max_score}
              </span>
              <span className="stat-label">Total Score</span>
            </div>
          </div>

          {/* Device Tabs (if multiple) */}
          {auditData.devices.length > 1 && (
            <div className="device-tabs">
              {auditData.devices.map((d, i) => (
                <button
                  key={i}
                  className={`device-tab ${i === activeDevice ? 'active' : ''}`}
                  onClick={() => {
                    setActiveDevice(i);
                    setResultTab('failed');
                  }}
                >
                  <span className="tab-vendor">{d.vendor_display}</span>
                  <span className="tab-name">{d.device_name}</span>
                </button>
              ))}
            </div>
          )}

          {/* Device Header Card */}
          <div className="device-header-card">
            <div className="device-info-row">
              <div>
                <span className="device-label">Device</span>
                <h2 className="device-title">{device.device_name}</h2>
              </div>
              <div>
                <span className="device-label">Vendor</span>
                <p className="device-vendor">{device.vendor_display}</p>
              </div>
              <div>
                <span className="device-label">Score</span>
                <p className="device-score">
                  {device.security_score}/{device.max_score}
                </p>
              </div>
              <div className={`risk-badge risk-${device.risk_level.toLowerCase()}`}>
                {device.risk_level}
              </div>
            </div>

            {/* Score Bar */}
            <div className="score-bar-container">
              <div className="score-bar">
                <div
                  className="score-fill"
                  style={{ width: `${scorePercent}%` }}
                ></div>
              </div>
              <span className="score-percent">{scorePercent}%</span>
            </div>
          </div>

          {/* Tab Switcher */}
          <div className="result-tabs">
            <button
              className={`result-tab ${resultTab === 'failed' ? 'active' : ''}`}
              onClick={() => setResultTab('failed')}
            >
              Failed ({device.failed_rules.length})
            </button>
            <button
              className={`result-tab ${resultTab === 'passed' ? 'active' : ''}`}
              onClick={() => setResultTab('passed')}
            >
              Passed ({device.passed_rules.length})
            </button>
            <button
              className={`result-tab ${resultTab === 'unknown' ? 'active' : ''}`}
              onClick={() => setResultTab('unknown')}
            >
              Unknown ({device.unknown_commands.length})
            </button>
          </div>

          {/* Rules List */}
          <div className="rules-list">
            {resultTab === 'failed' &&
              device.failed_rules.map((r, i) => (
                <div key={i} className="rule-card rule-fail">
                  <div className="rule-header">
                    <span className="rule-badge badge-fail">FAIL</span>
                    <span className={`severity-badge sev-${r.severity.toLowerCase()}`}>
                      {r.severity}
                    </span>
                    <span className="rule-id">{r.rule_id}</span>
                  </div>
                  <p className="rule-desc">{r.description}</p>
                  <div className="rule-meta">
                    <span className="rule-evidence">{r.evidence}</span>
                    <span className="rule-remediation">
                      Fix: {r.remediation.split('\n')[0]}
                    </span>
                  </div>
                </div>
              ))}

            {resultTab === 'passed' &&
              device.passed_rules.map((r, i) => (
                <div key={i} className="rule-card rule-pass">
                  <div className="rule-header">
                    <span className="rule-badge badge-pass">PASS</span>
                    <span className="rule-id">{r.rule_id}</span>
                  </div>
                  <p className="rule-desc">{r.description}</p>
                  <div className="rule-meta">
                    <span className="rule-evidence">{r.evidence}</span>
                  </div>
                </div>
              ))}

            {resultTab === 'unknown' &&
              (device.unknown_commands.length > 0 ? (
                device.unknown_commands.map((u, i) => (
                  <div key={i} className="rule-card rule-unknown">
                    <div className="rule-header">
                      <span className="rule-badge badge-unknown">UNKNOWN</span>
                      <span className="rule-id">Line {u.line_number}</span>
                    </div>
                    <p className="rule-desc">{u.command}</p>
                    <div className="rule-meta">
                      <span className="rule-evidence">Needs human review</span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="empty-state">
                  <div className="empty-icon">✓</div>
                  <p>All commands recognized</p>
                </div>
              ))}
          </div>
        </section>
      </div>
    );
  }

  /* =========================
     VENDOR DETECTED SCREEN
     ========================= */
  if (screen === 'vendor') {
    const primaryVendor = vendorData[0] || {};

    return (
      <div className="main-container vendor-page">
        {/* Top Navbar */}
        <nav className="glass-nav">
          <div className="logo-section">
            <div className="logo-icon"></div>
            <span className="logo-text">NETAUDIT</span>
          </div>

          <div className="nav-actions">
            <button className="secondary-btn" onClick={() => setScreen('upload')}>
              Back
            </button>
            <button className="secondary-btn">How it works</button>
            <button className="primary-btn">Sign Up</button>
          </div>
        </nav>

        {/* Vendor Section */}
        <section className="vendor-screen">
          <div className="vendor-wrapper">
            {/* Heading */}
            <div className="vendor-heading">
              <div className="success-icon">✓</div>

              <p className="small-heading">
                {vendorData.length > 1
                  ? `${vendorData.length} CONFIGURATIONS UPLOADED SUCCESSFULLY`
                  : 'CONFIGURATION UPLOADED SUCCESSFULLY'}
              </p>

              <h1>
                Vendor <span className="gradient-text">Detected</span>
              </h1>

              <p className="vendor-description">
                NetAudit has identified the vendor from your configuration.
                Review the detected vendor before starting the security audit.
              </p>
            </div>

            {/* Detection Information — one card per file */}
            {vendorData.map((v, i) => (
              <div key={i} className="detection-card">
                <div className="detection-item">
                  <div>
                    <span className="detection-label">
                      {v.filename}
                    </span>
                    <p className="detection-vendor">{v.vendor_display}</p>
                  </div>
                  <div className="vendor-check">✓</div>
                </div>
              </div>
            ))}

            {/* Continue Button */}
            <button
              className="continue-audit-btn"
              onClick={handleAudit}
              disabled={loading}
            >
              {loading ? 'Running Audit...' : 'Continue to Security Audit'}
              <span>→</span>
            </button>

            <p className="vendor-note">
              Vendor detection is based on the uploaded configuration syntax.
            </p>
          </div>
        </section>
      </div>
    );
  }

  /* =========================
     UPLOAD SCREEN
     ========================= */
  return (
    <div className="main-container">
      {/* Floating Navbar */}
      <nav className="glass-nav">
        <div className="logo-section">
          <div className="logo-icon"></div>
          <span className="logo-text">NETAUDIT</span>
        </div>

        <div className="nav-actions">
          <button className="secondary-btn">How it works</button>

          <button className="primary-btn">Start Audit</button>

          <button className="secondary-btn">Login</button>

          <button className="primary-btn">Sign Up</button>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="hero-section">
        <h1 className="hero-title">
          Track Your Network Security <br />
          <span className="gradient-text">& Compliance Ratings</span>
        </h1>

        <p className="hero-subtitle">
          Review your infrastructure configurations and check AI-powered
          security feedback across all enterprise vendors.
        </p>
      </section>

      {/* Vendor Marquee */}
      <div className="vendor-marquee">
        <div className="marquee-content">
          {[...vendors, ...vendors].map((vendor, i) => (
            <span key={i} className="vendor-tag">
              {vendor}
            </span>
          ))}
        </div>
      </div>

      {/* Upload Card */}
      <div className="glass-card-container">
        <div className="glass-card">
          <div className="card-header">
            <h3>Upload Configuration</h3>

            <p>Your data is processed locally and stays secure.</p>
          </div>

          {/* Drop Zone */}
          <label className="drop-zone">
            <input
              type="file"
              className="hidden-input"
              multiple
              onChange={(e) => setFiles(Array.from(e.target.files))}
            />

            {files.length === 0 ? (
              <div className="drop-zone-content">
                <div className="upload-circle">
                  <svg
                    width="24"
                    height="24"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                  >
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                    <polyline points="17 8 12 3 7 8" />
                    <line x1="12" y1="3" x2="12" y2="15" />
                  </svg>
                </div>

                <div className="text-stack">
                  <span className="main-label">Select Source File(s)</span>

                  <span className="sub-label">
                    Drag and drop or click to browse — supports multiple files
                  </span>
                </div>
              </div>
            ) : (
              <div className="file-active">
                <div className="status-badge">
                  {files.length === 1 ? 'Ready to Audit' : `${files.length} Files Ready`}
                </div>

                <span className="file-name">
                  {files.length === 1
                    ? files[0].name
                    : files.map((f) => f.name).join(', ')}
                </span>

                <button
                  className="change-link"
                  onClick={(e) => {
                    e.preventDefault();
                    setFiles([]);
                  }}
                >
                  Replace File{files.length > 1 ? 's' : ''}
                </button>
              </div>
            )}
          </label>

          {/* Analyze Button */}
          <button
            className="analyze-btn"
            onClick={handleAnalyze}
            disabled={loading || files.length === 0}
          >
            {loading ? 'Uploading...' : 'Run Security Analysis'}
          </button>
        </div>
      </div>

      {/* Footer */}
      <footer className="footer">
        TRUSTED BY ENTERPRISE SECURITY TEAMS WORLDWIDE
      </footer>
    </div>
  );
}
