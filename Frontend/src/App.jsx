import React, { useState } from 'react';
import './App.css';

export default function App() {
  const [file, setFile] = useState(null);
  const vendors = [
    'CISCO',
    'FORTINET',
    'PALO ALTO',
    'JUNIPER',
    'CHECK POINT',
    'ARISTA',
    'F5 NETWORKS',
  ];

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

      {/* Side Scroll Animation (Vendor Marquee) */}
      <div className="vendor-marquee">
        <div className="marquee-content">
          {[...vendors, ...vendors].map((vendor, i) => (
            <span key={i} className="vendor-tag">
              {vendor}
            </span>
          ))}
        </div>
      </div>

      {/* Glassmorphism Upload Card */}
      <div className="glass-card-container">
        <div className="glass-card">
          <div className="card-header">
            <h3>Upload Configuration</h3>
            <p>Your data is processed locally and stays secure.</p>
          </div>

          <label className="drop-zone">
            <input
              type="file"
              className="hidden-input"
              onChange={(e) => setFile(e.target.files[0])}
            />
            {!file ? (
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
                  <span className="main-label">Select Source File</span>
                  <span className="sub-label">
                    Drag and drop or click to browse
                  </span>
                </div>
              </div>
            ) : (
              <div className="file-active">
                <div className="status-badge">Ready to Audit</div>
                <span className="file-name">{file.name}</span>
                <button
                  className="change-link"
                  onClick={(e) => {
                    e.preventDefault();
                    setFile(null);
                  }}
                >
                  Replace File
                </button>
              </div>
            )}
          </label>

          <button className="analyze-btn">Run Security Analysis</button>
        </div>
      </div>

      <footer className="footer">
        TRUSTED BY ENTERPRISE SECURITY TEAMS WORLDWIDE
      </footer>
    </div>
  );
}
