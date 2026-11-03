import React, { useState, useEffect } from 'react';
import { AlertCircle, Trash2, ChevronDown, ChevronUp, Bell, Check } from 'lucide-react';
import Header from '../components/Header';
import { api } from '../services/api';

export default function Alerts({ activeAlertsCount, onAlertsUpdated }) {
  const [alerts, setAlerts] = useState([]);
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [expandedAlerts, setExpandedAlerts] = useState({});
  const [loading, setLoading] = useState(true);

  const fetchAlerts = async () => {
    try {
      const res = await api.getAlerts(filterSeverity);
      setAlerts(res.data);
      // Auto expand first alert by default
      if (res.data.length > 0) {
        setExpandedAlerts(prev => ({ [res.data[0].alert_id]: true, ...prev }));
      }
    } catch (err) {
      console.error('Failed to load alerts:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [filterSeverity]);

  const toggleExpand = (alertId) => {
    setExpandedAlerts(prev => ({
      ...prev,
      [alertId]: !prev[alertId]
    }));
  };

  const handleClearAll = async () => {
    if (window.confirm('Are you sure you want to clear all alerts?')) {
      try {
        await api.clearAlerts();
        fetchAlerts();
        if (onAlertsUpdated) onAlertsUpdated();
      } catch (err) {
        console.error('Failed to clear alerts:', err);
      }
    }
  };

  const handleResolve = async (alertId, e) => {
    e.stopPropagation();
    try {
      await api.resolveAlert(alertId);
      fetchAlerts();
      if (onAlertsUpdated) onAlertsUpdated();
    } catch (err) {
      console.error('Failed to resolve alert:', err);
    }
  };

  // Counts for top cards
  const totalAlerts = alerts.length;
  const criticalCount = alerts.filter(a => a.severity === 'CRITICAL').length;
  const highCount = alerts.filter(a => a.severity === 'HIGH').length;
  const otherCount = alerts.filter(a => !['CRITICAL', 'HIGH'].includes(a.severity)).length;

  return (
    <div>
      <Header title="Alerts" activeAlertsCount={activeAlertsCount} />

      {/* 4 Summary Stat Cards */}
      <div className="stats-grid">
        <div className="stat-card">
          <div style={{ textAlign: 'center', width: '100%' }}>
            <div className="stat-value">{totalAlerts}</div>
            <div className="stat-label">Total Alerts</div>
          </div>
        </div>

        <div className="stat-card">
          <div style={{ textAlign: 'center', width: '100%' }}>
            <div className="stat-value" style={{ color: '#B52E2E' }}>{criticalCount}</div>
            <div className="stat-label" style={{ color: '#B52E2E' }}>Critical</div>
          </div>
        </div>

        <div className="stat-card">
          <div style={{ textAlign: 'center', width: '100%' }}>
            <div className="stat-value" style={{ color: '#D47735' }}>{highCount}</div>
            <div className="stat-label" style={{ color: '#D47735' }}>High</div>
          </div>
        </div>

        <div className="stat-card">
          <div style={{ textAlign: 'center', width: '100%' }}>
            <div className="stat-value" style={{ color: '#A89572' }}>{otherCount}</div>
            <div className="stat-label">Other</div>
          </div>
        </div>
      </div>

      {/* Filter Bar & Clear All */}
      <div className="filter-bar">
        <div className="pill-group">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
            <button
              key={sev}
              type="button"
              className={`pill-btn ${filterSeverity === sev ? 'active' : ''}`}
              onClick={() => setFilterSeverity(sev)}
            >
              {sev}
            </button>
          ))}
        </div>

        <button type="button" onClick={handleClearAll} className="btn-outline" style={{ color: '#B52E2E' }}>
          <Trash2 size={15} />
          <span>Clear all</span>
        </button>
      </div>

      {/* Alert Cards List */}
      {alerts.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: '48px 20px', color: '#A89572', fontFamily: 'DM Mono' }}>
          No active alerts matching the selected filter.
        </div>
      ) : (
        alerts.map((alert) => {
          const isExpanded = expandedAlerts[alert.alert_id];
          const isCritical = alert.severity === 'CRITICAL';
          const isHigh = alert.severity === 'HIGH';

          return (
            <div key={alert.alert_id} className="alert-banner">
              <div
                className={`alert-header ${isHigh ? 'high' : !isCritical ? 'medium' : ''}`}
                onClick={() => toggleExpand(alert.alert_id)}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <Bell size={18} />
                  <span className="alert-badge">{alert.severity}</span>
                  <span className="alert-badge">{alert.attack_type}</span>
                  <span style={{ fontWeight: 600, fontSize: '0.95rem' }}>
                    ⚠ {alert.detection_message}
                  </span>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                  <span style={{ fontFamily: 'DM Mono', fontSize: '0.82rem', opacity: 0.9 }}>
                    {alert.timestamp}
                  </span>
                  {alert.status === 'ACTIVE' && (
                    <button
                      type="button"
                      onClick={(e) => handleResolve(alert.alert_id, e)}
                      style={{
                        backgroundColor: 'rgba(255,255,255,0.2)',
                        border: 'none',
                        color: '#FFF',
                        padding: '4px 10px',
                        borderRadius: 6,
                        cursor: 'pointer',
                        fontSize: '0.75rem',
                        fontFamily: 'DM Mono',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 4
                      }}
                      title="Mark as Resolved"
                    >
                      <Check size={12} /> Resolve
                    </button>
                  )}
                  {isExpanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                </div>
              </div>

              {isExpanded && (
                <div className="alert-body">
                  <div className="alert-tiles-grid">
                    <div className="alert-tile">
                      <div className="alert-tile-label">Alert ID</div>
                      <div className="alert-tile-val" style={{ fontSize: '0.82rem' }}>{alert.alert_id}</div>
                    </div>
                    <div className="alert-tile">
                      <div className="alert-tile-label">Attack Type</div>
                      <div className="alert-tile-val">{alert.attack_type}</div>
                    </div>
                    <div className="alert-tile">
                      <div className="alert-tile-label">Severity</div>
                      <div className="alert-tile-val" style={{ color: isCritical ? '#B52E2E' : '#D47735' }}>
                        {alert.severity}
                      </div>
                    </div>
                    <div className="alert-tile">
                      <div className="alert-tile-label">Anomaly Score</div>
                      <div className="alert-tile-val">{alert.anomaly_score.toFixed(3)}</div>
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 16, marginBottom: 16 }}>
                    <div className="alert-tile">
                      <div className="alert-tile-label">Confidence</div>
                      <div className="alert-tile-val">{alert.confidence.toFixed(1)}%</div>
                    </div>
                    <div className="alert-tile">
                      <div className="alert-tile-label">Traffic Info</div>
                      <div className="alert-tile-val" style={{ fontSize: '0.88rem' }}>{alert.traffic_summary}</div>
                    </div>
                  </div>

                  <div className="alert-log-block">
{`⚠ Network anomaly detected!
Attack Type   : ${alert.attack_type}
Confidence    : ${alert.confidence.toFixed(1)}%
Anomaly Score : ${alert.anomaly_score.toFixed(3)}
Protocol      : ${alert.protocol}
Src Bytes     : ${alert.src_bytes}
Dst Bytes     : ${alert.dst_bytes}
Flag          : ${alert.flag}`}
                  </div>
                </div>
              )}
            </div>
          );
        })
      )}
    </div>
  );
}

