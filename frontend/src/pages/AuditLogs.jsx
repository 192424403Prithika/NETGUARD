import React, { useState, useEffect } from 'react';
import { Search, Download, Trash2, Eye, X, Filter } from 'lucide-react';
import Header from '../components/Header';
import { api } from '../services/api';

export default function AuditLogs({ activeAlertsCount }) {
  const [logs, setLogs] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [classFilter, setClassFilter] = useState('ALL');
  const [selectedRecord, setSelectedRecord] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const res = await api.getHistory({
        page,
        limit: 15,
        search: search || undefined,
        severity: severityFilter !== 'ALL' ? severityFilter : undefined,
        classification: classFilter !== 'ALL' ? classFilter : undefined,
      });
      setLogs(res.data.items);
      setTotalCount(res.data.total);
      setTotalPages(res.data.total_pages || 1);
    } catch (err) {
      console.error('Failed to load history:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [page, severityFilter, classFilter]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPage(1);
    fetchLogs();
  };

  const handleClearHistory = async () => {
    if (window.confirm('Are you sure you want to permanently clear the audit & prediction history?')) {
      try {
        await api.clearHistory();
        setPage(1);
        fetchLogs();
      } catch (err) {
        console.error('Failed to clear history:', err);
      }
    }
  };

  return (
    <div>
      <Header title="Audit Logs" activeAlertsCount={activeAlertsCount} />

      {/* Control / Filter Bar */}
      <div className="card" style={{ padding: '18px 24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16 }}>
          <form onSubmit={handleSearchSubmit} style={{ display: 'flex', gap: 10, flex: 1, maxWidth: 360 }}>
            <div style={{ position: 'relative', width: '100%' }}>
              <Search size={16} color="#A89572" style={{ position: 'absolute', left: 12, top: 12 }} />
              <input
                type="text"
                placeholder="Search by Code, Protocol, Attack..."
                className="form-input"
                style={{ paddingLeft: 36, width: '100%' }}
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <button type="submit" className="btn-primary" style={{ padding: '8px 16px' }}>
              Search
            </button>
          </form>

          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <select
              className="form-select"
              value={severityFilter}
              onChange={(e) => { setSeverityFilter(e.target.value); setPage(1); }}
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="NORMAL">Normal</option>
            </select>

            <select
              className="form-select"
              value={classFilter}
              onChange={(e) => { setClassFilter(e.target.value); setPage(1); }}
            >
              <option value="ALL">All Status</option>
              <option value="ANOMALY">Anomaly</option>
              <option value="NORMAL">Normal</option>
            </select>

            <a href={api.exportPredictionsUrl} className="btn-outline" style={{ textDecoration: 'none' }}>
              <Download size={14} /> Export CSV
            </a>

            <button type="button" onClick={handleClearHistory} className="btn-outline" style={{ color: '#B52E2E' }}>
              <Trash2 size={14} /> Clear
            </button>
          </div>
        </div>
      </div>

      {/* Table Card */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="table-container">
          <table className="custom-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>TIMESTAMP</th>
                <th>CLASSIFICATION</th>
                <th>SCORE</th>
                <th>SEVERITY</th>
                <th>PROTOCOL</th>
                <th>SRC BYTES</th>
                <th>DST BYTES</th>
                <th>ATTACK FAMILY</th>
                <th style={{ textAlign: 'center' }}>ACTION</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={10} style={{ textAlign: 'center', padding: 32, color: '#A89572' }}>
                    Loading audit records...
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={10} style={{ textAlign: 'center', padding: 32, color: '#A89572' }}>
                    No audit records found.
                  </td>
                </tr>
              ) : (
                logs.map((log) => {
                  const isAno = log.classification === 'ANOMALY';
                  return (
                    <tr key={log.id}>
                      <td style={{ fontWeight: 600 }}>{log.id}</td>
                      <td style={{ fontSize: '0.8rem', color: '#7E6B56' }}>{log.timestamp}</td>
                      <td>
                        <span className={`badge ${isAno ? 'badge-critical' : 'badge-normal'}`}>
                          {log.classification}
                        </span>
                      </td>
                      <td style={{ fontWeight: 700, color: isAno ? '#B52E2E' : '#278653' }}>
                        {log.hybrid_score.toFixed(4)}
                      </td>
                      <td>
                        <span className={`badge ${
                          log.severity === 'CRITICAL' ? 'badge-critical' :
                          log.severity === 'HIGH' ? 'badge-high' : 'badge-normal'
                        }`}>
                          {log.severity}
                        </span>
                      </td>
                      <td>{log.protocol}</td>
                      <td>{Number(log.src_bytes).toLocaleString()}</td>
                      <td>{Number(log.dst_bytes).toLocaleString()}</td>
                      <td style={{ fontWeight: 600 }}>{log.attack_type}</td>
                      <td style={{ textAlign: 'center' }}>
                        <button
                          type="button"
                          onClick={() => setSelectedRecord(log)}
                          className="btn-outline"
                          style={{ padding: '4px 10px', fontSize: '0.78rem' }}
                        >
                          <Eye size={13} /> View
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '14px 24px',
          borderTop: '1px solid #E9E0CC',
          fontFamily: 'DM Mono',
          fontSize: '0.82rem',
          color: '#A89572'
        }}>
          <div>
            Showing <strong>{logs.length}</strong> of <strong>{totalCount}</strong> records
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              type="button"
              className="btn-outline"
              disabled={page <= 1}
              onClick={() => setPage(p => Math.max(1, p - 1))}
              style={{ padding: '4px 12px' }}
            >
              Previous
            </button>
            <span style={{ display: 'flex', alignItems: 'center', padding: '0 8px', color: '#5B3B20', fontWeight: 600 }}>
              Page {page} of {totalPages}
            </span>
            <button
              type="button"
              className="btn-outline"
              disabled={page >= totalPages}
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              style={{ padding: '4px 12px' }}
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* Record Inspection Modal */}
      {selectedRecord && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0,0,0,0.45)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 200,
          padding: 20
        }}>
          <div className="card" style={{ maxWidth: 640, width: '100%', maxHeight: '90vh', overflowY: 'auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
              <div>
                <h3 className="card-title">Record #{selectedRecord.id}</h3>
                <div style={{ fontFamily: 'DM Mono', fontSize: '0.8rem', color: '#A89572' }}>
                  {selectedRecord.prediction_code}
                </div>
              </div>
              <button
                type="button"
                onClick={() => setSelectedRecord(null)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#5B3B20' }}
              >
                <X size={22} />
              </button>
            </div>

            <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(2, 1fr)', marginBottom: 20 }}>
              <div className="alert-tile">
                <div className="alert-tile-label">Classification</div>
                <div className="alert-tile-val" style={{ color: selectedRecord.classification === 'ANOMALY' ? '#B52E2E' : '#278653' }}>
                  {selectedRecord.classification} ({selectedRecord.attack_type})
                </div>
              </div>
              <div className="alert-tile">
                <div className="alert-tile-label">Hybrid Score</div>
                <div className="alert-tile-val">{selectedRecord.hybrid_score.toFixed(4)}</div>
              </div>
              <div className="alert-tile">
                <div className="alert-tile-label">Isolation Forest Score</div>
                <div className="alert-tile-val">{selectedRecord.isolation_forest_score.toFixed(4)}</div>
              </div>
              <div className="alert-tile">
                <div className="alert-tile-label">Autoencoder Reconstruction Error</div>
                <div className="alert-tile-val">{selectedRecord.reconstruction_error.toFixed(6)}</div>
              </div>
            </div>

            <h4 style={{ fontFamily: 'var(--font-serif)', fontSize: '0.98rem', marginBottom: 10 }}>
              Network Flow Attributes
            </h4>
            <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)', marginBottom: 20 }}>
              <div className="alert-tile info">
                <div className="alert-tile-label">Protocol</div>
                <div className="alert-tile-val">{selectedRecord.protocol}</div>
              </div>
              <div className="alert-tile info">
                <div className="alert-tile-label">Flag</div>
                <div className="alert-tile-val">{selectedRecord.flag}</div>
              </div>
              <div className="alert-tile info">
                <div className="alert-tile-label">Duration</div>
                <div className="alert-tile-val">{selectedRecord.duration}s</div>
              </div>
              <div className="alert-tile info">
                <div className="alert-tile-label">Src Bytes</div>
                <div className="alert-tile-val">{Number(selectedRecord.src_bytes).toLocaleString()}</div>
              </div>
              <div className="alert-tile info">
                <div className="alert-tile-label">Dst Bytes</div>
                <div className="alert-tile-val">{Number(selectedRecord.dst_bytes).toLocaleString()}</div>
              </div>
              <div className="alert-tile info">
                <div className="alert-tile-label">Packet Count</div>
                <div className="alert-tile-val">{selectedRecord.packet_count}</div>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button
                type="button"
                className="btn-primary"
                onClick={() => setSelectedRecord(null)}
              >
                Close Record
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

