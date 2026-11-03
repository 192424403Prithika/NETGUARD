import React, { useState } from 'react';
import { Send, UploadCloud, FileText, CheckCircle2, AlertTriangle, Download } from 'lucide-react';
import Header from '../components/Header';
import { api } from '../services/api';

export default function UploadCSV({ activeAlertsCount, onNewAlert }) {
  // Manual Sample Form State
  const [formData, setFormData] = useState({
    duration: 0.5,
    src_bytes: 30000,
    dst_bytes: 25000,
    protocol: 'TCP',
    flag: 'REJ',
    packet_count: 12
  });
  const [manualLoading, setManualLoading] = useState(false);
  const [predictionResult, setPredictionResult] = useState(null);

  // Batch CSV Upload State
  const [dragActive, setDragActive] = useState(false);
  const [batchLoading, setBatchLoading] = useState(false);
  const [batchResult, setBatchResult] = useState(null);
  const [uploadError, setUploadError] = useState('');

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: ['duration', 'src_bytes', 'dst_bytes', 'packet_count'].includes(name) 
        ? parseFloat(value) || 0 
        : value
    }));
  };

  const handleManualSubmit = async (e) => {
    e.preventDefault();
    setManualLoading(true);
    try {
      const res = await api.predictManual(formData);
      setPredictionResult(res.data);
      if (res.data.classification === 'ANOMALY' && onNewAlert) {
        onNewAlert();
      }
    } catch (err) {
      console.error('Manual prediction failed:', err);
    } finally {
      setManualLoading(false);
    }
  };

  const handleFileUpload = async (file) => {
    if (!file || !file.name.endsWith('.csv')) {
      setUploadError('Please select a valid .csv file.');
      return;
    }
    setUploadError('');
    setBatchLoading(true);

    const data = new FormData();
    data.append('file', file);

    try {
      const res = await api.predictCsv(data);
      setBatchResult(res.data);
      if (res.data.anomalous_records > 0 && onNewAlert) {
        onNewAlert();
      }
    } catch (err) {
      setUploadError(err.response?.data?.detail || 'Failed to process CSV file.');
    } finally {
      setBatchLoading(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  const downloadSampleCsv = () => {
    const csvContent = 
`duration,src_bytes,dst_bytes,protocol,flag,packet_count,label
0.5,30000,25000,TCP,REJ,12,R2L
0.1,65000,40,TCP,S0,140,DoS
1.2,120,0,TCP,S0,2,Probe
4.8,1240,4820,TCP,SF,18,Normal
0.05,420,0,UDP,SF,2,Normal
0.8,28500,22100,TCP,REJ,15,R2L
0.01,89000,0,ICMP,SF,95,DoS
6.5,2100,8900,TCP,SF,24,Normal`;

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'netguard_sample_traffic.csv';
    a.click();
    window.URL.revokeObjectURL(url);
  };

  return (
    <div>
      <Header title="Upload CSV" activeAlertsCount={activeAlertsCount} />

      {/* Section A: Manual Sample Prediction */}
      <div className="card">
        <h2 className="card-title">Manual Sample Prediction</h2>
        <form onSubmit={handleManualSubmit} style={{ marginTop: 20 }}>
          <div className="form-grid">
            <div className="form-group">
              <label className="form-label">Duration (s)</label>
              <input
                type="number"
                step="0.01"
                name="duration"
                className="form-input"
                value={formData.duration}
                onChange={handleInputChange}
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">Src Bytes</label>
              <input
                type="number"
                name="src_bytes"
                className="form-input"
                value={formData.src_bytes}
                onChange={handleInputChange}
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">Dst Bytes</label>
              <input
                type="number"
                name="dst_bytes"
                className="form-input"
                value={formData.dst_bytes}
                onChange={handleInputChange}
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">Protocol</label>
              <select
                name="protocol"
                className="form-select"
                value={formData.protocol}
                onChange={handleInputChange}
              >
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMP">ICMP</option>
              </select>
            </div>

            <div className="form-group">
              <label className="form-label">Flag</label>
              <select
                name="flag"
                className="form-select"
                value={formData.flag}
                onChange={handleInputChange}
              >
                <option value="SF">SF</option>
                <option value="S0">S0</option>
                <option value="REJ">REJ</option>
                <option value="RSTO">RSTO</option>
                <option value="SH">SH</option>
              </select>
            </div>
          </div>

          <button type="submit" className="btn-primary" disabled={manualLoading}>
            <Send size={16} />
            <span>{manualLoading ? 'Running Prediction...' : 'Run Prediction'}</span>
          </button>
        </form>

        {/* Prediction Result Display */}
        {predictionResult && (
          <div className={`result-card ${predictionResult.classification === 'ANOMALY' ? 'anomaly' : 'normal'}`}>
            <div className="result-header">
              <div className="result-title">
                {predictionResult.classification === 'ANOMALY' ? (
                  <>
                    <AlertTriangle size={20} color="#B52E2E" />
                    <span>ANOMALY — {predictionResult.attack_type}</span>
                  </>
                ) : (
                  <>
                    <CheckCircle2 size={20} color="#278653" />
                    <span>NORMAL TRAFFIC</span>
                  </>
                )}
              </div>
              <div className="result-confidence">
                Confidence: {predictionResult.confidence.toFixed(1)}%
              </div>
            </div>

            <div className="result-metrics-grid">
              <div className="result-metric-box">
                <div className="metric-label">Anomaly Score</div>
                <div className="metric-val">{predictionResult.hybrid_score.toFixed(4)}</div>
              </div>
              <div className="result-metric-box">
                <div className="metric-label">ISO Score</div>
                <div className="metric-val">{predictionResult.isolation_forest_score.toFixed(4)}</div>
              </div>
              <div className="result-metric-box">
                <div className="metric-label">MSE Score</div>
                <div className="metric-val">{predictionResult.reconstruction_error.toFixed(6)}</div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Section B: Batch CSV Upload */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <h2 className="card-title">Batch CSV Upload</h2>
          <button type="button" onClick={downloadSampleCsv} className="btn-outline">
            <Download size={14} />
            <span>Download Sample CSV</span>
          </button>
        </div>

        <div
          onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
          onDragLeave={() => setDragActive(false)}
          onDrop={handleDrop}
          onClick={() => document.getElementById('csvFileInput').click()}
          style={{
            border: `2px dashed ${dragActive ? '#654321' : '#E9E0CC'}`,
            borderRadius: 16,
            padding: '48px 20px',
            textAlign: 'center',
            cursor: 'pointer',
            backgroundColor: dragActive ? '#F4EEDB' : '#FFFDF7',
            transition: 'all 0.2s ease',
          }}
        >
          <input
            id="csvFileInput"
            type="file"
            accept=".csv"
            style={{ display: 'none' }}
            onChange={(e) => {
              if (e.target.files && e.target.files[0]) {
                handleFileUpload(e.target.files[0]);
              }
            }}
          />
          <UploadCloud size={40} color="#A89572" style={{ marginBottom: 12 }} />
          <div style={{ fontFamily: 'DM Mono', fontSize: '0.95rem', color: '#49321F', fontWeight: 600 }}>
            {batchLoading ? 'Processing Dataset & Running Hybrid Model...' : 'Drop CSV here or click to browse'}
          </div>
          <div style={{ fontFamily: 'DM Mono', fontSize: '0.78rem', color: '#A89572', marginTop: 6 }}>
            Supports standard network datasets (NSL-KDD, CICIDS2017, UNSW-NB15)
          </div>
        </div>

        {uploadError && (
          <div style={{ color: '#B52E2E', fontFamily: 'DM Mono', fontSize: '0.85rem', marginTop: 14 }}>
            Error: {uploadError}
          </div>
        )}

        {/* Batch Result Report */}
        {batchResult && (
          <div style={{ marginTop: 24 }}>
            <div className="stats-grid">
              <div className="stat-card">
                <div>
                  <div className="stat-value">{batchResult.total_records}</div>
                  <div className="stat-label">Total Records</div>
                  <div className="stat-subtext">Processed in {batchResult.processing_time}</div>
                </div>
              </div>
              <div className="stat-card">
                <div>
                  <div className="stat-value" style={{ color: '#278653' }}>{batchResult.normal_records}</div>
                  <div className="stat-label">Normal Records</div>
                  <div className="stat-subtext">Verified safe</div>
                </div>
              </div>
              <div className="stat-card">
                <div>
                  <div className="stat-value" style={{ color: '#B52E2E' }}>{batchResult.anomalous_records}</div>
                  <div className="stat-label">Anomalous Records</div>
                  <div className="stat-subtext">{batchResult.anomaly_percentage}% anomaly rate</div>
                </div>
              </div>
              <div className="stat-card">
                <div>
                  <div className="stat-value" style={{ fontSize: '1.25rem' }}>{batchResult.filename}</div>
                  <div className="stat-label">Batch Dataset</div>
                  <div className="stat-subtext">{batchResult.columns.length} features mapped</div>
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 16 }}>
              <a href={api.exportPredictionsUrl} className="btn-primary" style={{ textDecoration: 'none' }}>
                <Download size={16} />
                <span>Download Prediction Results (CSV)</span>
              </a>
            </div>

            {/* Dataset Preview Table */}
            <div style={{ marginTop: 20 }}>
              <h3 style={{ fontFamily: 'var(--font-serif)', fontSize: '1.05rem', marginBottom: 12 }}>
                Dataset Preview (Top 5 Rows)
              </h3>
              <div className="table-container">
                <table className="custom-table">
                  <thead>
                    <tr>
                      {batchResult.columns.map((c, i) => (
                        <th key={i}>{c}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {batchResult.preview.map((row, rIdx) => (
                      <tr key={rIdx}>
                        {batchResult.columns.map((c, cIdx) => (
                          <td key={cIdx}>{row[c] !== undefined ? String(row[c]) : '-'}</td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

