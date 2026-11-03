import React, { useState, useEffect, useRef } from 'react';
import { Square, Play, CheckCircle2, AlertTriangle, ShieldAlert } from 'lucide-react';
import { 
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, ReferenceLine 
} from 'recharts';
import Header from '../components/Header';
import { api } from '../services/api';

export default function LiveMonitor({ activeAlertsCount, onNewAlert }) {
  const [isRunning, setIsRunning] = useState(true);
  const [pollInterval, setPollInterval] = useState(0.5); // seconds
  const [inspectedCount, setInspectedCount] = useState(5);
  const [anomaliesCount, setAnomaliesCount] = useState(1);
  const [chartData, setChartData] = useState([
    { time: '00:46:52', score: 0.50, isAnomaly: false },
    { time: '00:46:55', score: 0.51, isAnomaly: true },
    { time: '00:46:58', score: 0.12, isAnomaly: false },
    { time: '00:47:01', score: 0.44, isAnomaly: false },
    { time: '00:47:04', score: 0.23, isAnomaly: false },
  ]);
  const [latestEvent, setLatestEvent] = useState({
    classification: 'NORMAL',
    attack_type: 'Normal',
    timestamp: '2026-03-26T03:17:04.739391',
    protocol: 'TCP',
    src_bytes: 1513,
    dst_bytes: 3952,
    flag: 'REJ',
    duration: '7.30s',
    isolation_forest_score: -0.0865,
    reconstruction_error: 0.00041,
    hybrid_score: 0.2117,
    confidence: 'N/A'
  });

  const timerRef = useRef(null);

  const fetchSample = async () => {
    try {
      const res = await api.getNextLiveSample();
      const { event, total_inspected, anomalies_detected } = res.data;
      
      setInspectedCount(total_inspected);
      setAnomaliesCount(anomalies_detected);
      setLatestEvent(event);

      const isAno = event.classification === 'ANOMALY';
      if (isAno && onNewAlert) {
        onNewAlert();
      }

      setChartData(prev => {
        const next = [...prev, {
          time: event.time_label,
          score: event.hybrid_score,
          isAnomaly: isAno
        }];
        return next.slice(-20); // Keep last 20 points
      });
    } catch (err) {
      console.error('Failed to poll live sample:', err);
    }
  };

  useEffect(() => {
    if (isRunning) {
      timerRef.current = setInterval(fetchSample, pollInterval * 1000);
    } else {
      if (timerRef.current) clearInterval(timerRef.current);
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isRunning, pollInterval]);

  const toggleMonitor = async () => {
    if (isRunning) {
      try {
        await api.stopLive();
      } catch (err) {}
      setIsRunning(false);
    } else {
      try {
        await api.startLive(pollInterval);
      } catch (err) {}
      setIsRunning(true);
    }
  };

  // Custom dot rendering for anomaly markers
  const renderCustomDot = (props) => {
    const { cx, cy, payload } = props;
    if (payload.isAnomaly) {
      return (
        <circle
          key={`dot-${payload.time}`}
          cx={cx}
          cy={cy}
          r={5.5}
          fill="#B52E2E"
          stroke="#FFF"
          strokeWidth={2}
        />
      );
    }
    return null;
  };

  const isLatestAnomaly = latestEvent.classification === 'ANOMALY';

  return (
    <div>
      <Header title="Live Monitor" activeAlertsCount={activeAlertsCount} />

      {/* Top Controls Card */}
      <div className="card live-controls-card">
        <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
          <button
            type="button"
            className={isRunning ? 'btn-danger' : 'btn-primary'}
            onClick={toggleMonitor}
          >
            {isRunning ? <Square size={16} fill="#FFF" /> : <Play size={16} fill="#FFF" />}
            <span>{isRunning ? 'Stop Monitor' : 'Start Monitor'}</span>
          </button>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontFamily: 'DM Mono', fontSize: '0.88rem' }}>
            <span style={{ color: '#A89572' }}>Poll interval:</span>
            <select
              className="form-select"
              style={{ padding: '6px 12px', fontSize: '0.85rem' }}
              value={pollInterval}
              onChange={(e) => setPollInterval(parseFloat(e.target.value))}
            >
              <option value={0.5}>0.5s</option>
              <option value={1.0}>1.0s</option>
              <option value={2.0}>2.0s</option>
              <option value={5.0}>5.0s</option>
            </select>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          {isRunning ? (
            <span className="live-badge">
              <span className="status-dot" style={{ width: 6, height: 6 }} /> LIVE
            </span>
          ) : (
            <span className="paused-badge">PAUSED</span>
          )}
          <span style={{ fontFamily: 'DM Mono', fontSize: '0.86rem', color: '#5B3B20' }}>
            <strong>{inspectedCount}</strong> inspected · <strong>{anomaliesCount}</strong> anomalies
          </span>
        </div>
      </div>

      {/* Live Anomaly Score Chart */}
      <div className="card">
        <h2 className="card-title">Live Anomaly Score</h2>
        <div className="card-subtitle">
          Red dots = detected anomalies · Dashed line = alert threshold (0.5)
        </div>

        <div style={{ width: '100%', height: 320, marginTop: 10 }}>
          <ResponsiveContainer>
            <LineChart data={chartData} margin={{ top: 20, right: 35, left: -10, bottom: 20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#E9E0CC" vertical={false} />
              <XAxis 
                dataKey="time" 
                stroke="#A89572" 
                tick={{ fill: '#A89572', fontSize: 11, fontFamily: 'DM Mono' }} 
              />
              <YAxis 
                domain={[0, 1]} 
                ticks={[0, 0.25, 0.5, 0.75, 1]} 
                stroke="#A89572" 
                tick={{ fill: '#A89572', fontSize: 11, fontFamily: 'DM Mono' }} 
              />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: '#FFFDF7', 
                  border: '1px solid #E9E0CC', 
                  borderRadius: 10, 
                  fontFamily: 'DM Mono' 
                }} 
              />
              <ReferenceLine 
                y={0.5} 
                stroke="#B52E2E" 
                strokeDasharray="4 4" 
                label={{ value: 'Thr', position: 'right', fill: '#B52E2E', fontSize: 11, fontFamily: 'DM Mono' }} 
              />
              <Line 
                type="monotone" 
                dataKey="score" 
                stroke="#8A5A36" 
                strokeWidth={2.5} 
                dot={renderCustomDot} 
                isAnimationActive={false} 
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Latest Traffic Event Card */}
      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {isLatestAnomaly ? (
              <AlertTriangle size={24} color="#B52E2E" />
            ) : (
              <CheckCircle2 size={24} color="#278653" />
            )}
            <span style={{ 
              fontFamily: 'var(--font-serif)', 
              fontSize: '1.25rem', 
              fontWeight: 700, 
              color: isLatestAnomaly ? '#B52E2E' : '#278653' 
            }}>
              {isLatestAnomaly ? `Anomaly Detected — ${latestEvent.attack_type}` : 'Normal Traffic'}
            </span>
          </div>

          <div style={{ fontFamily: 'DM Mono', fontSize: '0.82rem', color: '#A89572' }}>
            {latestEvent.timestamp}
          </div>
        </div>

        <div className="stats-grid" style={{ marginBottom: 16 }}>
          <div className="result-metric-box">
            <div className="metric-label">Protocol</div>
            <div className="metric-val">{latestEvent.protocol}</div>
          </div>
          <div className="result-metric-box">
            <div className="metric-label">Src Bytes</div>
            <div className="metric-val">{Number(latestEvent.src_bytes).toLocaleString()}</div>
          </div>
          <div className="result-metric-box">
            <div className="metric-label">Dst Bytes</div>
            <div className="metric-val">{Number(latestEvent.dst_bytes).toLocaleString()}</div>
          </div>
          <div className="result-metric-box">
            <div className="metric-label">Flag</div>
            <div className="metric-val">{latestEvent.flag}</div>
          </div>
        </div>

        <div className="stats-grid">
          <div className="result-metric-box">
            <div className="metric-label">Duration</div>
            <div className="metric-val">{latestEvent.duration}</div>
          </div>
          <div className="result-metric-box">
            <div className="metric-label">Iso Score</div>
            <div className="metric-val">{Number(latestEvent.isolation_forest_score).toFixed(4)}</div>
          </div>
          <div className="result-metric-box">
            <div className="metric-label">Anomaly Score</div>
            <div className="metric-val" style={{ color: isLatestAnomaly ? '#B52E2E' : '#278653' }}>
              {Number(latestEvent.hybrid_score).toFixed(4)}
            </div>
          </div>
          <div className="result-metric-box">
            <div className="metric-label">Confidence</div>
            <div className="metric-val">{latestEvent.confidence}</div>
          </div>
        </div>

        <div style={{ marginTop: 14, fontFamily: 'DM Mono', fontSize: '0.76rem', color: '#A89572' }}>
          * Mode: Automated network packet/flow simulation for real-time model evaluation and continuous scoring.
        </div>
      </div>
    </div>
  );
}

