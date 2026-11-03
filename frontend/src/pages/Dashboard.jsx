import React, { useEffect, useState } from 'react';
import { Activity, AlertTriangle, ShieldCheck, TrendingUp } from 'lucide-react';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, 
  PieChart, Pie, Cell, BarChart, Bar, Legend 
} from 'recharts';
import Header from '../components/Header';
import { api } from '../services/api';

const PIE_COLORS = ['#8A3FFC', '#0072C3', '#FF832B', '#DA1E28', '#198038'];

export default function Dashboard({ activeAlertsCount }) {
  const [stats, setStats] = useState({
    total_inspected: 138,
    anomalies_found: 37,
    anomaly_percentage: 26.8,
    normal_traffic: 101,
    attack_types_count: 3,
    traffic_trend: [],
    attack_type_distribution: [],
    avg_anomaly_score_over_time: [],
  });
  const [loading, setLoading] = useState(true);

  const fetchDashboardData = async () => {
    try {
      const res = await api.getDashboard();
      setStats(res.data);
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 6000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div>
      <Header title="Dashboard" activeAlertsCount={activeAlertsCount} />

      {/* 4 Stats Cards */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon-wrapper">
            <Activity size={22} />
          </div>
          <div>
            <div className="stat-value">{stats.total_inspected}</div>
            <div className="stat-label">Total Inspected</div>
            <div className="stat-subtext">All traffic samples</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon-wrapper">
            <AlertTriangle size={22} color="#B52E2E" />
          </div>
          <div>
            <div className="stat-value" style={{ color: '#B52E2E' }}>{stats.anomalies_found}</div>
            <div className="stat-label">Anomalies Found</div>
            <div className="stat-subtext">{stats.anomaly_percentage}% of total</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon-wrapper">
            <ShieldCheck size={22} color="#278653" />
          </div>
          <div>
            <div className="stat-value" style={{ color: '#278653' }}>{stats.normal_traffic}</div>
            <div className="stat-label">Normal Traffic</div>
            <div className="stat-subtext">Cleared samples</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon-wrapper">
            <TrendingUp size={22} />
          </div>
          <div>
            <div className="stat-value">{stats.attack_types_count}</div>
            <div className="stat-label">Attack Types</div>
            <div className="stat-subtext">Distinct categories</div>
          </div>
        </div>
      </div>

      {/* Traffic Trend: Normal vs Anomaly Chart */}
      <div className="card">
        <h2 className="card-title">Traffic Trend — Normal vs Anomaly</h2>
        <div style={{ width: '100%', height: 320, marginTop: 16 }}>
          <ResponsiveContainer>
            <AreaChart data={stats.traffic_trend} margin={{ top: 10, right: 30, left: 0, bottom: 20 }}>
              <defs>
                <linearGradient id="colorNormal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#5B3B20" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#5B3B20" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="colorAnomaly" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#B52E2E" stopOpacity={0.35} />
                  <stop offset="95%" stopColor="#B52E2E" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#E9E0CC" vertical={false} />
              <XAxis dataKey="time" stroke="#A89572" tick={{ fill: '#A89572', fontSize: 11, fontFamily: 'DM Mono' }} />
              <YAxis stroke="#A89572" tick={{ fill: '#A89572', fontSize: 11, fontFamily: 'DM Mono' }} />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: '#FFFDF7', 
                  border: '1px solid #E9E0CC', 
                  borderRadius: 10, 
                  fontFamily: 'DM Mono',
                  boxShadow: '0 4px 12px rgba(91, 59, 32, 0.08)'
                }} 
              />
              <Area type="monotone" dataKey="Normal" stroke="#5B3B20" strokeWidth={2.5} fillOpacity={1} fill="url(#colorNormal)" />
              <Area type="monotone" dataKey="Anomaly" stroke="#B52E2E" strokeWidth={2.5} fillOpacity={1} fill="url(#colorAnomaly)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
        <div style={{ display: 'flex', justifyContent: 'center', gap: 24, fontFamily: 'DM Mono', fontSize: '0.82rem', marginTop: -10 }}>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color: '#5B3B20' }}>
            <span style={{ width: 12, height: 3, backgroundColor: '#5B3B20', borderRadius: 2 }} /> Normal
          </span>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color: '#B52E2E' }}>
            <span style={{ width: 12, height: 3, backgroundColor: '#B52E2E', borderRadius: 2 }} /> Anomaly
          </span>
        </div>
      </div>

      {/* Bottom Grid: Attack Distribution & Avg Score */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: 20 }}>
        <div className="card">
          <h2 className="card-title">Attack Type Distribution</h2>
          <div style={{ width: '100%', height: 260 }}>
            <ResponsiveContainer>
              <PieChart>
                <Pie
                  data={stats.attack_type_distribution}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={95}
                  paddingAngle={4}
                  dataKey="value"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  labelLine={{ stroke: '#A89572', strokeWidth: 1 }}
                >
                  {stats.attack_type_distribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#FFFDF7', 
                    border: '1px solid #E9E0CC', 
                    borderRadius: 10, 
                    fontFamily: 'DM Mono' 
                  }} 
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <h2 className="card-title">Avg Anomaly Score Over Time</h2>
          <div style={{ width: '100%', height: 260, marginTop: 10 }}>
            <ResponsiveContainer>
              <BarChart data={stats.avg_anomaly_score_over_time} margin={{ top: 10, right: 10, left: -15, bottom: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E9E0CC" vertical={false} />
                <XAxis dataKey="timestamp" stroke="#A89572" tick={{ fill: '#A89572', fontSize: 10, fontFamily: 'DM Mono' }} />
                <YAxis domain={[0, 1]} stroke="#A89572" tick={{ fill: '#A89572', fontSize: 10, fontFamily: 'DM Mono' }} />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#FFFDF7', 
                    border: '1px solid #E9E0CC', 
                    borderRadius: 10, 
                    fontFamily: 'DM Mono' 
                  }} 
                />
                <Bar dataKey="score" fill="#755030" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
}

