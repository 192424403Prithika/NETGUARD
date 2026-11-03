import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import LiveMonitor from './pages/LiveMonitor';
import UploadCSV from './pages/UploadCSV';
import AuditLogs from './pages/AuditLogs';
import Alerts from './pages/Alerts';
import Explainability from './pages/Explainability';
import { api } from './services/api';
import './style.css';

export default function App() {
  const [activeAlertsCount, setActiveAlertsCount] = useState(0);

  const refreshAlertCount = async () => {
    try {
      const res = await api.getAlerts(null, 'ACTIVE');
      setActiveAlertsCount(res.data.length);
    } catch (err) {
      // API may be connecting
    }
  };

  useEffect(() => {
    refreshAlertCount();
    const interval = setInterval(refreshAlertCount, 6000);
    return () => clearInterval(interval);
  }, []);

  return (
    <Router>
      <div className="app-container">
        <Sidebar activeAlertsCount={activeAlertsCount} />
        <main className="main-wrapper">
          <Routes>
            <Route path="/" element={<Dashboard activeAlertsCount={activeAlertsCount} />} />
            <Route 
              path="/live" 
              element={<LiveMonitor activeAlertsCount={activeAlertsCount} onNewAlert={refreshAlertCount} />} 
            />
            <Route 
              path="/upload" 
              element={<UploadCSV activeAlertsCount={activeAlertsCount} onNewAlert={refreshAlertCount} />} 
            />
            <Route path="/logs" element={<AuditLogs activeAlertsCount={activeAlertsCount} />} />
            <Route 
              path="/alerts" 
              element={<Alerts activeAlertsCount={activeAlertsCount} onAlertsUpdated={refreshAlertCount} />} 
            />
            <Route path="/explain" element={<Explainability activeAlertsCount={activeAlertsCount} />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}
