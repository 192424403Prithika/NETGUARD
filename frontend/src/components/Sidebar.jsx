import React, { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, 
  Radio, 
  Upload, 
  FileText, 
  Bell, 
  Lightbulb 
} from 'lucide-react';
import { api } from '../services/api';

export default function Sidebar({ activeAlertsCount = 0 }) {
  const [isApiOnline, setIsApiOnline] = useState(true);

  useEffect(() => {
    const checkHealth = async () => {
      try {
        await api.getHealth();
        setIsApiOnline(true);
      } catch (err) {
        setIsApiOnline(false);
      }
    };
    checkHealth();
    const interval = setInterval(checkHealth, 10000);
    return () => clearInterval(interval);
  }, []);

  const navItems = [
    { name: 'Dashboard', path: '/', icon: LayoutDashboard },
    { name: 'Live Monitor', path: '/live', icon: Radio },
    { name: 'Upload CSV', path: '/upload', icon: Upload },
    { name: 'Audit Logs', path: '/logs', icon: FileText },
    { name: 'Alerts', path: '/alerts', icon: Bell, badge: activeAlertsCount },
    { name: 'Explainability', path: '/explain', icon: Lightbulb },
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="brand-logo-box">NG</div>
        <div className="brand-info">
          <span className="brand-title">NetGuard</span>
          <span className="brand-subtitle">Anomaly Detection</span>
        </div>
      </div>

      <div className="sidebar-status">
        <span className={`status-dot ${isApiOnline ? '' : 'offline'}`} />
        <span>{isApiOnline ? 'API Online' : 'API Offline'}</span>
      </div>

      <nav className="sidebar-nav">
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.name}
              to={item.path}
              className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
            >
              <div className="nav-link-content">
                <Icon size={18} strokeWidth={2} />
                <span className="nav-text">{item.name}</span>
              </div>
              {item.badge !== undefined && item.badge > 0 && (
                <span className="nav-badge">{item.badge}</span>
              )}
            </NavLink>
          );
        })}
      </nav>
    </aside>
  );
}

