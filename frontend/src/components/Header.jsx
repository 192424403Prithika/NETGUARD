import React, { useState, useEffect } from 'react';

export default function Header({ title, activeAlertsCount = 0 }) {
  const [currentDateTime, setCurrentDateTime] = useState('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      const dd = String(now.getDate()).padStart(2, '0');
      const mm = String(now.getMonth() + 1).padStart(2, '0');
      const yyyy = now.getFullYear();
      const time = now.toLocaleTimeString('en-GB', { hour12: false });
      setCurrentDateTime(`${dd}/${mm}/${yyyy}, ${time}`);
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="page-header">
      <div>
        <h1 className="page-title">{title}</h1>
        <div className="page-timestamp">{currentDateTime}</div>
      </div>
      {activeAlertsCount > 0 && (
        <div className="active-alert-pill">
          <span className="pulse-dot" />
          <span>{activeAlertsCount} Active {activeAlertsCount === 1 ? 'Alert' : 'Alerts'}</span>
        </div>
      )}
    </div>
  );
}

