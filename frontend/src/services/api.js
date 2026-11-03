import axios from 'axios';

const API_BASE = 'http://localhost:8000/api';

export const apiClient = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
});

export const api = {
  getHealth: () => apiClient.get('/health'),
  getDashboard: () => apiClient.get('/dashboard'),
  getAlerts: (severity, status) => apiClient.get('/alerts', { params: { severity, status } }),
  clearAlerts: () => apiClient.delete('/alerts'),
  resolveAlert: (alertId) => apiClient.delete(`/alerts/${alertId}`),
  getHistory: (params) => apiClient.get('/history', { params }),
  clearHistory: () => apiClient.delete('/history'),
  predictManual: (data) => apiClient.post('/predict/manual', data),
  predictCsv: (formData) => apiClient.post('/predict/csv', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  }),
  getLiveStatus: () => apiClient.get('/live/status'),
  startLive: (interval = 0.5) => apiClient.post('/live/start', null, { params: { interval } }),
  stopLive: () => apiClient.post('/live/stop'),
  getNextLiveSample: () => apiClient.get('/live/next-sample'),
  getExplainability: (predId) => apiClient.get(`/explain/${predId}`),
  getModelMetrics: () => apiClient.get('/model/metrics'),
  updateThreshold: (threshold, weight_iso = 0.55, weight_ae = 0.45) => 
    apiClient.put('/model/threshold', { threshold, weight_iso, weight_ae }),
  exportPredictionsUrl: `${API_BASE}/export/predictions`,
  exportAlertsUrl: `${API_BASE}/export/alerts`,
};

