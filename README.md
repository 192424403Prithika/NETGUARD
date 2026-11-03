# NetGuard – Intelligent Network Anomaly Detection Web Application
### Hybrid Machine Learning System: Isolation Forest & Autoencoder Neural Network

**Academic Machine Learning Project**  
*Course*: Machine Learning for Electrical / Computer Engineers  
*Authors*: Abinaya Vinoth & B.H. Prithika  
*Faculty Guide*: Dr. Kavitha  

---

## 1. Overview & Problem Statement
Modern networks generate immense volumes of traffic where stealthy malicious intrusion attempts occur among regular benign flows. Traditional rule-based Intrusion Detection Systems (IDS) rely strictly on signature databases and fail against novel zero-day exploits.

**NetGuard** implements a dual-stage hybrid machine learning engine that combines:
1. **Autoencoder (Deep Learning)**: Learns non-linear representations of normal traffic patterns in a compressed latent space ($6 \rightarrow 16 \rightarrow 3 \rightarrow 16 \rightarrow 6$). Anomalous traffic results in high reconstruction Mean Squared Error (MSE).
2. **Isolation Forest (Ensemble Tree Outlier Detection)**: Isolates anomalies by recursive feature partitioning.
3. **Calibrated Hybrid Scoring**:
   $$\text{Hybrid Anomaly Score} = 0.55 \times \text{Norm}(\text{Isolation Forest Score}) + 0.45 \times \text{Norm}(\text{Autoencoder MSE})$$
   - Classification: $\text{Score} \ge 0.50 \implies \text{ANOMALY}$, else $\text{NORMAL}$
   - Severity Ranking: Critical, High, Medium, Low
   - Explainability: Feature-level Mean Squared Error contribution breakdown.

---

## 2. Project Architecture & Visual Alignment
The visual appearance faithfully implements the antique brown and cream theme:
- **Sidebar**: `#5B3B20` with cream rounded active indicator
- **Main Background**: `#F8F6E9`
- **Cards**: `#FFFDF7` with beige borders `#E9E0CC`
- **Primary Buttons**: `#654321`
- **Typography**: Libre Baskerville / Georgia (headings), DM Sans (body), DM Mono (metrics)

---

## 3. Directory Structure
```
Netcare/
├── backend/
│   ├── app/
│   │   ├── database/        # SQLite & SQLAlchemy models/engine
│   │   ├── ml/              # Autoencoder, Isolation Forest, Preprocessor, Hybrid detector
│   │   ├── models/          # DB schemas (Prediction, Alert, AuditLog, ModelMetadata)
│   │   ├── routes/          # REST API endpoints
│   │   ├── schemas/         # Pydantic schemas
│   │   ├── services/        # MLService singleton & data generator
│   │   └── main.py          # FastAPI application & startup lifecycle
│   ├── saved_models/        # Active serialized models
│   ├── uploaded_datasets/   # Processed CSVs
│   ├── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/      # Sidebar, Header
│   │   ├── pages/           # Dashboard, LiveMonitor, UploadCSV, AuditLogs, Alerts, Explainability
│   │   ├── services/        # Axios API client
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   └── style.css
│   ├── package.json
│   └── vite.config.js
├── datasets/                # Sample NSL-KDD benchmark datasets
├── notebooks/
│   └── model_training.ipynb # Jupyter notebook documenting training
├── README.md
└── start_backend.bat / start_frontend.bat
```

---

## 4. Quick Start Instructions

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm

### Step 1: Start Backend (FastAPI + Uvicorn)
```bash
# From project root directory
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
API Documentation will be live at: `http://localhost:8000/docs`

### Step 2: Start Frontend (React + Vite)
```bash
# Open a new terminal in project root
cd frontend
npm run dev
```
Open `http://localhost:5173` in your browser.

---

## 5. Modules Included
1. **Dashboard**: Live database-driven stat cards (Total Inspected, Anomalies Found, Normal, Attack Types), interactive Traffic Trend area chart (Normal vs Anomaly), Attack Type Distribution donut chart, and Avg Anomaly Score bar chart.
2. **Live Monitor**: Continuous packet flow scoring, pause/resume controls, polling interval selector (0.5s - 5.0s), live anomaly score chart with red alert threshold markers, and latest flow inspector.
3. **Upload CSV**: Manual single-flow prediction form (Duration, Src Bytes, Dst Bytes, Protocol, Flag) with instant hybrid scoring, plus large Batch CSV Drag-and-Drop uploader with dataset preview, metrics summary, and exportable predictions CSV.
4. **Alerts Management**: Summary cards (Critical, High, Other), severity filters, expandable alert cards with full flow details, and one-click alert resolution or clearing.
5. **Audit Logs**: Complete persistent history table, search by packet code/protocol/attack family, filter by severity/classification, pagination, detailed inspection modal, and CSV export.
6. **Explainability & Model Calibration**: Decomposition of hybrid score (55% IF + 45% AE), per-feature reconstruction error bar chart, natural language security findings, live threshold sensitivity slider, and academic benchmark evaluation metrics (Accuracy, Precision, Recall, F1, ROC-AUC, FPR, FNR).

