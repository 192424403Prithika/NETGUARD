@echo off
echo Starting NetGuard Backend API Server on http://localhost:8000 ...
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
pause

