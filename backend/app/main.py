import os
import sys
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

# Ensure backend root is on Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.app.database.database import engine, Base, SessionLocal
from backend.app.database.seeder import seed_database_if_empty
from backend.app.routes.api import router as api_router
from backend.app.services.ml_service import MLService

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: create tables, load ML models, seed baseline data
    print("Initializing NetGuard Backend Service...")
    Base.metadata.create_all(bind=engine)
    
    # Initialize ML service
    ml_service = MLService.get_instance()
    
    # Seed database
    db = SessionLocal()
    try:
        seed_database_if_empty(db)
    finally:
        db.close()
    
    print("NetGuard Anomaly Detection Engine is ready and running.")
    yield
    print("Shutting down NetGuard Backend Service...")

app = FastAPI(
    title="NetGuard – Intelligent Network Anomaly Detection API",
    description="Full-stack hybrid machine learning system utilizing Isolation Forest and Autoencoder neural networks.",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for frontend Vite development server & localhost
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(api_router)

@app.get("/")
def root():
    return {
        "system": "NetGuard Network Anomaly Detection System",
        "api_docs": "/docs",
        "health": "/api/health"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)

