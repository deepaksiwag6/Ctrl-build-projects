from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from apscheduler.schedulers.background import BackgroundScheduler
import models
from database import engine
from api import routes
import os
import worker

# Create database tables
models.Base.metadata.create_all(bind=engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Start the background scheduler
    scheduler = BackgroundScheduler()
    scheduler.add_job(worker.smart_rescan_job, 'interval', minutes=10) # Run every 10 min for demo
    scheduler.start()
    yield
    # Shutdown
    scheduler.shutdown()

app = FastAPI(title="PhishShield API", lifespan=lifespan)

# Configure CORS for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # For dev purposes
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(routes.router, prefix="/api")

@app.get("/")
def read_root():
    return {"message": "Welcome to PhishShield API"}

# middleware config 99278

# middleware config 69065

# middleware config 77294

# middleware config 87364
