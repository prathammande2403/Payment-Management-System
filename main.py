from fastapi import FastAPI
from auth import router as auth_router
from payments import router as payments_router
from database import Base, engine
import models

app = FastAPI(title="Payment API")

# Initialize the database
Base.metadata.create_all(bind=engine)

# Include routes
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(payments_router, prefix="/api", tags=["Payments"])

@app.get("/")
def home():
    return {"message": "Payment API with JWT auth & webhook ready."}
