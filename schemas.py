# schemas.py
from pydantic import BaseModel, Field
from typing import Optional, Any, Dict
from datetime import datetime

class UserCreate(BaseModel):
    username: str
    password: str
    full_name: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    username: Optional[str] = None

class PaymentCreate(BaseModel):
    sender_username: Optional[str] = Field(None, example="alice")
    receiver_username: Optional[str] = Field(None, example="bob")
    amount: float = Field(..., gt=0)
    currency: str = Field(default="INR")

class PaymentResponse(BaseModel):
    payment_id: str
    sender_id: Optional[int]
    receiver_id: Optional[int]
    amount: float
    currency: str
    status: str
    created_at: datetime
    
    class Config:
        orm_mode = True

class WebhookPayload(BaseModel):
    payment_id: str
    status: str
    metadata: Optional[Dict[str, Any]] = None


# python -m uvicorn main:app --reload