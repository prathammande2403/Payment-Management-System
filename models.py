# models.py
from sqlalchemy import Column, String, Float, DateTime, Integer, Text, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=True)

    payments_sent = relationship("Payment", back_populates="sender", foreign_keys="Payment.sender_id")
    payments_received = relationship("Payment", back_populates="receiver", foreign_keys="Payment.receiver_id")

class Payment(Base):
    __tablename__ = "payments"
    payment_id = Column(String, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    receiver_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    amount = Column(Float, nullable=False)
    currency = Column(String, default="INR")
    status = Column(String, default="pending")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    sender = relationship("User", foreign_keys=[sender_id])
    receiver = relationship("User", foreign_keys=[receiver_id])

class TransactionHistory(Base):
    __tablename__ = "transaction_history"
    id = Column(Integer, primary_key=True, index=True)
    payment_id = Column(String, nullable=False, index=True)
    status = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    # encrypted metadata (Fernet) stored as text
    encrypted_metadata = Column(Text, nullable=True)
