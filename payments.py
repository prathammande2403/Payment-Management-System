# routes/payments.py
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
import uuid
from database import get_db
from models import Payment, User, TransactionHistory
from schemas import PaymentCreate, PaymentResponse, WebhookPayload, UserCreate, Token
from utils import encrypt_metadata, decrypt_metadata, verify_webhook_signature
from auth import get_current_user
from utils import get_password_hash, create_access_token
from database import SessionLocal
from fastapi.security import OAuth2PasswordRequestForm

router = APIRouter(prefix="/payments")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ----- Auth endpoints (register/login token) -----
@router.post("/auth/register", status_code=201)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == user_in.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already registered")
    user = User(
        username=user_in.username,
        hashed_password=get_password_hash(user_in.password),
        full_name=user_in.full_name,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"username": user.username, "id": user.id}


@router.post("/auth/token", response_model=Token)
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    from auth import authenticate_user

    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token({"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


# ----- Payment operations -----
@router.post("/send", response_model=PaymentResponse)
def send_payment(
    request: PaymentCreate, db: Session = Depends(get_db), current_user=Depends(get_current_user)
):
    # Map sender/receiver usernames to user IDs if provided; otherwise use current_user as sender
    sender = None
    receiver = None
    if request.sender_username:
        sender = db.query(User).filter(User.username == request.sender_username).first()
    else:
        sender = current_user
    if request.receiver_username:
        receiver = db.query(User).filter(User.username == request.receiver_username).first()

    payment_id = str(uuid.uuid4())
    payment = Payment(
        payment_id=payment_id,
        sender_id=sender.id if sender else None,
        receiver_id=receiver.id if receiver else None,
        amount=request.amount,
        currency=request.currency,
        status="initiated",
    )
    db.add(payment)
    db.commit()
    db.refresh(payment)

    # Add initial transaction history (no metadata)
    tx = TransactionHistory(payment_id=payment.payment_id, status=payment.status, encrypted_metadata=None)
    db.add(tx)
    db.commit()

    return payment


@router.get("/{payment_id}", response_model=PaymentResponse)
def get_payment(
    payment_id: str, db: Session = Depends(get_db), current_user=Depends(get_current_user)
):
    payment = db.query(Payment).filter(Payment.payment_id == payment_id).first()
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")
    return payment


# ----- Webhook endpoint (used by payment gateway to confirm status) -----
@router.post("/webhook")
async def payment_webhook(request: Request, db: Session = Depends(get_db)):
    # Read raw body bytes to verify signature
    payload_bytes = await request.body()
    signature_header = request.headers.get("X-Signature", "")  # provider-specific header
    if not verify_webhook_signature(payload_bytes, signature_header):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid signature")

    # Parse JSON (we use Pydantic schema for clarity)
    import json
    data = json.loads(payload_bytes.decode())
    webhook = WebhookPayload(**data)

    # Find payment
    payment = db.query(Payment).filter(Payment.payment_id == webhook.payment_id).first()
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")

    # Update status
    payment.status = webhook.status
    db.add(payment)

    # Encrypt metadata and store transaction history
    encrypted_meta = None
    if webhook.metadata:
        try:
            encrypted_meta = encrypt_metadata(webhook.metadata)
        except Exception:
            encrypted_meta = None

    tx = TransactionHistory(
        payment_id=payment.payment_id,
        status=webhook.status,
        encrypted_metadata=encrypted_meta,
    )
    db.add(tx)
    db.commit()
    db.refresh(payment)

    return {"ok": True}


# ----- Get transaction history for a payment (protected) -----
@router.get("/{payment_id}/history")
def payment_history(
    payment_id: str, db: Session = Depends(get_db), current_user=Depends(get_current_user)
):
    txs = (
        db.query(TransactionHistory)
        .filter(TransactionHistory.payment_id == payment_id)
        .order_by(TransactionHistory.created_at.desc())
        .all()
    )
    results = []
    for t in txs:
        meta = None
        if t.encrypted_metadata:
            try:
                meta = decrypt_metadata(t.encrypted_metadata)
            except Exception:
                meta = None
        results.append(
            {
                "id": t.id,
                "payment_id": t.payment_id,
                "status": t.status,
                "created_at": t.created_at,
                "metadata": meta,
            }
        )
    return results
