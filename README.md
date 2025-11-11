# 💳 Payment Management API (FastAPI + JWT + Webhooks)

A secure backend API for managing user authentication, payments, and transaction history — inspired by real-world fintech systems like **PayU**.  
Built with **FastAPI**, **JWT authentication**, and **webhook** integration for payment confirmation.

---

## 🚀 Features

✅ **JWT Authentication** – Secure user registration and login system using password hashing and token-based authentication.  
✅ **Payment Management** – Create and retrieve payments for authenticated users.  
✅ **Webhook Integration** – Simulated webhook endpoint to handle asynchronous payment confirmations.  
✅ **Encrypted Storage** – Sensitive transaction data encrypted using AES.  
✅ **Modular Architecture** – Separate routes for authentication, payments, and webhook.  
✅ **Interactive API Docs** – Auto-generated Swagger UI available at `/docs`.

---

## 🧱 Tech Stack

- **Backend Framework:** FastAPI  
- **Authentication:** OAuth2 + JWT (via `python-jose`, `passlib`)  
- **Database:** SQLite (can be replaced with PostgreSQL/MySQL easily)  
- **Server:** Uvicorn  
- **Encryption:** Cryptography  
- **Frontend (optional):** Streamlit or Swagger UI

---

## 📁 Project Structure

