# COGNISEC-AI: Agentic Cognitive Zero Trust Identity Protection System

**COGNISEC-AI** is a continuous authentication and behavioral security platform engineered for multi-application zero-trust defense. It passively collects behavioral biometrics (keystroke dynamics, cursor velocity vectors, interaction entropy) without recording passwords or private content, continuously evaluates cognitive risk via statistical baselines (Welford algorithm) and a scikit-learn **Isolation Forest** anomaly detector, and dynamically enforces zero-trust policy decisions across multiple web applications.

---

## Key Architecture & Capabilities

### 1. Behavioral Biometric Telemetry
- **Passive Ingestion**: Ingests client-side timing, flight/dwell times, mouse velocity, acceleration, click patterns, and idle periods without capturing sensitive text or passwords.
- **Privacy-Preserving**: Only numerical interaction dynamics are computed on the client and sent to the backend.

### 2. Adaptive Profiling & Anomaly Detection
- **Welford Incremental Baseline**: Tracks user-specific typing and cursor movement baselines using Welford's algorithm for online variance and mean computation.
- **Isolation Forest ML Model**: Unsupervised anomaly detection trained per-user to identify behavioral deviations.
- **Anti-Poisoning & Cold-Start Guard**: Suspicious or high-risk telemetry is blocked from contaminating the legitimate user baseline.

### 3. Risk Engine & Continuous Zero-Trust Decisions
- **Multi-Factor Risk Scoring**: Evaluates anomaly scores, device trust, session state, and interaction patterns.
- **Dynamic Policy Actions**:
  - `ALLOW` (Low Risk): Uninterrupted access.
  - `STEP_UP_REQUIRED` (Medium Risk): Requires secondary authentication challenge to restore normal access.
  - `TERMINATE` (High Risk): Immediate session revocation and kill switch activation.

### 4. SOC Command Center & Admin Dashboard
- Live security KPIs (active sessions, blocked ATOs, threat alerts).
- Real-time audit event stream and device fingerprint inventory.
- Interactive attack simulator for controlled security evaluations (e.g., impossible travel, abnormal typing/cursor dynamics, session hijacking).

### 5. Protected Demo Applications
1. 🎓 **BITS Pilani Academic Portal** (`college.html`) — DigiLocker Aadhaar verification, anti-proxy exam proctoring shield.
2. 💎 **Nyraa Luxe Retail** (`shopping.html`) — High-value protected checkout, passive biometric payment defense.
3. 🩺 **AyuSync MedCare Network** (`healthcare.html`) — ABDM ABHA Health ID shield, EHR workstation proximity guard.
4. 🛡️ **SOC Command Center** (`index.html`) — Real-time telemetry dashboard, threat radar, audit timeline, and attack simulator.

---

## Technology Stack

- **Backend**: Python 3 / FastAPI (Asynchronous REST API)
- **Database**: PostgreSQL (e.g., Neon Cloud PostgreSQL) or SQLite with SQLAlchemy 2.0 ORM
- **Machine Learning**: NumPy, Pandas, Scikit-learn (Isolation Forest)
- **Authentication**: Bcrypt password hashing & JWT Access Tokens (Role-Based: `USER` & `ADMIN`)
- **Frontend**: Vanilla HTML5, CSS3, JavaScript (ES6+), Three.js / Canvas visual HUD

---

## Database Configuration

The application supports persistent databases via SQLAlchemy:
- **Neon PostgreSQL**: For production/cloud deployment, supply your Neon connection string via the `DATABASE_URL` environment variable.
- **SQLite (Development Fallback)**: By default, if no `DATABASE_URL` is configured, the application falls back to a local SQLite database (`sqlite:///./cognisec.db`).

---

## Environment Variable Setup

1. Copy the example environment file:
   ```bash
   cp backend/.env.example backend/.env
   ```

2. Configure the variables in `backend/.env`:
   ```env
   PROJECT_NAME=COGNISEC-AI
   ENVIRONMENT=development
   API_V1_STR=/api
   SECRET_KEY=your-secure-secret-key-here
   ALGORITHM=HS256
   ACCESS_TOKEN_EXPIRE_MINUTES=1440

   # Database Connection String (Neon PostgreSQL or SQLite)
   DATABASE_URL=postgresql://USER:PASSWORD@HOST/DATABASE

   # Allowed CORS Origins
   CORS_ORIGINS=["http://localhost:3000","http://localhost:5500","http://127.0.0.1:3000","http://127.0.0.1:5500","http://localhost:8000","http://127.0.0.1:8000","null","*"]

   # Risk Engine Thresholds
   RISK_THRESHOLD_LOW=0.30
   RISK_THRESHOLD_MEDIUM=0.65
   RISK_THRESHOLD_HIGH=0.85
   ```

> **Note**: Never commit `backend/.env` containing real credentials or secret keys to version control.

---

## Local Setup & Quickstart

### 1. Backend Setup
```bash
# Navigate to backend directory
cd backend

# Install Python dependencies
pip3 install -r requirements.txt

# Seed default demo accounts and initial dataset
python3 seed_data.py

# Start FastAPI server on port 8000
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 2. Frontend Launch
In a separate terminal from the root workspace directory:
```bash
# Serve static frontend on port 5500
python3 -m http.server 5500
```

### 3. Access URLs
- **Main Platform & 3D HUD Landing Page**: [http://localhost:5500/index.html](http://localhost:5500/index.html)
- **College Portal (BITS Pilani)**: [http://localhost:5500/college.html](http://localhost:5500/college.html)
- **E-Commerce Portal (Nyraa Luxe Retail)**: [http://localhost:5500/shopping.html](http://localhost:5500/shopping.html)
- **Healthcare Portal (AyuSync MedCare)**: [http://localhost:5500/healthcare.html](http://localhost:5500/healthcare.html)
- **FastAPI Interactive Swagger Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc Interactive Documentation**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

### 4. Default Seeded Credentials
- **SOC Administrator**: `admin.soc@cognisec.ai` / `Admin@123`
- **Standard User**: `user.portal@cognisec.ai` / `User@123`
- **College Student**: `student.alex@veritas.edu` / `Student@123`
- **E-Commerce VIP**: `customer.jane@auraluxe.com` / `Customer@123`
- **Healthcare Doctor**: `dr.sarah@aetheriahealth.org` / `Doctor@123`

---

## Running Automated Tests

Run the test suite with `pytest`:
```bash
python3 -m pytest backend/tests/ -v
```
All unit and integration tests covering authentication, session management, behavioral telemetry, Welford profiling, Isolation Forest anomaly detection, risk engine policies, and attack simulations will execute.
