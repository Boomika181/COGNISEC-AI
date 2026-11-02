import time
import requests
import concurrent.futures

BASE_URL = "http://127.0.0.1:8000"

print("=================================================================")
print("COGNISEC-AI HEALTHCARE APPOINTMENT OTP END-TO-END VERIFICATION")
print("=================================================================")

# 1. Login with authoritative registered account
print("\n[STEP 1] Logging in as authenticated user boomikaram35@gmail.com...")
login_res = requests.post(f"{BASE_URL}/api/auth/login", json={
    "email": "boomikaram35@gmail.com",
    "password": "Broostfu35*",
    "application": "HEALTHCARE"
})
assert login_res.status_code == 200, f"Login failed: {login_res.text}"
login_data = login_res.json()
token = login_data["access_token"]
session_id = login_data["session_id"]
print(f"✓ Authenticated: email={login_data.get('email')}, session_id={session_id}, status={login_data.get('session_status')}")

headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

# 2. Wait for 20-second observation window
print("\n[STEP 2] Waiting for 20-second behavioral observation window...")
for i in range(21, 0, -5):
    print(f"  Observing telemetry... {i}s remaining")
    time.sleep(5)
print("  Observation window complete.")

# 3. Request and verify login OTP
print("\n[STEP 3] Requesting Login OTP...")
login_otp_req = requests.post(f"{BASE_URL}/api/auth/login-otp/request", json={"session_id": session_id}, headers=headers)
assert login_otp_req.status_code == 200, f"Login OTP request failed: {login_otp_req.text}"
login_otp_data = login_otp_req.json()
masked_login_email = login_otp_data.get("masked_email")
print(f"✓ Login OTP dispatched to {masked_login_email}: challenge_id={login_otp_data.get('challenge_id')}")
assert masked_login_email == "b***5@gmail.com", f"Expected b***5@gmail.com, got {masked_login_email}"

login_otp_val = login_otp_data.get("otp")
login_verify = requests.post(f"{BASE_URL}/api/auth/login-otp/verify", json={
    "session_id": session_id,
    "challenge_id": login_otp_data.get("challenge_id"),
    "otp_code": login_otp_val
}, headers=headers)
assert login_verify.status_code == 200, f"Login OTP verify failed: {login_verify.text}"
print(f"✓ Login OTP verified. Session status is now ACTIVE!")

# 4. Appointment OTP Concurrent Dispatch Test
print("\n[STEP 4] Testing Concurrent Appointment OTP Requests (Duplicate Prevention)...")
apt_payload = {
    "session_id": session_id,
    "doctor_id": "doc-2",
    "appointment_date": "2026-11-18",
    "time_slot": "03:00 PM",
    "patient_name": "Boomika Ram",
    "patient_phone": "+91 98765 43210",
    "patient_email": "boomikaram35@gmail.com",
    "department": "Neurology",
    "consultation_mode": "In-Person Hospital Visit",
    "room": "OPD Room 204"
}

def send_apt_req(idx):
    res = requests.post(f"{BASE_URL}/api/healthcare/appointment-otp/request", json=apt_payload, headers=headers)
    return idx, res.status_code, res.json()

with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
    futures = [executor.submit(send_apt_req, i) for i in range(2)]
    results = [f.result() for f in futures]

status_codes = [r[1] for r in results]
print(f"Concurrent requests completed with statuses: {status_codes}")

# Exactly one should be 200, the other should be 429
assert 200 in status_codes, "At least one request must succeed with 200"
assert 429 in status_codes, f"The concurrent request must be rejected with 429, but got: {status_codes}"
print("✓ Concurrency protection verified: exactly ONE request proceeded; duplicate request blocked with HTTP 429.")

success_res = next(r[2] for r in results if r[1] == 200)
challenge_id_1 = success_res["challenge_id"]
otp_code_1 = success_res["otp"]
masked_email = success_res["masked_email"]
print(f"✓ Valid Appointment OTP issued: challenge_id={challenge_id_1}, recipient={masked_email}")
assert masked_email == "b***5@gmail.com", f"Expected b***5@gmail.com, got {masked_email}"

# 5. Cooldown Test
print("\n[STEP 5] Testing Cooldown Enforcement...")
cooldown_res = requests.post(f"{BASE_URL}/api/healthcare/appointment-otp/request", json=apt_payload, headers=headers)
print(f"Immediate request returned status {cooldown_res.status_code}: {cooldown_res.json().get('detail')}")
assert cooldown_res.status_code == 429
print("✓ Cooldown enforced: subsequent request within 15s blocked with HTTP 429.")

# 6. Resend OTP Test after Cooldown
print("\n[STEP 6] Waiting 16s for cooldown to test OTP Resend...")
time.sleep(16)
resend_res = requests.post(f"{BASE_URL}/api/healthcare/appointment-otp/resend", json={
    "session_id": session_id,
    "challenge_id": challenge_id_1
}, headers=headers)
print(f"Resend status {resend_res.status_code}: {resend_res.json().get('message')}")
assert resend_res.status_code == 200, f"Resend failed: {resend_res.text}"
resend_data = resend_res.json()
challenge_id_2 = resend_data.get("challenge_id")
otp_code_2 = resend_data.get("otp")
print(f"✓ Fresh challenge issued: new_challenge_id={challenge_id_2}")
assert challenge_id_2 != challenge_id_1

# Verify old challenge/code fails
old_code_verify = requests.post(f"{BASE_URL}/api/healthcare/appointment-otp/verify", json={
    "session_id": session_id,
    "challenge_id": challenge_id_1,
    "otp_code": otp_code_1
}, headers=headers)
assert old_code_verify.status_code == 400
print("✓ Old OTP code correctly invalidated by resend.")

# 7. Wrong Code Verification Test on new challenge
print("\n[STEP 7] Testing Wrong OTP Code Rejection & Attempt Counter...")
wrong_verify = requests.post(f"{BASE_URL}/api/healthcare/appointment-otp/verify", json={
    "session_id": session_id,
    "challenge_id": challenge_id_2,
    "otp_code": "000000"
}, headers=headers)
print(f"Wrong code status {wrong_verify.status_code}: {wrong_verify.json().get('detail')}")
assert wrong_verify.status_code == 400
assert "2 attempt(s) remaining" in wrong_verify.json().get("detail")
print("✓ Wrong OTP rejected; remaining attempts decremented to 2.")

# 8. Correct Code Verification Test on new challenge
print("\n[STEP 8] Testing Correct Appointment OTP Verification...")
correct_verify = requests.post(f"{BASE_URL}/api/healthcare/appointment-otp/verify", json={
    "session_id": session_id,
    "challenge_id": challenge_id_2,
    "otp_code": otp_code_2
}, headers=headers)
print(f"Correct code status {correct_verify.status_code}: {correct_verify.json().get('message')}")
assert correct_verify.status_code == 200, f"Verification failed: {correct_verify.text}"
confirm_data = correct_verify.json()
reference_id = confirm_data.get("reference_id")
apt_info = confirm_data.get("appointment", {})
print(f"✓ Appointment CONFIRMED! Reference Token: {reference_id}")
print(f"  Doctor: {apt_info.get('doctor_name')}")
print(f"  Date & Time: {apt_info.get('appointment_date')} @ {apt_info.get('time_slot')}")
print(f"  Consultation Mode: {apt_info.get('consultation_mode')}")

# 9. Replay Test
print("\n[STEP 9] Testing Replay Attack Prevention...")
replay_verify = requests.post(f"{BASE_URL}/api/healthcare/appointment-otp/verify", json={
    "session_id": session_id,
    "challenge_id": challenge_id_2,
    "otp_code": otp_code_2
}, headers=headers)
print(f"Replay verification status {replay_verify.status_code}: {replay_verify.json().get('detail')}")
assert replay_verify.status_code == 400
print("✓ Replay rejected: consumed code cannot be reused.")

# 10. Database Persistence Verification
print("\n[STEP 10] Verifying PostgreSQL Records...")
import sys
sys.path.insert(0, './backend')
from app.database.connection import SessionLocal
from app.models.otp_challenge import OTPChallenge
from app.models.appointment import HealthcareAppointment

db = SessionLocal()
otp1 = db.query(OTPChallenge).filter(OTPChallenge.challenge_id == challenge_id_1).first()
assert otp1 is not None and otp1.is_consumed == True
assert otp1.recipient_email == "boomikaram35@gmail.com"
print(f"✓ Challenge 1 ({challenge_id_1}) recorded in DB: recipient={otp1.recipient_email}, is_consumed={otp1.is_consumed}")

otp2 = db.query(OTPChallenge).filter(OTPChallenge.challenge_id == challenge_id_2).first()
assert otp2 is not None and otp2.is_consumed == True
assert otp2.recipient_email == "boomikaram35@gmail.com"
print(f"✓ Challenge 2 ({challenge_id_2}) recorded in DB: recipient={otp2.recipient_email}, is_consumed={otp2.is_consumed}")

apt_rec = db.query(HealthcareAppointment).filter(HealthcareAppointment.reference_id == reference_id).first()
assert apt_rec is not None and apt_rec.status == "CONFIRMED"
assert apt_rec.patient_email == "boomikaram35@gmail.com"
print(f"✓ Appointment {reference_id} found in DB with status CONFIRMED and patient_email=boomikaram35@gmail.com.")

print("\n=================================================================")
print("ALL 10 VERIFICATION STEPS PASSED WITH 100% SUCCESS!")
print("=================================================================")
