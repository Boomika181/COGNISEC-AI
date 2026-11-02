import time
import requests

BASE_URL = "http://127.0.0.1:8000"
BOOTSTRAP_KEY = "cognisec_dev_bootstrap_secret_2026"
TEST_EMAIL = "boomikaram35@gmail.com"

print("=================================================================")
print("COGNISEC-AI ACCOUNT LOCKOUT & RECOVERY END-TO-END VERIFICATION")
print("=================================================================")

# STEP 1: Unlock account initially via authorized dev endpoint
print("\n[STEP 1] Ensuring account is unlocked via dev-unlock-account...")
unlock_res = requests.post(
    f"{BASE_URL}/api/auth/dev-unlock-account",
    headers={"X-Bootstrap-Key": BOOTSTRAP_KEY},
    json={"email": TEST_EMAIL}
)
assert unlock_res.status_code == 200, f"Unlock failed: {unlock_res.text}"
print(f"✓ Account unlocked: {unlock_res.json().get('message')}")

# STEP 2: Verify valid authentication
print("\n[STEP 2] Testing successful login with valid credentials...")
login_ok = requests.post(f"{BASE_URL}/api/auth/login", json={
    "email": TEST_EMAIL,
    "password": "Broostfu35*",
    "application": "HEALTHCARE"
})
assert login_ok.status_code == 200, f"Valid login failed: {login_ok.text}"
print(f"✓ Valid login succeeded: session_id={login_ok.json().get('session_id')}, status={login_ok.json().get('session_status')}")

# STEP 3: Verify incorrect password rejection
print("\n[STEP 3] Testing incorrect password rejection...")
login_fail_1 = requests.post(f"{BASE_URL}/api/auth/login", json={
    "email": TEST_EMAIL,
    "password": "WrongPassword@123",
    "application": "HEALTHCARE"
})
assert login_fail_1.status_code == 401, f"Expected 401, got {login_fail_1.status_code}"
print("✓ Failed attempt 1 rejected with HTTP 401.")

# STEP 4: Trigger 3-attempt lockout
print("\n[STEP 4] Triggering 3-attempt account lockout...")
login_fail_2 = requests.post(f"{BASE_URL}/api/auth/login", json={
    "email": TEST_EMAIL,
    "password": "WrongPassword@123",
    "application": "HEALTHCARE"
})
assert login_fail_2.status_code == 401
print("✓ Failed attempt 2 rejected with HTTP 401.")

login_fail_3 = requests.post(f"{BASE_URL}/api/auth/login", json={
    "email": TEST_EMAIL,
    "password": "WrongPassword@123",
    "application": "HEALTHCARE"
})
assert login_fail_3.status_code == 403, f"Expected 403 on lockout, got {login_fail_3.status_code}"
assert "Account is locked" in login_fail_3.json().get("detail", "")
print("✓ Failed attempt 3 triggered lockout: HTTP 403 'Account is locked. Access denied.'")

# Verify that even correct credentials are now rejected while locked
locked_login = requests.post(f"{BASE_URL}/api/auth/login", json={
    "email": TEST_EMAIL,
    "password": "Broostfu35*",
    "application": "HEALTHCARE"
})
assert locked_login.status_code == 403
assert "Account is locked" in locked_login.json().get("detail", "")
print("✓ Locked account blocks subsequent logins with HTTP 403.")

# STEP 5: Test authorized recovery endpoint
print("\n[STEP 5] Testing authorized dev-unlock-account...")
# Verify unauthorized requests are rejected
bad_key_res = requests.post(
    f"{BASE_URL}/api/auth/dev-unlock-account",
    headers={"X-Bootstrap-Key": "invalid_key"},
    json={"email": TEST_EMAIL}
)
assert bad_key_res.status_code == 403
print("✓ Unauthorized unlock request safely rejected with HTTP 403.")

# Verify authorized unlock
good_unlock = requests.post(
    f"{BASE_URL}/api/auth/dev-unlock-account",
    headers={"X-Bootstrap-Key": BOOTSTRAP_KEY},
    json={"email": TEST_EMAIL}
)
assert good_unlock.status_code == 200
print(f"✓ Authorized unlock succeeded: {good_unlock.json().get('message')}")

# STEP 6: Test secure password-reset flow
print("\n[STEP 6] Testing Secure Password Reset Flow...")
reset_req = requests.post(f"{BASE_URL}/api/auth/password-reset/request", json={"email": TEST_EMAIL})
assert reset_req.status_code == 200, f"Password reset request failed: {reset_req.text}"
reset_data = reset_req.json()
print(f"✓ Password reset code dispatched to {reset_data.get('masked_email')}")

# In exhibition/test mode, the server returns the generated OTP for automated flow testing
reset_otp = reset_data.get("otp")
assert reset_otp is not None, f"Expected demo OTP in response: {reset_data}"

# Set updated password
new_pwd = "Broostfu35*"
verify_reset = requests.post(f"{BASE_URL}/api/auth/password-reset/verify", json={
    "email": TEST_EMAIL,
    "otp_code": reset_otp,
    "new_password": new_pwd,
    "confirm_password": new_pwd
})
assert verify_reset.status_code == 200, f"Password reset verification failed: {verify_reset.text}"
print(f"✓ Password successfully reset: {verify_reset.json().get('message')}")

# STEP 7: Verify successful login creating valid session
print("\n[STEP 7] Verifying login creates valid authenticated session...")
login_active = requests.post(f"{BASE_URL}/api/auth/login", json={
    "email": TEST_EMAIL,
    "password": new_pwd,
    "application": "HEALTHCARE"
})
assert login_active.status_code == 200
login_info = login_active.json()
session_id = login_info["session_id"]
token = login_info["access_token"]
print(f"✓ Authenticated: session_id={session_id}, status={login_info.get('session_status')}")

# STEP 8: Verify 20-second observation and OTP flow
print("\n[STEP 8] Verifying 20-second observation and OTP flow...")
headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

for i in range(21, 0, -5):
    print(f"  Observing telemetry... {i}s remaining")
    time.sleep(5)

login_otp_req = requests.post(f"{BASE_URL}/api/auth/login-otp/request", json={"session_id": session_id}, headers=headers)
assert login_otp_req.status_code == 200, f"Login OTP request failed: {login_otp_req.text}"
otp_info = login_otp_req.json()
print(f"✓ Login OTP dispatched to {otp_info.get('masked_email')}: challenge_id={otp_info.get('challenge_id')}")

login_otp_verify = requests.post(f"{BASE_URL}/api/auth/login-otp/verify", json={
    "session_id": session_id,
    "challenge_id": otp_info.get("challenge_id"),
    "otp_code": otp_info.get("otp")
}, headers=headers)
assert login_otp_verify.status_code == 200
print(f"✓ Login OTP verified! Session is now ACTIVE.")

# STEP 9: Cross-Portal Authentication Verification (College, Shopping, Healthcare)
print("\n[STEP 9] Verifying Cross-Portal Authentication for the same account...")
for portal, app_name in [("College", "COLLEGE"), ("Shopping", "SHOPPING"), ("Healthcare", "HEALTHCARE")]:
    portal_login = requests.post(f"{BASE_URL}/api/auth/login", json={
        "email": TEST_EMAIL,
        "password": new_pwd,
        "application": app_name
    })
    assert portal_login.status_code == 200, f"{portal} login failed: {portal_login.text}"
    p_data = portal_login.json()
    print(f"✓ {portal} Portal authenticated: session_id={p_data.get('session_id')}, role={p_data.get('role')}")

print("\n=================================================================")
print("ALL ACCOUNT LOCKOUT & AUTHENTICATION TESTS PASSED WITH 100% SUCCESS!")
print("=================================================================")
