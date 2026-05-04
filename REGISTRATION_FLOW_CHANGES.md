# 3FA Registration Flow Enhancement

## Problem Statement
Previously, when a user created an account, they were immediately logged in and could access the application without completing all three authentication factors. This posed a security risk as the 3FA requirement was not enforced during the registration process.

## Solution Implemented
Modified the registration flow to **enforce mandatory 3-factor authentication completion before granting full access** to the application.

## New Registration Flow

### Before Changes ❌
```
User Registration
     ↓
Create Account + Set Session
     ↓
Redirect to /inventory (LOGGED IN!)
     ↓
User can skip TOTP/FIDO2 setup
```

### After Changes ✅
```
User Registration (Password Selected)
     ↓
Create Account + Set REGISTRATION_IN_PROGRESS Flag
     ↓
Force TOTP Setup & Verification
     ↓
Force FIDO2 Setup & Registration
     ↓
Remove REGISTRATION_IN_PROGRESS Flag
     ↓
Redirect to /inventory (Fully Authenticated with All 3 Factors)
```

## Detailed Changes

### 1. Registration Endpoint (`POST /register`)
**File:** `app.py` (lines 595-610)

**Changes:**
- After creating user account, set `registration_in_progress=True` in session
- User is NOT fully authenticated yet
- Redirect to `/registration/totp_setup` instead of inventory/settings

**Code:**
```python
# Set registration state - user must complete 3FA before full login
reset_session(
    request,
    username=username,
    user_id=uid,
    registration_in_progress=True,
    authenticator_preference=(...),
)
mark_auth_method(request, "password")

# Redirect to mandatory TOTP setup during registration
return RedirectResponse(url="/registration/totp_setup", status_code=302)
```

### 2. New: Mandatory TOTP Setup During Registration

**Endpoints:** 
- `GET /registration/totp_setup` - Display QR code
- `POST /registration/totp_setup` - Verify TOTP code

**Features:**
- User must scan QR code and enter 6-digit code
- Sets `totp_verified=True` flag
- Redirects to FIDO2 setup on success
- Uses new `get_registration_user()` dependency to ensure user is in registration flow

**Code Guard:**
```python
def get_registration_user(request: Request):
    """Check if user is in registration flow."""
    username = request.session.get("username")
    if not username or not request.session.get("registration_in_progress"):
        raise HTTPException(status_code=403, detail="Not in registration flow")
    return username
```

### 3. New: Mandatory FIDO2 Setup During Registration

**Endpoints:**
- `GET /registration/fido_setup` - Display FIDO2 registration page
- `POST /registration/fido_setup` - Complete FIDO2 registration

**Features:**
- Checks that TOTP was verified first
- User must register security key or biometric
- Clears `registration_in_progress` flag on success
- Marks all 3 auth methods as complete
- Redirects to `/inventory` as fully authenticated

**Code:**
```python
# Registration complete!
request.session.pop("registration_in_progress", None)
mark_auth_method(request, "fido")

return {
    "success": True,
    "message": "3FA setup complete! You are now fully authenticated.",
    "redirect": "/inventory",
}
```

### 4. Protected Pages Updated

**Updated Pages to Redirect During Registration:**
- `/dashboard` - Redirects to `/registration/totp_setup` if `registration_in_progress` is true
- `/inventory` - Same protection
- `/auth/success` - Same protection

**Code Example:**
```python
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, username: str = Depends(get_current_user)):
    # Redirect to registration if still in progress
    if request.session.get("registration_in_progress"):
        return RedirectResponse(url="/registration/totp_setup", status_code=302)
    # ... rest of page logic
```

## User Experience Flow

### Step 1: Registration Page
- Enter username
- Enter password
- Confirm password
- **CHECK:** Enable TOTP (required)
- **CHECK:** Enable Security Key OR Biometric (required)
- Click "Register"

### Step 2: TOTP Setup (Mandatory)
- Display QR code
- Scan with authenticator app (Google Authenticator, Authy, Microsoft Authenticator)
- Enter 6-digit code from app
- Verify code
- → Continue to FIDO2 Setup

### Step 3: FIDO2 Setup (Mandatory)
- Click "Register Security Key" or use Biometric
- Follow browser prompts to register authenticator
- Authenticator is registered
- → Registration Complete ✅

### Step 4: Fully Authenticated
- Automatically redirected to `/inventory`
- All 3 authentication factors verified:
  1. ✅ Password
  2. ✅ TOTP (Time-based One-Time Password)
  3. ✅ FIDO2 (Security Key or Biometric)

## Security Benefits

1. **Enforced 3FA Requirement:** Cannot create account without all 3 factors
2. **No Weak Accounts:** Every registered user is fully secured
3. **Registration Flow Control:** Users cannot skip authentication setup
4. **Session Gating:** Protected pages redirect back if registration incomplete
5. **Clear State Tracking:** `registration_in_progress` flag prevents unauthorized access

## Testing the New Flow

1. Start the application:
   ```bash
   cd d:\3fa
   python app.py
   ```

2. Navigate to `http://localhost:8000/register`

3. Create a new account with:
   - Username: `testuser`
   - Password: `TestPass123`
   - Enable TOTP: ✓
   - Enable FIDO2 or Biometric: ✓

4. You will be **forced** through TOTP setup, then FIDO2 setup

5. Only after completing both can you access the application

## Backwards Compatibility

- Existing login flow (`/login`) is unchanged
- Existing users with incomplete 3FA are redirected to `/settings` on login
- Only new registrations follow the mandatory 3FA flow
- No database schema changes required

## Files Modified

- `app.py` - Main application file with registration flow changes
  - Lines 595-610: Registration endpoint changes
  - Lines 611-620: Dashboard protection
  - Lines 621-640: Auth success page protection  
  - Lines 641-650: Inventory page protection
  - Lines 872-1050: New registration flow endpoints

## Notes

- TOTP and FIDO2 secrets are still stored in the database during setup
- Session encryption remains the same
- Rate limiting still applies to registration attempts
- All audit logging remains in place
