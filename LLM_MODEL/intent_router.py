def detect_intent(message: str):
    if "login" in message:
        return "LOGIN"
    if "signup" in message:
        return "SIGNUP"
    if "otp" in message:
        return "OTP"
    if "donate" in message:
        return "DONATE"
    if "error" in message:
        return "ERROR"
    return "UNKNOWN"