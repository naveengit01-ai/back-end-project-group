def rule_reply(message, user):
    msg = message.lower().strip()

    email = user.get("email")
    first = user.get("first_name", "")
    last = user.get("last_name", "")
    role = user.get("user_type", "")

    # ✅ STRICT personal queries only
    if msg in ["my email", "what is my email", "tell me my email"]:
        return f"Your registered email is {email}"

    if msg in ["my name", "what is my name", "tell me my name"]:
        full_name = f"{first} {last}".strip()
        return f"Your name is {full_name}" if full_name else "Your name is not fully updated."

    # ✅ Donations (personal)
    if msg in ["my donations", "donation history", "how many donations i made"]:
        return "I can check your donation history for you."

    # ✅ Rider-specific
    if role == "rider" and msg in ["my rides", "ride history", "completed rides"]:
        return "I can check how many rides you have completed."

    # ✅ Login / Signup ISSUES (not explanations)
    login_keywords = [
        "can't login",
        "cannot login",
        "login problem",
        "login issue",
        "signup problem",
        "signup issue",
        "unable to signup"
    ]
    if any(k in msg for k in login_keywords):
        return (
            "I can help with login or signup issues. "
            "Please tell me what error you are facing."
        )

    # ❌ IMPORTANT: Do NOT intercept project questions
    return None