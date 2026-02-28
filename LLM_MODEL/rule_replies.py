def rule_reply(message, user):
    message = message.lower()

    # 👤 PROFILE
    if "my email" in message:
        return f"Your registered email is {user.get('email', 'not found')}"

    if "my name" in message:
        first = user.get("first_name", "")
        last = user.get("last_name", "")
        return f"Your name is {first} {last}".strip()

    # ❤️ DONATIONS
    if "my donations" in message:
        return "I can check your donation history for you."

    # 💼 JOBS
    if "my jobs" in message or "job applications" in message:
        return "I can help you with your job applications."

    # 🔐 LOGIN / SIGNUP
    if "login" in message or "sign up" in message or "signup" in message:
        return "If you're facing login or signup issues, I can guide you step by step."

    return None