def rule_reply(message, user):
    msg = message.lower()

    email = user["email"] if "email" in user else None
    first = user["first_name"] if "first_name" in user else ""
    last = user["last_name"] if "last_name" in user else ""
    role = user.get("user_type", "")

    if "my email" in msg or "email" in msg:
        return f"Your registered email is {email}"

    if "my name" in msg or "name" in msg:
        return f"Your name is {first} {last}".strip()

    if "donation" in msg:
        return "I can check your donation history."

    if role == "rider" and "ride" in msg:
        return "I can check your rides."

    if "login" in msg or "signup" in msg:
        return "I can help you with login or signup issues."

    return None