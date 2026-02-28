def rule_reply(message, user):
    if "my name" in message:
        return f"Your name is {user.get('first_name', 'User')}"

    if "my email" in message:
        return f"Your registered email is {user.get('email')}"

    if "login" in message:
        return (
            "Login help:\n"
            "1. Verify email using OTP\n"
            "2. Select correct role\n"
            "3. Enter correct password"
        )

    if "signup" in message:
        return (
            "Signup steps:\n"
            "1. Fill all details\n"
            "2. Verify OTP\n"
            "3. Login after verification"
        )

    return None