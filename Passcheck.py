import re

def password_strength(password):
    score = 0
    suggestions = []

    # Length
    if len(password) >= 8:
        score += 2
    else:
        suggestions.append("Use at least 8 characters.")

    # Uppercase
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        suggestions.append("Add uppercase letters.")

    # Lowercase
    if re.search(r'[a-z]', password):
        score += 1
    else:
        suggestions.append("Add lowercase letters.")

    # Numbers
    if re.search(r'\d', password):
        score += 1
    else:
        suggestions.append("Include numbers.")

    # Special Characters
    if re.search(r'[@$!%*?&#]', password):
        score += 1
    else:
        suggestions.append("Include special characters like @, #, $, etc.")

    # Common Passwords Check
    common_passwords = ['password', '123456', 'qwerty', 'abc123']
    if password.lower() not in common_passwords:
        score += 2
    else:
        suggestions.append("Avoid common passwords.")

    # Final Rating
    if score <= 3:
        rating = "Weak"
    elif score <= 6:
        rating = "Medium"
    else:
        rating = "Strong"

    return rating, score, suggestions


# Example usage
if __name__ == "__main__":
    pwd = input("Enter your password: ")
    rating, score, tips = password_strength(pwd)
    print(f"\nPassword Strength: {rating} (Score: {score}/8)")
    if tips:
        print("Suggestions:")
        for t in tips:
            print("-", t)
