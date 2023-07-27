import hashlib
import bcrypt

def evaluate_password_strength(password):
    uniqueness_score = check_uniqueness(password)
    complexity_score = check_complexity(password)
    pattern_score = check_pattern(password)
    if len(password)>8:
        total_score = (complexity_score+pattern_score+uniqueness_score)/3
    else:
        total_score = (complexity_score+pattern_score)/3
    if total_score <= 0.45:
        password_strength = "Weak"
    elif total_score <= 0.65:
        password_strength = "Moderate"
    else:
        password_strength = "Strong"

    return password_strength


def check_uniqueness(password):
    unique_chars = set(password)
    uniqueness_score = len(unique_chars)/len(password)

    return round(uniqueness_score,2)


def check_complexity(password):
    complexity_score = 0.0
    req_met = 0
    # Define complexity requirements
    # complexity_requirements = [
    n = len(password)
    if n>=8:
        req_met = req_met+1 #length
    if any(c.isupper() for c in password):
        req_met = req_met+1 # Uppercase check
    if any(c.islower() for c in password):
        req_met = req_met+1  # Lowercase check
    if any(c.isdigit() for c in password):
        req_met = req_met+1  # Number check
    if any(not c.isalnum() for c in password):
        req_met = req_met+1  # Special character check
    #]

    # Check if all complexity requirements are fulfilled
    # if all(complexity_requirements):
    #     complexity_score = 1.0
    complexity_score = req_met/5
    return round(complexity_score,2)


def check_pattern(password):
    pattern_score = 1.0

    # Define common patterns to avoid in passwords
    common_patterns = [
        '123', 'abc', 'password', 'qwerty', 'admin'
    ]

    # Check if password contains any of the common patterns
    for pattern in common_patterns:
        if pattern in password.lower():
            print(f"Invalid Password. Detected common pattern: {pattern}")
            sub = password.lower().replace(pattern, '')
            pattern_score = len(sub)/len(password)
            break

    return round(pattern_score,2)


def hash_password_sha256(password):
    # Hash the password using SHA-256 algorithm
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password


def hash_password_bcrypt(password):
    # Hash the password using bcrypt algorithm
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password


def test_password(password):
    conditions=[]
    tests = [
        (lambda p: len(p) >= 8, "Minimum length of 8 characters"),
        (lambda p: any(c.isupper() for c in p), "At least one uppercase letter"),
        (lambda p: any(c.islower() for c in p), "At least one lowercase letter"),
        (lambda p: any(c.isdigit() for c in p), "At least one digit"),
        (lambda p: any(not c.isalnum() for c in p), "At least one special character")
    ]

    for test, condition in tests:
        if not test(password):
            conditions.append(condition)
    return conditions


def main():
    password = input("Enter a password: ")

    # Perform password strength analysis
    password_strength = evaluate_password_strength(password)
    if not test_password(password):
        print("Password does not meet all requirements.")

    # Hash the password using SHA-256
    hashed_password_sha256 = hash_password_sha256(password)
    print("SHA-256 Hashed Password:", hashed_password_sha256)

    # Hash the password using bcrypt
    hashed_password_bcrypt = hash_password_bcrypt(password)
    print("bcrypt Hashed Password:", hashed_password_bcrypt)


if __name__ == "__main__":
    main()
    