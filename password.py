import random
import string


def validate_password(password):
    if len(password) < 8:
        print("Error: Password should be at least 8 characters long.")
        return False
    elif not any(char.isdigit() for char in password):
        print("Error: Password should contain at least one digit.")
        return False
    elif not any(char.islower() for char in password):
        print("Error: Password should contain at least one lowercase letter.")
        return False
    elif not any(char.isupper() for char in password):
        print("Error: Password should contain at least one uppercase letter.")
        return False
    elif not any(char in "!@#$%^&*()-_=+[]{}\|;:'\"<>,.?/" for char in password):
        print("Error: Password should contain at least one special character.")
        return False
    else:
        return True

def generate_random_password(length=12):
    while True:
        # Generate a random password of specified length
        password = ''.join(random.choices(string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}\\|;:'\"<>,.?/", k=length))

        # Check if the generated password meets the requirements
        if validate_password(password):
            return password

# Sample usage
password = generate_random_password()
print("Randomly generated password:", password)
