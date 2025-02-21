import secrets
import string


class Password:
    
    @staticmethod
    def generate(length=8):
        if length < 8:
            raise ValueError("Password length should be at least 8 characters")

        alphabet = string.ascii_letters
        digits = string.digits
        special_characters = string.punctuation

        password = [
            secrets.choice(alphabet.lower()),
            secrets.choice(alphabet.upper()),
            secrets.choice(digits),
            secrets.choice(special_characters)
        ]

        all_characters = alphabet + digits + special_characters
        password += [secrets.choice(all_characters) for _ in range(length - 4)]

        secrets.SystemRandom().shuffle(password)

        return ''.join(password)