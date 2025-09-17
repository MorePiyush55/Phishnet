import secrets
import base64

# Generate encryption key (32 bytes for Fernet)
encryption_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
print(f"ENCRYPTION_KEY={encryption_key}")

# Generate JWT secret (32 bytes)
jwt_secret = secrets.token_urlsafe(32)
print(f"SECRET_KEY={jwt_secret}")
