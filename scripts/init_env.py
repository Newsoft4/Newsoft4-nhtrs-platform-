from pathlib import Path
import secrets
from cryptography.fernet import Fernet
root = Path(__file__).resolve().parents[1]
path = root / '.env'
if path.exists():
    raise SystemExit('.env already exists; refusing to replace your secrets.')
values = {
    'DB_PASSWORD': secrets.token_urlsafe(24),
    'JWT_SECRET': secrets.token_urlsafe(48),
    'ENCRYPTION_KEY': Fernet.generate_key().decode(),
    'ID_HASH_SECRET': secrets.token_urlsafe(48),
    'BOOTSTRAP_USERNAME': 'admin',
    'BOOTSTRAP_PASSWORD': secrets.token_urlsafe(24),
    'COOKIE_SECURE': 'false',
    'ALLOWED_ORIGIN': 'http://localhost:8000',
}
with path.open('x') as f:
    f.write(''.join(f'{k}={v}\n' for k,v in values.items()))
path.chmod(0o600)
print('Created .env; secure it and save the one-time bootstrap password in your password manager.')
print('Bootstrap username: admin')
print('Bootstrap password:', values['BOOTSTRAP_PASSWORD'])
