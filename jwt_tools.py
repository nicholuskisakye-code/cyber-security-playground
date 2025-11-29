
import jwt, time, os
SECRET = os.environ.get('CYBER_PLAYGROUND_SECRET','nemesis-secret-please-change')

def create_jwt(payload: dict, exp_seconds=3600):
    data = dict(payload)
    data['iat'] = int(time.time())
    data['exp'] = int(time.time()) + exp_seconds
    return jwt.encode(data, SECRET, algorithm='HS256')

def decode_jwt(token: str):
    return jwt.decode(token, SECRET, algorithms=['HS256'])
