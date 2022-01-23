import hashlib

def get_hash(data):
    return hashlib.sha256(data.encode('utf-8')).hexdigest()