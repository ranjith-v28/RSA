import rsa
from pathlib import Path

# Emoji mapping for all ASCII characters (32-126)
EMOJI_TABLE = [
    "😀", "😃", "😄", "😁", "😆", "😅", "😂", "🤣", "😊", "😇",  # 32-41
    "🙂", "🙃", "😉", "😌", "😍", "🥰", "😘", "😗", "😙", "😚",  # 42-51
    "😋", "😛", "😝", "😜", "🤪", "🤨", "🧐", "🤓", "😎", "🥸",  # 52-61
    "🤩", "🥳", "😏", "😒", "😞", "😔", "😟", "😕", "🙁", "☹️",  # 62-71
    "😣", "😖", "😫", "😩", "🥺", "😢", "😭", "😤", "😠", "😡",  # 72-81
    "🤬", "🤯", "😳", "🥵", "🥶", "😱", "😨", "😰", "😥", "😓",  # 82-91
    "🫣", "🤗", "🫡", "🤔", "🫢", "🤭", "🤫", "🤥", "😶", "🫠",  # 92-101
    "😐", "🫤", "😑", "😬", "🙄", "😯", "😦", "😧", "😮", "🥱",  # 102-111
    "😴", "🤤", "😪", "😵", "🫥", "🤐", "🥴", "🤢", "🤮", "🤕",  # 112-121
    "🤑", "🤠", "😈", "👿", "👹", "👺", "🤡", "💩", "👻", "💀",  # 122-131
    "☠️", "👽", "👾", "🤖", "🎃", "😺", "😸", "😹", "😻", "😼",  # 132-141
    "😽", "🙀", "😿", "😾", "🙈", "🙉", "🙊", "💌", "💘", "💝",  # 142-151
    "💖", "💗", "💓", "💞", "💕", "💟", "❣️", "💔", "❤️", "🧡",  # 152-161
    "💛", "💚", "💙", "💜", "🤎", "🖤", "🤍", "💋", "💯", "🔥"   # 162-171
]
EMOJI_MAP = {e: i+32 for i, e in enumerate(EMOJI_TABLE)}

def generate_keys(key_id):
    """Generate and save RSA key pair"""
    pub_key, priv_key = rsa.newkeys(2048)
    Path('user_keys').mkdir(exist_ok=True)
    
    with open(f'user_keys/{key_id}_pub.pem', 'wb') as f:
        f.write(pub_key.save_pkcs1())
    with open(f'user_keys/{key_id}_priv.pem', 'wb') as f:
        f.write(priv_key.save_pkcs1())
    
    return pub_key.save_pkcs1().decode(), priv_key.save_pkcs1().decode()

def encrypt_message(message, pub_key):
    """Encrypt text → emojis"""
    pub_key = rsa.PublicKey.load_pkcs1(pub_key.encode())
    encrypted = rsa.encrypt(message.encode(), pub_key)
    return ''.join([EMOJI_TABLE[b-32] for b in encrypted if 32 <= b <= 126])

def decrypt_message(emojis, priv_key):
    """Decrypt emojis → text"""
    priv_key = rsa.PrivateKey.load_pkcs1(priv_key.encode())
    encrypted = bytes([EMOJI_MAP[e] for e in emojis if e in EMOJI_MAP])
    return rsa.decrypt(encrypted, priv_key).decode()