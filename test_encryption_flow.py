import rsa
import base64

EMOJI_MAPPING = [
    "😀", "😃", "😄", "😁", "😆", "😅", "😂", "🤣", "😊", "😇",
    "🙂", "🙃", "😉", "😌", "😍", "🥰", "😘", "😗", "😙", "😚",
    "😋", "😛", "😝", "😜", "🤪", "🤨", "🧐", "🤓", "😎", "🥸",
    "🤩", "🥳", "😏", "😒", "😞", "😔", "😟", "😕", "🙁", "☹️",
    "😣", "😖", "😫", "😩", "🥺", "😢", "😭", "😤", "😠", "😡",
    "🤬", "🤯", "😳", "🥵", "🥶", "😱", "😨", "😰", "😥", "😓",
    "🫣", "🤗", "🫡", "🤔", "🫢", "🤭", "🤫", "🤥", "😶"
]

def bytes_to_emojis(data):
    """Convert bytes to emoji sequence"""
    return ''.join([EMOJI_MAPPING[b % len(EMOJI_MAPPING)] for b in data])

def emojis_to_bytes(emoji_str):
    """Convert emoji sequence back to bytes"""
    emoji_map = {e: i for i, e in enumerate(EMOJI_MAPPING)}
    return bytes([emoji_map[e] for e in emoji_str if e in emoji_map])

def test_encryption_flow():
    print("\n🔍 Testing complete encryption/decryption flow...")
    
    # Step 1: Generate a new key pair
    print("\n1️⃣ Generating new key pair...")
    (pubkey, privkey) = rsa.newkeys(2048)
    
    # Save the keys in the same format as the web interface
    public_key_str = pubkey.save_pkcs1('PEM').decode()
    private_key_str = privkey.save_pkcs1('PEM').decode()
    
    print("\n📝 Generated Public Key:")
    print("-" * 50)
    print(public_key_str)
    print("-" * 50)
    
    print("\n🔒 Generated Private Key:")
    print("-" * 50)
    print(private_key_str)
    print("-" * 50)
    
    # Step 2: Test message
    test_message = "Hello, this is a test message!"
    print(f"\n2️⃣ Original message: {test_message}")
    
    # Step 3: Encrypt
    print("\n3️⃣ Encrypting message...")
    encrypted = rsa.encrypt(test_message.encode(), pubkey)
    print("✅ Encryption successful!")
    print(f"Encrypted data length: {len(encrypted)} bytes")
    
    # Step 4: Convert to emojis
    print("\n4️⃣ Converting to emojis...")
    emojis = bytes_to_emojis(encrypted)
    print("✅ Converted to emojis!")
    print(f"Number of emojis: {len(emojis)}")
    print(f"First few emojis: {emojis[:10]}...")
    
    # Step 5: Convert back to bytes
    print("\n5️⃣ Converting emojis back to bytes...")
    encrypted_data = emojis_to_bytes(emojis)
    print("✅ Converted back to bytes!")
    print(f"Converted data length: {len(encrypted_data)} bytes")
    
    if len(encrypted_data) != len(encrypted):
        print(f"⚠️ Warning: Length mismatch! Original: {len(encrypted)}, Converted: {len(encrypted_data)}")
        return
    
    # Step 6: Decrypt
    print("\n6️⃣ Decrypting message...")
    try:
        decrypted = rsa.decrypt(encrypted_data, privkey).decode()
        print(f"Decrypted message: {decrypted}")
    except rsa.pkcs1.DecryptionError:
        print("❌ Decryption failed - The data appears to be corrupted")
        return
    except Exception as e:
        print(f"❌ Decryption error: {str(e)}")
        return
    
    # Step 7: Verify
    if decrypted == test_message:
        print("\n✅ Test passed! Complete flow is working correctly.")
        print("\n🔑 Use these keys in the web interface:")
        print("\nPublic Key (for encryption):")
        print(public_key_str)
        print("\nPrivate Key (for decryption):")
        print(private_key_str)
    else:
        print("\n❌ Test failed! Decrypted message doesn't match original.")
        print(f"Original: {test_message}")
        print(f"Decrypted: {decrypted}")

if __name__ == '__main__':
    test_encryption_flow() 