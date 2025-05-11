import rsa
import os

def test_encryption_decryption():
    try:
        # Read the keys
        with open('user_keys/public_key.pem', 'rb') as f:
            public_key = rsa.PublicKey.load_pkcs1(f.read())
            
        with open('user_keys/private_key.pem', 'rb') as f:
            private_key = rsa.PrivateKey.load_pkcs1(f.read())
        
        # Test message
        test_message = "Hello, this is a test message!"
        print(f"\nOriginal message: {test_message}")
        
        # Encrypt
        encrypted = rsa.encrypt(test_message.encode(), public_key)
        print("\nEncryption successful!")
        
        # Decrypt
        decrypted = rsa.decrypt(encrypted, private_key).decode()
        print(f"Decrypted message: {decrypted}")
        
        # Verify
        if decrypted == test_message:
            print("\n✅ Test passed! Keys are working correctly.")
        else:
            print("\n❌ Test failed! Decrypted message doesn't match original.")
            
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")

if __name__ == '__main__':
    test_encryption_decryption() 