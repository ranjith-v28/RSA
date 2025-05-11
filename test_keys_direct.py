import rsa
import os

def test_keys_directly():
    try:
        print("\n🔍 Testing RSA key pair directly...")
        
        # Read the keys
        with open('user_keys/public_key.pem', 'rb') as f:
            public_key = rsa.PublicKey.load_pkcs1(f.read())
            
        with open('user_keys/private_key.pem', 'rb') as f:
            private_key = rsa.PrivateKey.load_pkcs1(f.read())
        
        # Print key information
        print(f"\nPublic Key (n): {public_key.n}")
        print(f"Private Key (n): {private_key.n}")
        
        # Verify they are a pair
        if public_key.n != private_key.n:
            print("\n❌ Error: Keys are not a matching pair!")
            return
            
        print("\n✅ Keys are a matching pair!")
        
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
    test_keys_directly() 