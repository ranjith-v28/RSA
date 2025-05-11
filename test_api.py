import requests
import json
import rsa

def test_api():
    # Base URL
    base_url = 'http://127.0.0.1:5000'
    
    # Read the keys
    with open('user_keys/public_key.pem', 'r') as f:
        public_key = f.read().strip()
    
    with open('user_keys/private_key.pem', 'r') as f:
        private_key = f.read().strip()
    
    # Verify keys can be loaded
    try:
        pub_key = rsa.PublicKey.load_pkcs1(public_key.encode())
        priv_key = rsa.PrivateKey.load_pkcs1(private_key.encode())
        print("\n✅ Keys loaded successfully")
    except Exception as e:
        print(f"\n❌ Error loading keys: {str(e)}")
        return
    
    # Test message
    test_message = "Hello, this is a test message!"
    print(f"\nOriginal message: {test_message}")
    
    try:
        # Test encryption
        print("\nTesting encryption...")
        encrypt_response = requests.post(
            f'{base_url}/encrypt',
            json={
                'message': test_message,
                'public_key': public_key
            }
        )
        
        if encrypt_response.status_code != 200:
            print(f"Encryption failed: {encrypt_response.text}")
            return
            
        encrypted_data = encrypt_response.json()
        print("Encryption successful!")
        print(f"Encrypted emojis: {encrypted_data['emojis']}")
        
        # Test decryption
        print("\nTesting decryption...")
        print("Using private key:", private_key[:50] + "..." if len(private_key) > 50 else private_key)
        
        decrypt_response = requests.post(
            f'{base_url}/decrypt',
            json={
                'emojis': encrypted_data['emojis'],
                'private_key': private_key
            }
        )
        
        if decrypt_response.status_code != 200:
            print(f"Decryption failed: {decrypt_response.text}")
            return
            
        decrypted_data = decrypt_response.json()
        print("Decryption successful!")
        print(f"Decrypted message: {decrypted_data['message']}")
        
        # Verify
        if decrypted_data['message'] == test_message:
            print("\n✅ Test passed! API is working correctly.")
        else:
            print("\n❌ Test failed! Decrypted message doesn't match original.")
            
    except requests.exceptions.ConnectionError:
        print("\n❌ Error: Could not connect to the server. Make sure it's running at http://127.0.0.1:5000")
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")

if __name__ == '__main__':
    test_api() 