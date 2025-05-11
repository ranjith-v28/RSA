import rsa
import base64

def test_my_keys(public_key_str, private_key_str, test_message="Hello, this is a test!"):
    try:
        print("\n🔍 Testing your RSA key pair...")
        
        # Clean up the keys
        public_key_str = public_key_str.strip()
        private_key_str = private_key_str.strip()
        
        print("\n📝 Public Key:")
        print("-" * 50)
        print(public_key_str)
        print("-" * 50)
        
        print("\n🔒 Private Key:")
        print("-" * 50)
        print(private_key_str)
        print("-" * 50)
        
        # Load the keys
        try:
            pub_key = rsa.PublicKey.load_pkcs1(public_key_str.encode())
            print("\n✅ Public key loaded successfully")
            print(f"Public key modulus (n): {pub_key.n}")
        except Exception as e:
            print(f"\n❌ Error loading public key: {str(e)}")
            return
            
        try:
            priv_key = rsa.PrivateKey.load_pkcs1(private_key_str.encode())
            print("\n✅ Private key loaded successfully")
            print(f"Private key modulus (n): {priv_key.n}")
        except Exception as e:
            print(f"\n❌ Error loading private key: {str(e)}")
            return
        
        # Verify they are a pair
        if pub_key.n != priv_key.n:
            print("\n❌ Error: Keys are not a matching pair!")
            print("The modulus (n) values don't match between public and private keys")
            return
            
        print("\n✅ Keys are a matching pair!")
        
        # Test encryption/decryption
        print(f"\nOriginal message: {test_message}")
        
        # Encrypt
        try:
            encrypted = rsa.encrypt(test_message.encode(), pub_key)
            print("\n✅ Encryption successful!")
        except Exception as e:
            print(f"\n❌ Encryption failed: {str(e)}")
            return
        
        # Decrypt
        try:
            decrypted = rsa.decrypt(encrypted, priv_key).decode()
            print(f"Decrypted message: {decrypted}")
        except Exception as e:
            print(f"\n❌ Decryption failed: {str(e)}")
            return
        
        # Verify
        if decrypted == test_message:
            print("\n✅ Test passed! Keys are working correctly.")
        else:
            print("\n❌ Test failed! Decrypted message doesn't match original.")
            
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")

if __name__ == '__main__':
    # Get the keys from user input
    print("Please paste your public key (including BEGIN and END lines):")
    public_key = ""
    while True:
        line = input()
        if line.strip() == "-----END RSA PUBLIC KEY-----":
            public_key += line + "\n"
            break
        public_key += line + "\n"
    
    print("\nPlease paste your private key (including BEGIN and END lines):")
    private_key = ""
    while True:
        line = input()
        if line.strip() == "-----END RSA PRIVATE KEY-----":
            private_key += line + "\n"
            break
        private_key += line + "\n"
    
    # Test the keys
    test_my_keys(public_key, private_key) 