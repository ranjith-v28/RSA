import rsa
import os

def decrypt_data(encrypted_data, private_key_path='user_keys/private_key.pem'):
    """
    Decrypt data using a private key
    
    Args:
        encrypted_data (bytes): The encrypted data to decrypt
        private_key_path (str): Path to the private key file (default: 'user_keys/private_key.pem')
    
    Returns:
        str: The decrypted message
    """
    try:
        # Check if private key file exists
        if not os.path.exists(private_key_path):
            raise FileNotFoundError(f"Private key file not found at {private_key_path}")
        
        # Load the private key
        with open(private_key_path, 'rb') as f:
            private_key = rsa.PrivateKey.load_pkcs1(f.read())
        
        # Decrypt the data
        decrypted_data = rsa.decrypt(encrypted_data, private_key)
        
        # Convert bytes to string
        return decrypted_data.decode('utf-8')
        
    except rsa.pkcs1.DecryptionError:
        raise ValueError("Decryption failed - The private key does not match the public key used for encryption")
    except Exception as e:
        raise Exception(f"Decryption error: {str(e)}")

if __name__ == '__main__':
    # Example usage
    try:
        # Read encrypted data from a file (you would need to have this file)
        with open('encrypted_data.bin', 'rb') as f:
            encrypted_data = f.read()
        
        # Decrypt the data
        decrypted_message = decrypt_data(encrypted_data)
        print("\n✅ Message decrypted successfully!")
        print("\nDecrypted message:")
        print("-" * 50)
        print(decrypted_message)
        print("-" * 50)
        
    except Exception as e:
        print(f"\n❌ Error: {str(e)}") 