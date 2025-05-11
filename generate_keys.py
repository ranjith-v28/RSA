import rsa
import os
import sys
import time

def generate_rsa_keys(key_size=4096):
    """Generate a pair of RSA keys with specified key size"""
    try:
        print(f"\n🔐 Generating {key_size}-bit RSA keys...")
        print("This may take a few moments for {key_size}-bit keys...")
        
        start_time = time.time()
        
        # Generate the key pair
        (pubkey, privkey) = rsa.newkeys(key_size)
        
        # Calculate generation time
        generation_time = time.time() - start_time
        
        # Create user_keys directory if it doesn't exist
        os.makedirs('user_keys', exist_ok=True)
        
        # Save the public key
        public_key_path = 'user_keys/public_key.pem'
        with open(public_key_path, 'wb') as f:
            f.write(pubkey.save_pkcs1('PEM'))
        
        # Save the private key
        private_key_path = 'user_keys/private_key.pem'
        with open(private_key_path, 'wb') as f:
            f.write(privkey.save_pkcs1('PEM'))
        
        # Verify the key size
        actual_key_size = pubkey.n.bit_length()
        if actual_key_size != key_size:
            print(f"\n⚠️ Warning: Generated key size is {actual_key_size} bits instead of {key_size} bits")
        
        print("\n✅ Keys generated successfully!")
        print(f"⏱️ Generation time: {generation_time:.2f} seconds")
        print(f"🔑 Key size: {actual_key_size} bits")
        
        print("\n📄 Public Key (user_keys/public_key.pem):")
        print("-" * 50)
        print(pubkey.save_pkcs1('PEM').decode())
        print("-" * 50)
        
        print("\n🔒 Private Key (user_keys/private_key.pem):")
        print("-" * 50)
        print(privkey.save_pkcs1('PEM').decode())
        print("-" * 50)
        
        print("\n💾 Keys have been saved to the user_keys directory:")
        print(f"   - Public key: {os.path.abspath(public_key_path)}")
        print(f"   - Private key: {os.path.abspath(private_key_path)}")
        
        print("\n⚠️ IMPORTANT: Keep your private key secure and never share it!")
        print("   The private key is required for decryption.")
        
    except Exception as e:
        print(f"\n❌ Error generating keys: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    # Allow custom key size through command line argument
    key_size = 4096  # Default to 4096 bits
    if len(sys.argv) > 1:
        try:
            key_size = int(sys.argv[1])
            if key_size < 2048:
                print("⚠️ Warning: Key sizes below 2048 bits are not recommended for security reasons.")
                if input("Do you want to continue? (y/n): ").lower() != 'y':
                    sys.exit(0)
        except ValueError:
            print("❌ Invalid key size. Using default 4096 bits.")
    
    generate_rsa_keys(key_size) 