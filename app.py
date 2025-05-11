from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import rsa
import base64
import re
import os
from io import StringIO
from werkzeug.utils import secure_filename
import logging

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  # Enable CORS for all routes and origins

# =============================================
# Configuration
# =============================================
MAX_MESSAGE_LENGTH = 1000  # characters
ALLOWED_EXTENSIONS = {'pem', 'key'}
EMOJI_MAPPING = [
    "😀", "😃", "😄", "😁", "😆", "😅", "😂", "🤣", "😊", "😇",
    "🙂", "🙃", "😉", "😌", "😍", "🥰", "😘", "😗", "😙", "😚",
    "😋", "😛", "😝", "😜", "🤪", "🤨", "🧐", "🤓", "😎", "🥸",
    "🤩", "🥳", "😏", "😒", "😞", "😔", "😟", "😕", "🙁", "☹️",
    "😣", "😖", "😫", "😩", "🥺", "😢", "😭", "😤", "😠", "😡",
    "🤬", "🤯", "😳", "🥵", "🥶", "😱", "😨", "😰", "😥", "😓",
    "🫣", "🤗", "🫡", "🤔", "🫢", "🤭", "🤫", "🤥", "😶"
]

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)

# =============================================
# Helper Functions
# =============================================

def allowed_file(filename):
    """Check if the file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_rsa_key(key_str, is_private=False):
    """Validate RSA key format and type"""
    try:
        if not key_str or not isinstance(key_str, str):
            return False, "Key is empty or not a string"
            
        # Clean up the key string
        key_str = key_str.strip()
        
        # For private key, be more lenient with the format
        if is_private:
            # Try to load the key directly
            try:
                rsa.PrivateKey.load_pkcs1(key_str.encode())
                return True, "Key is valid"
            except:
                # If that fails, try to clean up the key
                try:
                    # Remove any whitespace and newlines
                    key_content = ''.join(key_str.split())
                    # Try to load the key
                    rsa.PrivateKey.load_pkcs1(key_content.encode())
                    return True, "Key is valid"
                except:
                    return False, "Invalid private key format"
        else:
            # For public key, maintain strict validation
            if not key_str.startswith("-----BEGIN RSA PUBLIC KEY-----"):
                return False, "Public key must start with '-----BEGIN RSA PUBLIC KEY-----'"
            if not key_str.endswith("-----END RSA PUBLIC KEY-----"):
                return False, "Public key must end with '-----END RSA PUBLIC KEY-----'"
            
            try:
                rsa.PublicKey.load_pkcs1(key_str.encode())
                return True, "Key is valid"
            except Exception as e:
                return False, f"Invalid public key format: {str(e)}"
            
    except Exception as e:
        logging.error(f"Key validation error: {str(e)}")
        return False, f"Key validation error: {str(e)}"

def bytes_to_emojis(data):
    """Convert bytes to emoji sequence"""
    return ''.join([EMOJI_MAPPING[b % len(EMOJI_MAPPING)] for b in data])

def emojis_to_bytes(emoji_str):
    """Convert emoji sequence back to bytes"""
    emoji_map = {e: i for i, e in enumerate(EMOJI_MAPPING)}
    return bytes([emoji_map[e] for e in emoji_str if e in emoji_map])

def sanitize_input(text, max_length):
    """Sanitize and validate user input"""
    if not isinstance(text, str):
        return None
    text = text.strip()
    if not text or len(text) > max_length:
        return None
    return text

def validate_key_pair(public_key_str, private_key_str):
    """Validate that the public and private keys form a valid pair"""
    try:
        # Clean up the keys
        public_key_str = public_key_str.strip()
        private_key_str = private_key_str.strip()
        
        # Load the keys
        try:
            pub_key = rsa.PublicKey.load_pkcs1(public_key_str.encode())
            priv_key = rsa.PrivateKey.load_pkcs1(private_key_str.encode())
        except Exception as e:
            return False, f"Failed to load keys: {str(e)}"
        
        # Verify they are a pair by checking their modulus (n)
        if pub_key.n != priv_key.n:
            return False, "Keys do not form a valid pair"
        
        # Test encryption/decryption with a small message
        test_message = "test"
        try:
            encrypted = rsa.encrypt(test_message.encode(), pub_key)
            decrypted = rsa.decrypt(encrypted, priv_key).decode()
            if decrypted != test_message:
                return False, "Key pair validation failed"
        except Exception as e:
            return False, f"Key pair test failed: {str(e)}"
        
        return True, "Keys are valid and form a pair"
    except Exception as e:
        return False, f"Key validation error: {str(e)}"

# =============================================
# Routes
# =============================================

@app.route('/')
def home():
    """Render the main interface"""
    return render_template('index.html')

@app.route('/encrypt')
def encrypt_page():
    """Render the encryption page"""
    return render_template('encrypt.html')

@app.route('/decrypt')
def decrypt_page():
    """Render the decryption page"""
    return render_template('decrypt.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        message = request.form['message']
        public_key = request.form['public_key']
        
        # Log the input lengths for debugging
        print(f"Message length: {len(message)}")
        print(f"Public key length: {len(public_key)}")
        
        # Load the public key
        try:
            public_key_data = rsa.PublicKey.load_pkcs1(public_key.encode())
            print("Public key loaded successfully")
        except Exception as e:
            print(f"Error loading public key: {str(e)}")
            return jsonify({'error': 'Invalid public key format'}), 400
        
        # Encrypt the message
        try:
            encrypted_bytes = rsa.encrypt(message.encode('utf-8'), public_key_data)
            print(f"Encrypted to {len(encrypted_bytes)} bytes")
            encrypted_emojis = bytes_to_emojis(encrypted_bytes)
            print(f"Converted to {len(encrypted_emojis)} emojis")
            return jsonify({'encrypted_text': encrypted_emojis})
        except Exception as e:
            print(f"Error during encryption: {str(e)}")
            return jsonify({'error': f'Encryption failed: {str(e)}'}), 500
            
    except Exception as e:
        print(f"Unexpected error in encrypt endpoint: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        encrypted_text = request.form['encrypted_text']
        private_key = request.form['private_key']
        
        # Log the input lengths for debugging
        print(f"Encrypted text length: {len(encrypted_text)}")
        print(f"Private key length: {len(private_key)}")
        
        # Convert emojis back to bytes
        try:
            encrypted_bytes = emojis_to_bytes(encrypted_text)
            print(f"Converted to {len(encrypted_bytes)} bytes")
        except ValueError as e:
            print(f"Error converting emojis to bytes: {str(e)}")
            return jsonify({'error': f'Invalid emoji sequence: {str(e)}'}), 400
        
        # Load the private key
        try:
            private_key_data = rsa.PrivateKey.load_pkcs1(private_key.encode())
            print("Private key loaded successfully")
        except Exception as e:
            print(f"Error loading private key: {str(e)}")
            return jsonify({'error': 'Invalid private key format'}), 400
        
        # Decrypt the message
        try:
            decrypted_bytes = rsa.decrypt(encrypted_bytes, private_key_data)
            print(f"Decrypted to {len(decrypted_bytes)} bytes")
            decrypted_text = decrypted_bytes.decode('utf-8')
            print(f"Decoded message: {decrypted_text[:50]}...")  # Print first 50 chars
            return jsonify({'decrypted_text': decrypted_text})
        except rsa.pkcs1.DecryptionError as e:
            print(f"Decryption error: {str(e)}")
            return jsonify({'error': 'The private key does not match the public key used for encryption'}), 400
        except Exception as e:
            print(f"Unexpected error during decryption: {str(e)}")
            return jsonify({'error': f'Decryption failed: {str(e)}'}), 500
            
    except Exception as e:
        print(f"Unexpected error in decrypt endpoint: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/validate_keys', methods=['POST'])
def validate_keys():
    """Validate that the public and private keys form a valid pair"""
    try:
        data = request.json
        if not data:
            return jsonify({'valid': False, 'error': 'No data provided'}), 400
            
        public_key = data.get('public_key')
        private_key = data.get('private_key')
        
        if not public_key or not private_key:
            return jsonify({'valid': False, 'error': 'Both public and private keys are required'}), 400
            
        # Clean up the keys
        public_key = public_key.strip()
        private_key = private_key.strip()
        
        # Validate the key pair
        is_valid, message = validate_key_pair(public_key, private_key)
        
        return jsonify({
            'valid': is_valid,
            'error': None if is_valid else message
        })
        
    except Exception as e:
        logging.error(f"Key validation error: {str(e)}")
        return jsonify({'valid': False, 'error': str(e)}), 500

# =============================================
# Error Handlers
# =============================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def server_error(e):
    logging.error(f"Server error: {str(e)}")
    return jsonify({'error': 'Internal server error'}), 500

# =============================================
# Main Application
# =============================================

if __name__ == '__main__':
    # Ensure the user_keys directory exists
    os.makedirs('user_keys', exist_ok=True)
    
    # Start the Flask application
    app.run(host='127.0.0.1', port=5000, debug=True)