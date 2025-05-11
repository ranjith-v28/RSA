/**
 * Cyber Sentinel - Secure Emoji Messaging
 * Handles encryption/decryption with user-provided RSA keys
 */

document.addEventListener('DOMContentLoaded', () => {
    // ======================
    // DOM Elements
    // ======================
    const publicKeyTextarea = document.getElementById('publicKey');
    const privateKeyTextarea = document.getElementById('privateKey');
    const messageInput = document.getElementById('messageInput');
    const emojisInput = document.getElementById('emojisInput');
    const encryptButton = document.getElementById('encryptButton');
    const decryptButton = document.getElementById('decryptButton');
    const encryptedOutput = document.getElementById('encryptedOutput');
    const decryptedOutput = document.getElementById('decryptedOutput');

    // ======================
    // Event Listeners
    // ======================
    encryptButton.addEventListener('click', handleEncryption);
    decryptButton.addEventListener('click', handleDecryption);

    // ======================
    // Core Functions
    // ======================

    /**
     * Handles the encryption process
     */
    async function handleEncryption() {
        try {
            // Validate inputs
            const message = messageInput.value.trim();
            const publicKey = publicKeyTextarea.value.trim();
            
            if (!message) {
                showAlert('Please enter a message to encrypt', 'error');
                return;
            }
            
            if (!publicKey) {
                showAlert('Please provide your public key', 'error');
                return;
            }

            // Show loading state
            toggleLoading(encryptButton, true);

            // Call encryption API
            const response = await fetch('/encrypt', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    message: message,
                    public_key: publicKey
                })
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || 'Encryption failed');
            }

            // Display results
            document.getElementById('emojiOutput').textContent = result.emojis;
            encryptedOutput.classList.remove('hidden');
            
            // Copy to clipboard automatically
            copyToClipboard(result.emojis);
            showAlert('Message encrypted and copied to clipboard!', 'success');

        } catch (error) {
            console.error('Encryption error:', error);
            showAlert(`Encryption failed: ${error.message}`, 'error');
        } finally {
            toggleLoading(encryptButton, false);
        }
    }

    /**
     * Handles the decryption process
     */
    async function handleDecryption() {
        try {
            // Validate inputs
            const emojis = emojisInput.value.trim();
            const privateKey = privateKeyTextarea.value.trim();
            
            if (!emojis) {
                showAlert('Please enter emojis to decrypt', 'error');
                return;
            }
            
            if (!privateKey) {
                showAlert('Private key is required for decryption', 'error');
                privateKeyTextarea.focus();
                return;
            }

            // Validate private key format
            if (!privateKey.includes('-----BEGIN RSA PRIVATE KEY-----') || 
                !privateKey.includes('-----END RSA PRIVATE KEY-----')) {
                showAlert('Invalid private key format. Please provide a valid RSA private key.', 'error');
                privateKeyTextarea.focus();
                return;
            }

            // Show loading state
            toggleLoading(decryptButton, true);

            // Call decryption API
            const response = await fetch('/decrypt', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    emojis: emojis,
                    private_key: privateKey
                })
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || 'Decryption failed');
            }

            // Display results
            document.getElementById('textOutput').textContent = result.message;
            document.getElementById('decryptedOutput').classList.remove('hidden');
            showAlert('Message decrypted successfully!', 'success');

        } catch (error) {
            console.error('Decryption error:', error);
            showAlert(`Decryption failed: ${error.message}`, 'error');
        } finally {
            toggleLoading(decryptButton, false);
        }
    }

    // ======================
    // Helper Functions
    // ======================

    /**
     * Shows alert message to user
     * @param {string} message - Alert content
     * @param {string} type - 'success' or 'error'
     */
    function showAlert(message, type = 'success') {
        const alertBox = document.createElement('div');
        alertBox.className = `alert ${type}`;
        alertBox.textContent = message;
        
        document.body.appendChild(alertBox);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            alertBox.classList.add('fade-out');
            setTimeout(() => alertBox.remove(), 300);
        }, 5000);
    }

    /**
     * Toggles loading state on buttons
     * @param {HTMLElement} button - Button element
     * @param {boolean} isLoading - Loading state
     */
    function toggleLoading(button, isLoading) {
        if (isLoading) {
            button.innerHTML = '<div class="spinner"></div> Processing...';
            button.disabled = true;
        } else {
            button.textContent = button === encryptButton ? 'Encrypt to Emojis' : 'Decrypt Message';
            button.disabled = false;
        }
    }

    /**
     * Copies text to clipboard
     * @param {string} text - Text to copy
     */
    function copyToClipboard(text) {
        navigator.clipboard.writeText(text).catch(err => {
            console.error('Could not copy text: ', err);
        });
    }

    // ======================
    // Key Format Validation (Optional)
    // ======================
    publicKeyTextarea.addEventListener('input', validateKeyFormat);
    privateKeyTextarea.addEventListener('input', validateKeyFormat);

    function validateKeyFormat(e) {
        const key = e.target.value;
        const isPublic = e.target.id === 'publicKey';
        
        if (!key) return;
        
        const isValid = (
            key.includes('-----BEGIN RSA ') && 
            key.includes('-----END RSA ') && 
            key.length > 100
        );
        
        if (!isValid) {
            e.target.style.borderColor = '#e74c3c';
            showAlert(`Warning: This doesn't look like a valid ${isPublic ? 'public' : 'private'} RSA key`, 'error');
        } else {
            e.target.style.borderColor = '#2ecc71';
        }
    }

    // Copy functionality
    document.getElementById('copyEncrypted').addEventListener('click', () => {
        const emojiOutput = document.getElementById('emojiOutput').textContent;
        if (emojiOutput) {
            navigator.clipboard.writeText(emojiOutput)
                .then(() => {
                    showToast('Encrypted emojis copied to clipboard!');
                })
                .catch(err => {
                    showToast('Failed to copy: ' + err.message, 'error');
                });
        }
    });

    document.getElementById('copyDecrypted').addEventListener('click', () => {
        const textOutput = document.getElementById('textOutput').textContent;
        if (textOutput) {
            navigator.clipboard.writeText(textOutput)
                .then(() => {
                    showToast('Decrypted message copied to clipboard!');
                })
                .catch(err => {
                    showToast('Failed to copy: ' + err.message, 'error');
                });
        }
    });

    // Clear functionality
    document.getElementById('clearEncrypted').addEventListener('click', () => {
        document.getElementById('emojiOutput').textContent = '';
        document.getElementById('encryptedOutput').classList.add('hidden');
    });

    document.getElementById('clearDecrypted').addEventListener('click', () => {
        document.getElementById('textOutput').textContent = '';
        document.getElementById('decryptedOutput').classList.add('hidden');
    });

    // Toast notification function
    function showToast(message, type = 'success') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.classList.add('show');
        }, 100);
        
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => {
                document.body.removeChild(toast);
            }, 300);
        }, 3000);
    }
});

// ======================
// CSS-in-JS for dynamic alerts
// ======================
const style = document.createElement('style');
style.textContent = `
    .alert {
        position: fixed;
        bottom: 20px;
        right: 20px;
        padding: 15px 25px;
        border-radius: 5px;
        color: white;
        z-index: 1000;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        animation: slideIn 0.3s ease-out;
    }
    
    .alert.success {
        background-color: #2ecc71;
    }
    
    .alert.error {
        background-color: #e74c3c;
    }
    
    .fade-out {
        animation: fadeOut 0.3s ease-in;
    }
    
    .spinner {
        display: inline-block;
        width: 16px;
        height: 16px;
        border: 3px solid rgba(255,255,255,0.3);
        border-radius: 50%;
        border-top-color: white;
        animation: spin 1s ease-in-out infinite;
        margin-right: 8px;
        vertical-align: middle;
    }
    
    @keyframes slideIn {
        from { transform: translateX(100%); }
        to { transform: translateX(0); }
    }
    
    @keyframes fadeOut {
        from { opacity: 1; }
        to { opacity: 0; }
    }
    
    @keyframes spin {
        to { transform: rotate(360deg); }
    }
`;
document.head.appendChild(style);