HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EncryptX - Secure Cryptographic System</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #1e293b 0%, #7c3aed 100%);
            min-height: 100vh;
            padding: 20px;
            color: #fff;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .card {
            background: rgba(30, 41, 59, 0.95);
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(124, 58, 237, 0.3);
        }
        
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
        }
        
        .header h1 {
            font-size: 32px;
            color: #a78bfa;
        }
        
        .user-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .btn-primary {
            background: #7c3aed;
            color: white;
        }
        
        .btn-primary:hover {
            background: #6d28d9;
            transform: translateY(-2px);
        }
        
        .btn-secondary {
            background: #475569;
            color: white;
        }
        
        .btn-danger {
            background: #dc2626;
            color: white;
        }
        
        .btn-success {
            background: #16a34a;
            color: white;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #cbd5e1;
            font-weight: 500;
        }
        
        .form-group input,
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 12px;
            border: 1px solid #475569;
            border-radius: 8px;
            background: #334155;
            color: white;
            font-size: 16px;
        }
        
        .form-group textarea {
            resize: vertical;
            min-height: 150px;
            font-family: 'Courier New', monospace;
        }
        
        .notification {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            animation: slideIn 0.3s;
        }
        
        .notification.success {
            background: rgba(34, 197, 94, 0.2);
            border: 1px solid #22c55e;
            color: #86efac;
        }
        
        .notification.error {
            background: rgba(239, 68, 68, 0.2);
            border: 1px solid #ef4444;
            color: #fca5a5;
        }
        
        @keyframes slideIn {
            from { transform: translateY(-20px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        
        .login-container {
            max-width: 450px;
            margin: 100px auto;
        }
        
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }
        
        .tab {
            flex: 1;
            padding: 12px;
            background: #475569;
            border: none;
            border-radius: 8px;
            color: white;
            cursor: pointer;
            font-weight: 600;
        }
        
        .tab.active {
            background: #7c3aed;
        }
        
        .grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .output-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        
        .security-info {
            background: rgba(124, 58, 237, 0.1);
            padding: 15px;
            border-radius: 8px;
            border: 1px solid rgba(124, 58, 237, 0.3);
        }
        
        .security-info h4 {
            color: #a78bfa;
            margin-bottom: 10px;
        }
        
        .security-info ul {
            list-style: none;
            font-size: 14px;
            color: #cbd5e1;
        }
        
        .security-info li {
            padding: 4px 0;
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.8);
            align-items: center;
            justify-content: center;
            z-index: 1000;
            padding: 20px;
        }
        
        .modal.active {
            display: flex;
        }
        
        .modal-content {
            background: #1e293b;
            padding: 30px;
            border-radius: 12px;
            max-width: 500px;
            width: 100%;
            border: 1px solid #7c3aed;
        }
        
        .hidden { display: none; }
        
        @media (max-width: 768px) {
            .grid, .output-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Login/Register Screen -->
        <div id="auth-screen" class="login-container">
            <div class="card">
                <h1 style="text-align: center; margin-bottom: 10px;">🔒 SecureCrypt</h1>
                <p style="text-align: center; color: #94a3b8; margin-bottom: 30px;">
                    Secure Cryptographic System
                </p>
                
                <div id="notification-auth"></div>
                
                <div class="tabs">
                    <button class="tab active" onclick="switchTab('login')">Login</button>
                    <button class="tab" onclick="switchTab('register')">Register</button>
                </div>
                
                <form id="auth-form" onsubmit="handleAuth(event)">
                    <div class="form-group">
                        <label>Username</label>
                        <input type="text" id="auth-username" required>
                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <input type="password" id="auth-password" required>
                    </div>
                    <div class="form-group hidden" id="confirm-password-group">
                        <label>Confirm Password</label>
                        <input type="password" id="auth-confirm-password">
                    </div>
                    <button type="submit" class="btn btn-primary" style="width: 100%;" id="auth-submit">
                        Login
                    </button>
                </form>
                
                <div class="security-info" style="margin-top: 20px;">
                    <h4>Security Requirements:</h4>
                    <ul>
                        <li>✓ Password: min 12 chars, uppercase, lowercase, number, special char</li>
                        <li>✓ Zero data persistence</li>
                        <li>✓ Session-based authentication</li>
                        <li>✓ Industry-standard encryption</li>
                    </ul>
                </div>
            </div>
        </div>
        
        <!-- Main Application Screen -->
        <div id="app-screen" class="hidden">
            <div class="card header">
                <div>
                    <h1>🔒 SecureCrypt</h1>
                    <p style="color: #94a3b8;">Secure Cryptographic System</p>
                </div>
                <div class="user-info">
                    <span id="current-user" style="color: #a78bfa; font-weight: 600;"></span>
                    <button class="btn btn-secondary" onclick="showSettings()">⚙️ Settings</button>
                    <button class="btn btn-danger" onclick="logout()">Logout</button>
                </div>
            </div>
            
            <div id="notification-app"></div>
            
            <!-- Control Panel -->
            <div class="card">
                <h2 style="margin-bottom: 20px; color: #a78bfa;">Cryptographic Controls</h2>
                
                <div class="grid">
                    <div class="form-group">
                        <label>Mode</label>
                        <select id="mode" onchange="updateModeUI()">
                            <option value="encrypt">Encrypt</option>
                            <option value="decrypt">Decrypt</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label>Algorithm</label>
                        <select id="algorithm" onchange="handleAlgorithmChange()">
                            <optgroup label="Recommended (Modern)">
                                <option value="AES">AES-256-GCM</option>
                                <option value="ChaCha20">ChaCha20-Poly1305</option>
                                <option value="Camellia">Camellia-256</option>
                            </optgroup>
                            <optgroup label="Asymmetric">
                                <option value="RSA">RSA-2048</option>
                            </optgroup>
                            <optgroup label="Block Ciphers">
                                <option value="3DES">Triple DES (3DES)</option>
                                <option value="Blowfish">Blowfish</option>
                                <option value="Twofish">Twofish</option>
                            </optgroup>
                        </select>
                    </div>
                </div>
                
                <div class="form-group" id="key-input">
                    <label>Encryption Key (min 8 characters)</label>
                    <input type="password" id="crypto-key" placeholder="Enter your secret key">
                </div>
                
                <div id="rsa-controls" class="hidden">
                    <button type="button" class="btn btn-primary" onclick="generateRSAKeys()" style="width: 100%; margin-bottom: 10px;">
                        Generate RSA Keys
                    </button>
                    <button type="button" class="btn btn-secondary" onclick="showPublicKey()" style="width: 100%;">
                        View My Public Key
                    </button>
                </div>
                
                <div id="rsa-status" class="hidden" style="background: rgba(34, 197, 94, 0.1); padding: 10px; border-radius: 8px; border: 1px solid #22c55e; margin-top: 10px;">
                    <span style="color: #86efac;">✓ RSA keys ready</span>
                </div>
            </div>
            
            <!-- Input/Output -->
            <div class="output-grid">
                <div class="card">
                    <h3 style="margin-bottom: 15px; color: #a78bfa;">Input Text</h3>
                    <textarea id="input-text" placeholder="Enter text to encrypt/decrypt..."></textarea>
                </div>
                
                <div class="card">
                    <h3 style="margin-bottom: 15px; color: #a78bfa;">Output Text</h3>
                    <textarea id="output-text" readonly placeholder="Result will appear here..."></textarea>
                </div>
            </div>
            
            <!-- Action Buttons -->
            <div style="display: flex; gap: 15px; justify-content: center; margin-bottom: 20px;">
                <button class="btn btn-primary" onclick="processCrypto()" style="min-width: 150px;">
                    <span id="action-text">🔒 Encrypt</span>
                </button>
                <button class="btn btn-secondary" onclick="clearData()">
                    Clear
                </button>
            </div>
            
            <!-- Security Information -->
            <div class="card">
                <h3 style="margin-bottom: 15px; color: #a78bfa;">Security Information</h3>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                    <div class="security-info">
                        <h4>Data Protection</h4>
                        <ul>
                            <li>• Zero persistence - memory only</li>
                            <li>• Session-based authentication</li>
                            <li>• No cross-user data access</li>
                            <li>• Cleared on logout</li>
                        </ul>
                    </div>
                    <div class="security-info">
                        <h4>Cryptographic Standards</h4>
                        <ul>
                            <li>• AES-256-GCM (Recommended)</li>
                            <li>• ChaCha20-Poly1305</li>
                            <li>• Camellia-256-CBC</li>
                            <li>• RSA-2048 with OAEP</li>
                            <li>• Triple DES (Legacy)</li>
                            <li>• PBKDF2-600k iterations</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Settings Modal -->
    <div id="settings-modal" class="modal">
        <div class="modal-content">
            <h2 style="color: #a78bfa; margin-bottom: 20px;">User Settings</h2>
            
            <div id="notification-settings"></div>
            
            <form id="change-password-form" onsubmit="changePassword(event)">
                <div class="form-group">
                    <label>Current Password</label>
                    <input type="password" id="settings-current-password" required>
                </div>
                <div class="form-group">
                    <label>New Password</label>
                    <input type="password" id="settings-new-password" required>
                </div>
                <div class="form-group">
                    <label>Confirm New Password</label>
                    <input type="password" id="settings-confirm-password" required>
                </div>
                
                <div style="display: flex; gap: 10px; margin-top: 20px;">
                    <button type="submit" class="btn btn-success" style="flex: 1;">
                        Change Password
                    </button>
                    <button type="button" class="btn btn-secondary" onclick="closeSettings()" style="flex: 1;">
                        Cancel
                    </button>
                </div>
            </form>
            
            <div class="security-info" style="margin-top: 20px;">
                <h4>Password Requirements:</h4>
                <ul>
                    <li>• Minimum 12 characters</li>
                    <li>• At least one uppercase letter</li>
                    <li>• At least one lowercase letter</li>
                    <li>• At least one number</li>
                    <li>• At least one special character</li>
                </ul>
            </div>
        </div>
    </div>
    
    <script>
        // Global state
        let csrfToken = null;
        let currentMode = 'login';
        let hasRSAKeys = false;
        
        // API helper with CSRF
        async function apiCall(url, method = 'GET', body = null) {
            const options = {
                method,
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json'
                }
            };
            
            if (csrfToken && method !== 'GET') {
                options.headers['X-CSRF-Token'] = csrfToken;
            }
            
            if (body) {
                options.body = JSON.stringify(body);
            }
            
            const response = await fetch(url, options);
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Request failed');
            }
            
            return data;
        }
        
        // Show notification
        function showNotification(message, type = 'success', target = 'app') {
            const id = `notification-${target}`;
            const el = document.getElementById(id);
            el.innerHTML = `<div class="notification ${type}">${message}</div>`;
            setTimeout(() => el.innerHTML = '', 5000);
        }
        
        // Tab switching
        function switchTab(tab) {
            currentMode = tab;
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            event.target.classList.add('active');
            
            const confirmGroup = document.getElementById('confirm-password-group');
            const submitBtn = document.getElementById('auth-submit');
            
            if (tab === 'register') {
                confirmGroup.classList.remove('hidden');
                submitBtn.textContent = 'Register';
            } else {
                confirmGroup.classList.add('hidden');
                submitBtn.textContent = 'Login';
            }
        }
        
        // Authentication
        async function handleAuth(e) {
            e.preventDefault();
            
            const username = document.getElementById('auth-username').value;
            const password = document.getElementById('auth-password').value;
            const confirmPassword = document.getElementById('auth-confirm-password').value;
            
            try {
                let data;
                if (currentMode === 'register') {
                    data = await apiCall('/api/register', 'POST', {
                        username,
                        password,
                        confirm_password: confirmPassword
                    });
                } else {
                    data = await apiCall('/api/login', 'POST', {
                        username,
                        password
                    });
                }
                
                csrfToken = data.csrf_token;
                hasRSAKeys = data.has_rsa_keys || false;
                
                document.getElementById('current-user').textContent = data.username;
                document.getElementById('auth-screen').classList.add('hidden');
                document.getElementById('app-screen').classList.remove('hidden');
                
                if (hasRSAKeys) {
                    document.getElementById('rsa-status').classList.remove('hidden');
                }
                
                showNotification(data.message, 'success', 'app');
            } catch (error) {
                showNotification(error.message, 'error', 'auth');
            }
        }
        
        // Logout
        async function logout() {
            try {
                await apiCall('/api/logout', 'POST');
                csrfToken = null;
                hasRSAKeys = false;
                
                document.getElementById('auth-screen').classList.remove('hidden');
                document.getElementById('app-screen').classList.add('hidden');
                document.getElementById('auth-form').reset();
                clearData();
            } catch (error) {
                showNotification(error.message, 'error', 'app');
            }
        }
        
        // Algorithm change handler
        function handleAlgorithmChange() {
            const algorithm = document.getElementById('algorithm').value;
            const keyInput = document.getElementById('key-input');
            const rsaControls = document.getElementById('rsa-controls');
            
            if (algorithm === 'RSA') {
                keyInput.classList.add('hidden');
                rsaControls.classList.remove('hidden');
            } else {
                keyInput.classList.remove('hidden');
                rsaControls.classList.add('hidden');
            }
        }
        
        // Update mode UI
        function updateModeUI() {
            const mode = document.getElementById('mode').value;
            const actionText = document.getElementById('action-text');
            actionText.textContent = mode === 'encrypt' ? '🔒 Encrypt' : '🔓 Decrypt';
        }
        
        // Process crypto operation
        async function processCrypto() {
            const mode = document.getElementById('mode').value;
            const algorithm = document.getElementById('algorithm').value;
            const key = document.getElementById('crypto-key').value;
            const inputText = document.getElementById('input-text').value;
            
            if (!inputText) {
                showNotification('Please enter text', 'error', 'app');
                return;
            }
            
            if (algorithm !== 'RSA' && !key) {
                showNotification('Please enter encryption key', 'error', 'app');
                return;
            }
            
            try {
                let data;
                if (mode === 'encrypt') {
                    data = await apiCall('/api/encrypt', 'POST', {
                        plaintext: inputText,
                        algorithm,
                        key
                    });
                    document.getElementById('output-text').value = data.ciphertext;
                    showNotification('Encryption successful', 'success', 'app');
                } else {
                    data = await apiCall('/api/decrypt', 'POST', {
                        ciphertext: inputText,
                        algorithm,
                        key
                    });
                    document.getElementById('output-text').value = data.plaintext;
                    showNotification('Decryption successful', 'success', 'app');
                }
            } catch (error) {
                showNotification(error.message, 'error', 'app');
            }
        }
        
        // Generate RSA keys
        async function generateRSAKeys() {
            try {
                const data = await apiCall('/api/generate-rsa-keys', 'POST');
                hasRSAKeys = true;
                document.getElementById('rsa-status').classList.remove('hidden');
                showNotification(data.message, 'success', 'app');
            } catch (error) {
                showNotification(error.message, 'error', 'app');
            }
        }
        
        // Show public key
        async function showPublicKey() {
            try {
                const data = await apiCall('/api/get-public-key', 'GET');
                alert('Your Public Key:\\n\\n' + data.public_key + '\\n\\nShare this key with others to receive encrypted messages.');
            } catch (error) {
                showNotification(error.message, 'error', 'app');
            }
        }
        
        // Clear data
        function clearData() {
            document.getElementById('input-text').value = '';
            document.getElementById('output-text').value = '';
            document.getElementById('crypto-key').value = '';
        }
        
        // Settings
        function showSettings() {
            document.getElementById('settings-modal').classList.add('active');
        }
        
        function closeSettings() {
            document.getElementById('settings-modal').classList.remove('active');
            document.getElementById('change-password-form').reset();
        }
        
        async function changePassword(e) {
            e.preventDefault();
            
            const currentPassword = document.getElementById('settings-current-password').value;
            const newPassword = document.getElementById('settings-new-password').value;
            const confirmPassword = document.getElementById('settings-confirm-password').value;
            
            try {
                const data = await apiCall('/api/change-password', 'POST', {
                    current_password: currentPassword,
                    new_password: newPassword,
                    confirm_password: confirmPassword
                });
                
                showNotification(data.message, 'success', 'settings');
                setTimeout(closeSettings, 2000);
            } catch (error) {
                showNotification(error.message, 'error', 'settings');
            }
        }
        
        // Initialize
        handleAlgorithmChange();
    </script>
</body>
</html>
'''
