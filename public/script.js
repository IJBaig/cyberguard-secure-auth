// --- UI Navigation ---
function switchView(viewId) {
    document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active'));
    document.getElementById(viewId).classList.add('active');
    document.querySelectorAll('.alert').forEach(el => { el.className = 'alert'; el.innerHTML = ''; el.style.display = 'none'; });
}

// Display Alerts
function showAlert(elementId, message, type) {
    const alertBox = document.getElementById(elementId);
    alertBox.className = `alert ${type}`;
    alertBox.innerHTML = message;
    alertBox.style.display = 'block';
}

// Toggle Password Visibility
function togglePassword(...fieldIds) {
    fieldIds.forEach(id => {
        const field = document.getElementById(id);
        if (field.type === "password") {
            field.type = "text";
        } else {
            field.type = "password";
        }
    });
}

// Handle Logout
function handleLogout() {
    document.getElementById('jwt-token').value = ''; 
    document.getElementById('login-password').value = ''; 
    document.getElementById('api-response').style.display = 'none'; // Clear the API box
    switchView('view-login');
    showAlert('login-alert', 'You have been securely logged out.', 'success');
}


// --- API FETCH CALLS & SECURITY ---

// NEW: Fetch CSRF Token before submitting forms
async function getCsrfToken() {
    try {
        const response = await fetch('/api/csrf-token');
        if (response.ok) {
            const data = await response.json();
            return data.csrfToken;
        }
    } catch (error) {
        console.error("Failed to fetch CSRF token:", error);
    }
    return '';
}

async function handleLogin() {
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;

    // Securely request the CSRF token
    const csrfToken = await getCsrfToken();

    const res = await fetch('/login', {
        method: 'POST',
        headers: { 
            'Content-Type': 'application/json',
            'csrf-token': csrfToken // Attach token to pass the backend check
        },
        body: JSON.stringify({ email, password })
    });
    const data = await res.json();

    if (res.ok) {
        switchView('view-welcome');
        document.getElementById('welcome-title').innerText = `Welcome, ${data.username}!`;
        document.getElementById('jwt-token').value = data.token;
    } else {
        showAlert('login-alert', data.error, 'error');
    }
}

async function handleRegister() {
    const payload = {
        username: document.getElementById('reg-username').value,
        email: document.getElementById('reg-email').value,
        password: document.getElementById('reg-password').value,
        confirmPassword: document.getElementById('reg-confirm').value
    };

    // Securely request the CSRF token
    const csrfToken = await getCsrfToken();

    const res = await fetch('/register', {
        method: 'POST',
        headers: { 
            'Content-Type': 'application/json',
            'csrf-token': csrfToken // Attach token to pass the backend check
        },
        body: JSON.stringify(payload)
    });
    const data = await res.json();

    if (res.ok) {
        showAlert('reg-alert', data.message, 'success');
        document.querySelectorAll('#view-register input').forEach(input => {
            if(input.type !== 'checkbox') input.value = '';
        });
    } else {
        showAlert('reg-alert', data.error, 'error');
    }
}

async function handleReset() {
    const payload = {
        username: document.getElementById('reset-username').value,
        email: document.getElementById('reset-email').value,
        newPassword: document.getElementById('reset-password').value
    };

    // Securely request the CSRF token
    const csrfToken = await getCsrfToken();

    const res = await fetch('/forgot-password', {
        method: 'POST',
        headers: { 
            'Content-Type': 'application/json',
            'csrf-token': csrfToken // Attach token to pass the backend check
        },
        body: JSON.stringify(payload)
    });
    const data = await res.json();

    if (res.ok) {
        showAlert('reset-alert', data.message, 'success');
        document.querySelectorAll('#view-forgot input').forEach(input => {
            if(input.type !== 'checkbox') input.value = '';
        });
    } else {
        showAlert('reset-alert', data.error, 'error');
    }
}

// Week 4 - Secure API Testing
async function testSecureAPI() {
    const apiBox = document.getElementById('api-response');
    apiBox.style.display = 'block';
    apiBox.className = 'alert';
    apiBox.innerText = 'Requesting secure data...';

    const res = await fetch('/api/sensitive-data', {
        method: 'GET',
        headers: {
            'x-api-key': 'intern-super-secret-api-key-2026' 
        }
    });
    
    const data = await res.json();

    if (res.ok) {
        apiBox.className = 'alert success';
        apiBox.innerHTML = `<strong>${data.message}</strong><br><br>Data Retrieved:<br>- ${data.classified_data.join('<br>- ')}`;
    } else {
        apiBox.className = 'alert error';
        apiBox.innerText = data.error;
    }
}
