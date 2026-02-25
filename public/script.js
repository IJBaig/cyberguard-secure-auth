// UI Navigation
function switchView(viewId) {
    document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active'));
    document.getElementById(viewId).classList.add('active');
    document.querySelectorAll('.alert').forEach(el => { el.className = 'alert'; el.innerHTML = ''; });
}

// Display Alerts
function showAlert(elementId, message, type) {
    const alertBox = document.getElementById(elementId);
    alertBox.className = `alert ${type}`;
    alertBox.innerText = message;
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
    document.getElementById('jwt-token').value = ''; // Destroy token from client
    document.getElementById('login-password').value = ''; // Clear password field
    switchView('view-login');
    showAlert('login-alert', 'You have been securely logged out.', 'success');
}

// API Calls
async function handleLogin() {
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;

    const res = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
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

    const res = await fetch('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    const data = await res.json();

    if (res.ok) {
        showAlert('reg-alert', data.message, 'success');
        document.querySelectorAll('#view-register input[type="text"], #view-register input[type="email"], #view-register input[type="password"]').forEach(input => input.value = '');
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

    const res = await fetch('/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    const data = await res.json();

    if (res.ok) {
        showAlert('reset-alert', data.message, 'success');
        document.querySelectorAll('#view-forgot input[type="text"], #view-forgot input[type="email"], #view-forgot input[type="password"]').forEach(input => input.value = '');
    } else {
        showAlert('reset-alert', data.error, 'error');
    }
}
