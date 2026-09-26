/**
 * AegisSec Authentication Module
 * 
 * Handles JWT token management, API calls, and auth state.
 */

const API_BASE = '';

// Token management
function getToken() {
    return localStorage.getItem('aegissec_token');
}

function setToken(token) {
    localStorage.setItem('aegissec_token', token);
}

function removeToken() {
    localStorage.removeItem('aegissec_token');
    localStorage.removeItem('aegissec_user');
}

function getUser() {
    const user = localStorage.getItem('aegissec_user');
    return user ? JSON.parse(user) : null;
}

function setUser(user) {
    localStorage.setItem('aegissec_user', JSON.stringify(user));
}

// API helper with auth
async function apiCall(url, options = {}) {
    const token = getToken();
    const headers = {
        'Content-Type': 'application/json',
        ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
        ...options.headers,
    };
    
    try {
        const response = await fetch(`${API_BASE}${url}`, {
            ...options,
            headers,
        });
        
        if (response.status === 401) {
            removeToken();
            window.location.href = '/login.html';
            return null;
        }
        
        return response;
    } catch (error) {
        console.error('API call failed:', error);
        return null;
    }
}

// Login
async function login(username, password) {
    try {
        const response = await fetch(`${API_BASE}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
        });
        
        if (response.ok) {
            const data = await response.json();
            setToken(data.access_token);
            
            // Fetch user info
            const userResponse = await apiCall('/api/auth/me');
            if (userResponse && userResponse.ok) {
                const user = await userResponse.json();
                setUser(user);
            }
            
            return { success: true };
        } else {
            const error = await response.json();
            return { success: false, error: error.detail || 'Login failed' };
        }
    } catch (e) {
        return { success: false, error: 'Network error or backend not reachable.' };
    }
}

// Logout
function logout() {
    removeToken();
    window.location.href = '/login.html';
}

// Check if authenticated
function requireAuth() {
    if (!getToken()) {
        window.location.href = '/login.html';
        return false;
    }
    return true;
}

// Update sidebar with user info
function updateUserDisplay() {
    const user = getUser();
    if (user) {
        const usernameEl = document.getElementById('sidebar-username');
        const roleEl = document.getElementById('sidebar-role');
        if (usernameEl) usernameEl.textContent = user.username;
        if (roleEl) roleEl.textContent = user.role;
    }
}
