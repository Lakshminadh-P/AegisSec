/**
 * AegisSec Main Application Script
 * 
 * Shared utilities for all pages.
 */

// Format datetime
function formatDate(dateStr) {
    if (!dateStr) return 'N/A';
    const date = new Date(dateStr);
    return date.toLocaleString();
}

// Format relative time
function timeAgo(dateStr) {
    if (!dateStr) return 'Never';
    const now = new Date();
    const date = new Date(dateStr);
    const seconds = Math.floor((now - date) / 1000);
    
    if (seconds < 60) return 'Just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
}

// Severity badge HTML
function severityBadge(severity) {
    const classes = {
        'CRITICAL': 'badge-critical',
        'HIGH': 'badge-high',
        'MEDIUM': 'badge-medium',
        'LOW': 'badge-low',
    };
    return `<span class="badge ${classes[severity] || 'badge-low'}">${severity}</span>`;
}

// Status badge HTML
function statusBadge(status) {
    const classes = {
        'OPEN': 'badge-open',
        'IN_PROGRESS': 'badge-in-progress',
        'FIXED': 'badge-fixed',
        'FALSE_POSITIVE': 'badge-false-positive',
    };
    const labels = {
        'OPEN': 'Open',
        'IN_PROGRESS': 'In Progress',
        'FIXED': 'Fixed',
        'FALSE_POSITIVE': 'False Positive',
    };
    return `<span class="badge ${classes[status] || ''}">${labels[status] || status}</span>`;
}

// Show toast notification
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast-notification toast-${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);
    
    setTimeout(() => toast.classList.add('show'), 10);
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Set active nav link
function setActiveNav() {
    const path = window.location.pathname;
    const filename = path.split('/').pop() || 'dashboard.html';
    
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
        const href = link.getAttribute('href');
        if (href && href.includes(filename)) {
            link.classList.add('active');
        }
    });
}

// Initialize page
document.addEventListener('DOMContentLoaded', () => {
    setActiveNav();
    if(typeof updateUserDisplay === 'function') {
        updateUserDisplay();
    }
});
