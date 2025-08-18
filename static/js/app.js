// Internal Audit Tracker - JavaScript Utilities

document.addEventListener('DOMContentLoaded', function() {
    // Initialize all JavaScript functionality
    initFormValidation();
    initTableSorting();
    initTooltips();
    initConfirmDialogs();
    initProgressBars();
});

// Form validation enhancements
function initFormValidation() {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            if (!validateForm(this)) {
                e.preventDefault();
            }
        });
    });
}

function validateForm(form) {
    const requiredFields = form.querySelectorAll('[required]');
    let isValid = true;
    
    requiredFields.forEach(field => {
        if (!field.value.trim()) {
            field.classList.add('invalid');
            isValid = false;
        } else {
            field.classList.remove('invalid');
            field.classList.add('valid');
        }
    });
    
    return isValid;
}

// Table sorting functionality
function initTableSorting() {
    const tables = document.querySelectorAll('table');
    tables.forEach(table => {
        const headers = table.querySelectorAll('th');
        headers.forEach((header, index) => {
            if (header.textContent.trim() && !header.querySelector('svg')) {
                header.style.cursor = 'pointer';
                header.addEventListener('click', () => sortTable(table, index));
            }
        });
    });
}

function sortTable(table, column) {
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    
    rows.sort((a, b) => {
        const aText = a.children[column].textContent.trim();
        const bText = b.children[column].textContent.trim();
        
        // Check if values are dates
        const aDate = new Date(aText);
        const bDate = new Date(bText);
        
        if (!isNaN(aDate) && !isNaN(bDate)) {
            return aDate - bDate;
        }
        
        // Check if values are numbers
        const aNum = parseFloat(aText);
        const bNum = parseFloat(bText);
        
        if (!isNaN(aNum) && !isNaN(bNum)) {
            return aNum - bNum;
        }
        
        // Default to string comparison
        return aText.localeCompare(bText);
    });
    
    // Re-append sorted rows
    rows.forEach(row => tbody.appendChild(row));
}

// Enhanced tooltips
function initTooltips() {
    const tooltips = document.querySelectorAll('[title]');
    tooltips.forEach(element => {
        element.addEventListener('mouseenter', showTooltip);
        element.addEventListener('mouseleave', hideTooltip);
    });
}

function showTooltip(e) {
    const title = e.target.getAttribute('title');
    if (!title) return;
    
    e.target.setAttribute('data-original-title', title);
    e.target.removeAttribute('title');
    
    const tooltip = document.createElement('div');
    tooltip.className = 'tooltip absolute bg-gray-800 text-white text-xs px-2 py-1 rounded z-50';
    tooltip.textContent = title;
    tooltip.id = 'tooltip';
    
    document.body.appendChild(tooltip);
    
    const rect = e.target.getBoundingClientRect();
    tooltip.style.left = rect.left + 'px';
    tooltip.style.top = (rect.top - tooltip.offsetHeight - 5) + 'px';
}

function hideTooltip(e) {
    const tooltip = document.getElementById('tooltip');
    if (tooltip) {
        tooltip.remove();
    }
    
    const originalTitle = e.target.getAttribute('data-original-title');
    if (originalTitle) {
        e.target.setAttribute('title', originalTitle);
        e.target.removeAttribute('data-original-title');
    }
}

// Confirmation dialogs
function initConfirmDialogs() {
    const confirmButtons = document.querySelectorAll('[data-confirm]');
    confirmButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            const message = this.getAttribute('data-confirm');
            if (!confirm(message)) {
                e.preventDefault();
            }
        });
    });
}

// Progress bars and loading states
function initProgressBars() {
    const progressBars = document.querySelectorAll('.progress-bar');
    progressBars.forEach(bar => {
        const value = bar.getAttribute('data-value');
        if (value) {
            animateProgressBar(bar, value);
        }
    });
}

function animateProgressBar(bar, targetValue) {
    let currentValue = 0;
    const increment = targetValue / 50;
    
    const interval = setInterval(() => {
        currentValue += increment;
        if (currentValue >= targetValue) {
            currentValue = targetValue;
            clearInterval(interval);
        }
        bar.style.width = currentValue + '%';
    }, 20);
}

// Utility functions
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification fixed top-4 right-4 p-4 rounded-lg shadow-lg z-50 ${getNotificationClass(type)}`;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.classList.add('opacity-0');
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

function getNotificationClass(type) {
    const classes = {
        success: 'bg-green-600 text-white',
        error: 'bg-red-600 text-white',
        warning: 'bg-yellow-600 text-white',
        info: 'bg-blue-600 text-white'
    };
    return classes[type] || classes.info;
}

function showLoadingButton(button) {
    button.classList.add('btn-loading');
    button.disabled = true;
}

function hideLoadingButton(button) {
    button.classList.remove('btn-loading');
    button.disabled = false;
}

// Auto-save functionality for forms
function initAutoSave() {
    const forms = document.querySelectorAll('[data-autosave]');
    forms.forEach(form => {
        const inputs = form.querySelectorAll('input, textarea, select');
        inputs.forEach(input => {
            input.addEventListener('change', () => {
                localStorage.setItem(`autosave_${input.name}`, input.value);
            });
            
            // Restore saved values
            const saved = localStorage.getItem(`autosave_${input.name}`);
            if (saved && !input.value) {
                input.value = saved;
            }
        });
        
        // Clear autosave on successful submit
        form.addEventListener('submit', () => {
            inputs.forEach(input => {
                localStorage.removeItem(`autosave_${input.name}`);
            });
        });
    });
}

// Export functions for use in other scripts
window.AuditTracker = {
    showNotification,
    showLoadingButton,
    hideLoadingButton,
    validateForm,
    sortTable
};
