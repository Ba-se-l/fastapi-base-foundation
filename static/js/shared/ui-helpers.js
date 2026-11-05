/**
 * Shared UI Helpers & Utilities
 * Provides Toasts, Syntax Highlighting, Clipboard, and Date Formatting.
 */

export function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

export function showToast(message, type = 'info', duration = 3500) {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    const icons = {
        success: '✓',
        danger: '✕',
        warning: '⚠',
        info: 'ℹ',
    };
    
    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || 'ℹ'}</span>
        <div class="toast-message">${escapeHtml(message)}</div>
        <button class="toast-close" aria-label="Close">&times;</button>
    `;

    const closeBtn = toast.querySelector('.toast-close');
    if (closeBtn) {
        closeBtn.addEventListener('click', () => {
            toast.classList.add('fade-out');
            setTimeout(() => toast.remove(), 250);
        });
    }

    container.appendChild(toast);

    if (duration > 0) {
        setTimeout(() => {
            if (toast.isConnected) {
                toast.classList.add('fade-out');
                setTimeout(() => toast.remove(), 250);
            }
        }, duration);
    }
}

export function syntaxHighlightJson(json) {
    if (typeof json !== 'string') {
        try {
            json = JSON.stringify(json, null, 2);
        } catch {
            return escapeHtml(String(json));
        }
    }
    if (!json) return '<span class="json-null">null</span>';

    // Safely tokenize without catastrophic backtracking (ReDoS hardened)
    const escaped = escapeHtml(json);
    return escaped.replace(/(&quot;.*?&quot;)(\s*:)?|(\b(?:true|false|null)\b)|(-?\b\d+(?:\.\d+)?\b)/g, (match, str, colon, bool, num) => {
        if (str) {
            if (colon) {
                return `<span class="json-key">${str}</span>${colon}`;
            }
            return `<span class="json-string">${str}</span>`;
        }
        if (bool) {
            return `<span class="json-boolean">${bool}</span>`;
        }
        if (num) {
            return `<span class="json-number">${num}</span>`;
        }
        return match;
    });
}

export function formatDate(isoStr) {
    if (!isoStr) return '-';
    try {
        const d = new Date(isoStr);
        if (isNaN(d.getTime())) return isoStr;
        return d.toLocaleString(undefined, {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        });
    } catch {
        return isoStr;
    }
}

export function copyToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
        return navigator.clipboard.writeText(text);
    }
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.opacity = '0';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    try {
        document.execCommand('copy');
    } finally {
        textArea.remove();
    }
    return Promise.resolve();
}

export function renderBadge(type, label) {
    const cls = `badge badge-${type}`;
    return `<span class="${cls}">${escapeHtml(label)}</span>`;
}
