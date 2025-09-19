// Existing functions (generatePassword, showPassword, fetchExport, filterEntries)...

// Responsive table handling
function makeTableResponsive() {
    const tables = document.querySelectorAll('.table');
    tables.forEach(table => {
        if (window.innerWidth < 768) {
            table.classList.add('table-responsive-sm');
        } else {
            table.classList.remove('table-responsive-sm');
        }
    });
}

// ARIA live region for dynamic updates
function announceUpdate(message) {
    const liveRegion = document.getElementById('live-region') || createLiveRegion();
    liveRegion.textContent = message;
    liveRegion.setAttribute('aria-live', 'polite');
}

function createLiveRegion() {
    const region = document.createElement('div');
    region.id = 'live-region';
    region.setAttribute('aria-live', 'polite');
    region.setAttribute('aria-atomic', 'true');
    region.style.position = 'absolute';
    region.style.left = '-9999px';
    document.body.appendChild(region);
    return region;
}

// Event listeners for responsiveness
window.addEventListener('resize', makeTableResponsive);
document.addEventListener('DOMContentLoaded', makeTableResponsive);

// Improved password show with timeout for security
function showPassword(id) {
    fetch(`/get_password/${id}`)
        .then(response => response.json())
        .then(data => {
            if (data.password) {
                navigator.clipboard.writeText(data.password);
                announceUpdate(`Password copied to clipboard`);
                // Auto-clear clipboard after 30s (security)
                setTimeout(() => navigator.clipboard.writeText(''), 30000);
            } else {
                announceUpdate('Error retrieving password');
            }
        });
}