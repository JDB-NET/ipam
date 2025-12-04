document.addEventListener('DOMContentLoaded', function() {
    // Check if toast was dismissed in this session
    const toastDismissed = sessionStorage.getItem('update-toast-dismissed');
    if (toastDismissed) {
        return;
    }
    
    // Check for updates
    fetch('/check_update')
        .then(response => response.json())
        .then(data => {
            if (data.update_available) {
                const toast = document.getElementById('update-toast');
                const currentVersionEl = document.getElementById('toast-current-version');
                const latestVersionEl = document.getElementById('toast-latest-version');
                const compareLink = document.getElementById('toast-compare-link');
                const closeBtn = document.getElementById('toast-close');
                
                // Set versions
                currentVersionEl.textContent = 'v' + data.current_version;
                latestVersionEl.textContent = 'v' + data.latest_version;
                
                // Set compare link (current version to latest version)
                compareLink.href = `https://github.com/JDB-NET/ipam/compare/v${data.current_version}...v${data.latest_version}`;
                
                // Show toast
                toast.classList.remove('hidden');
                
                // Close button handler
                closeBtn.addEventListener('click', function() {
                    toast.classList.add('hidden');
                    sessionStorage.setItem('update-toast-dismissed', 'true');
                });
            }
        })
        .catch(error => {
            console.error('Error checking for updates:', error);
        });
});

