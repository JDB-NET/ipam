// IP History Modal functionality
document.addEventListener('DOMContentLoaded', function() {
    const modal = document.getElementById('ip-history-modal');
    const closeBtn = document.getElementById('close-ip-history-modal');
    const content = document.getElementById('ip-history-content');
    const ipAddressSpan = document.getElementById('modal-ip-address');
    
    // Open modal when IP is clicked
    document.querySelectorAll('.ip-history-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const ip = this.getAttribute('data-ip');
            ipAddressSpan.textContent = ip;
            modal.classList.remove('hidden');
            modal.classList.add('flex');
            loadIPHistory(ip);
        });
    });
    
    // Close modal
    closeBtn.addEventListener('click', function() {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
    });
    
    // Close modal when clicking outside
    modal.addEventListener('click', function(e) {
        if (e.target === modal) {
            modal.classList.add('hidden');
            modal.classList.remove('flex');
        }
    });
    
    // Close modal with Escape key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && !modal.classList.contains('hidden')) {
            modal.classList.add('hidden');
            modal.classList.remove('flex');
        }
    });
    
    function loadIPHistory(ip) {
        content.innerHTML = '<div class="text-center text-gray-600 dark:text-gray-400">Loading...</div>';
        
        fetch(`/api/ip/${encodeURIComponent(ip)}/history`)
            .then(response => response.json())
            .then(data => {
                if (data.history && data.history.length > 0) {
                    displayHistory(data.history);
                } else {
                    content.innerHTML = '<div class="text-center text-gray-600 dark:text-gray-400">No history found for this IP address.</div>';
                }
            })
            .catch(error => {
                console.error('Error loading IP history:', error);
                content.innerHTML = '<div class="text-center text-red-500">Error loading IP history. Please try again.</div>';
            });
    }
    
    function displayHistory(history) {
        let html = '<div class="space-y-3">';
        
        history.forEach((entry, index) => {
            const isAssigned = entry.action === 'assigned';
            const icon = isAssigned ? 'fa-plus-circle text-green-500' : 'fa-minus-circle text-red-500';
            const actionText = isAssigned ? 'Assigned' : 'Removed';
            
            // Format timestamp
            let timestamp = 'Unknown';
            if (entry.timestamp) {
                try {
                    const date = new Date(entry.timestamp);
                    timestamp = date.toLocaleString();
                } catch (e) {
                    timestamp = entry.timestamp;
                }
            }
            
            html += `
                <div class="flex items-start gap-3 pb-3 ${index < history.length - 1 ? 'border-b border-gray-400 dark:border-zinc-600' : ''}">
                    <div class="flex-shrink-0 mt-1">
                        <i class="fas ${icon}"></i>
                    </div>
                    <div class="flex-1 min-w-0">
                        <div class="flex items-center gap-2 flex-wrap">
                            <span class="font-semibold">${actionText}</span>
                            <span class="text-gray-600 dark:text-gray-400">to</span>
                            <span class="font-semibold">${entry.device_name || 'Unknown'}</span>
                        </div>
                        <div class="text-sm text-gray-600 dark:text-gray-400 mt-1">
                            ${entry.subnet_name || 'Unknown'} (${entry.subnet_cidr || 'N/A'})
                        </div>
                        <div class="text-xs text-gray-500 dark:text-gray-500 mt-1">
                            by ${entry.user_name || 'Unknown'} • ${timestamp}
                        </div>
                    </div>
                </div>
            `;
        });
        
        html += '</div>';
        content.innerHTML = html;
    }
});

