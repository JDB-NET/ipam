// Font Awesome icon search functionality
// Common Font Awesome icons for device types
const fontAwesomeIcons = [
    // Network & Server
    'fa-server', 'fa-router', 'fa-network-wired', 'fa-switch', 'fa-hub', 'fa-ethernet',
    'fa-satellite-dish', 'fa-broadcast-tower', 'fa-tower-cell', 'fa-wifi', 'fa-network',
    'fa-project-diagram', 'fa-sitemap', 'fa-diagram-project', 'fa-cloud',
    
    // Security
    'fa-shield-halved', 'fa-shield', 'fa-shield-alt', 'fa-firewall', 'fa-lock', 'fa-unlock',
    'fa-key', 'fa-fingerprint', 'fa-user-shield', 'fa-user-lock',
    
    // Hardware
    'fa-print', 'fa-boxes-stacked', 'fa-database', 'fa-hard-drive', 'fa-memory', 'fa-microchip',
    'fa-cpu', 'fa-usb', 'fa-fan', 'fa-battery-full', 'fa-power-off', 'fa-plug', 'fa-bolt',
    'fa-lightbulb', 'fa-monitor', 'fa-display', 'fa-tv', 'fa-camera', 'fa-video',
    
    // Computing
    'fa-laptop', 'fa-desktop', 'fa-tablet', 'fa-mobile-alt', 'fa-phone', 'fa-keyboard',
    'fa-mouse', 'fa-microphone', 'fa-headphones', 'fa-speaker',
    
    // Storage & Files
    'fa-box', 'fa-package', 'fa-archive', 'fa-folder', 'fa-file', 'fa-hdd', 'fa-ssd',
    'fa-floppy-disk', 'fa-disk', 'fa-save', 'fa-folder-open', 'fa-folder-plus',
    
    // Data & Analytics
    'fa-chart-line', 'fa-chart-bar', 'fa-chart-pie', 'fa-graph', 'fa-analytics',
    'fa-database', 'fa-file-database', 'fa-file-chart-line', 'fa-file-chart-pie',
    
    // Location & Infrastructure
    'fa-globe', 'fa-earth', 'fa-map', 'fa-location', 'fa-map-marker', 'fa-building',
    'fa-warehouse', 'fa-home', 'fa-office', 'fa-industry',
    
    // Tools & Utilities
    'fa-robot', 'fa-cog', 'fa-gear', 'fa-wrench', 'fa-tools', 'fa-question',
    'fa-code', 'fa-terminal', 'fa-console', 'fa-bug', 'fa-bug-slash',
    
    // Identification
    'fa-id-card', 'fa-credit-card', 'fa-qrcode', 'fa-barcode', 'fa-rfid',
    
    // Transport & Logistics
    'fa-truck', 'fa-shipping-fast', 'fa-conveyor-belt', 'fa-pallet', 'fa-dolly',
    'fa-cube', 'fa-cubes', 'fa-layer-group', 'fa-stack',
    
    // UI & Display
    'fa-th', 'fa-th-large', 'fa-th-list', 'fa-list', 'fa-list-ul', 'fa-list-ol',
    'fa-table', 'fa-columns', 'fa-grid', 'fa-window-maximize', 'fa-window-restore',
    'fa-window-minimize', 'fa-window-close', 'fa-expand', 'fa-compress',
    
    // Actions
    'fa-sync', 'fa-sync-alt', 'fa-redo', 'fa-undo', 'fa-refresh', 'fa-download',
    'fa-upload', 'fa-exchange-alt', 'fa-share', 'fa-link', 'fa-unlink', 'fa-chain',
    'fa-chain-broken', 'fa-arrows-alt', 'fa-arrows', 'fa-move',
    
    // Time & Calendar
    'fa-clock', 'fa-hourglass', 'fa-stopwatch', 'fa-timer', 'fa-calendar',
    'fa-calendar-alt', 'fa-calendar-check', 'fa-calendar-times', 'fa-history',
    
    // Media
    'fa-play', 'fa-pause', 'fa-stop', 'fa-step-backward', 'fa-step-forward',
    'fa-fast-backward', 'fa-fast-forward', 'fa-eject', 'fa-record-vinyl',
    'fa-compact-disc', 'fa-cd', 'fa-dvd',
    
    // Users
    'fa-user-shield', 'fa-user-lock', 'fa-user-secret', 'fa-user-cog', 'fa-user-gear',
    'fa-user-tie', 'fa-user-ninja', 'fa-users', 'fa-users-cog', 'fa-user-group',
    'fa-user-friends', 'fa-user-plus', 'fa-user-minus', 'fa-user-times', 'fa-user-check',
    'fa-user-xmark', 'fa-user-slash'
];

function initIconSearch() {
    const iconInputs = document.querySelectorAll('.icon-search-input');
    
    iconInputs.forEach(input => {
        const container = input.closest('.icon-search-container');
        const preview = container.querySelector('.icon-preview');
        const suggestions = container.querySelector('.icon-suggestions');
        
        if (!preview || !suggestions) return;
        
        // Initialize preview if input already has a value
        if (input.value && input.value.trim()) {
            const iconClass = input.value.trim().startsWith('fa-') ? input.value.trim() : `fa-${input.value.trim()}`;
            preview.innerHTML = `<i class="fas ${iconClass}"></i>`;
            preview.classList.remove('hidden');
        }
        
        input.addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase().trim();
            
            // Update preview
            if (query) {
                const iconClass = query.startsWith('fa-') ? query : `fa-${query}`;
                preview.innerHTML = `<i class="fas ${iconClass}"></i>`;
                preview.classList.remove('hidden');
            } else {
                preview.classList.add('hidden');
            }
            
            // Filter and display suggestions
            if (query.length > 0) {
                const filtered = fontAwesomeIcons.filter(icon => 
                    icon.includes(query) || icon.replace('fa-', '').includes(query)
                ).slice(0, 10); // Show top 10 matches
                
                if (filtered.length > 0) {
                    suggestions.innerHTML = filtered.map(icon => `
                        <div class="icon-suggestion-item" data-icon="${icon}">
                            <i class="fas ${icon}"></i>
                            <span>${icon}</span>
                        </div>
                    `).join('');
                    suggestions.classList.remove('hidden');
                    
                    // Add click handlers
                    suggestions.querySelectorAll('.icon-suggestion-item').forEach(item => {
                        item.addEventListener('click', () => {
                            input.value = item.dataset.icon;
                            preview.innerHTML = `<i class="fas ${item.dataset.icon}"></i>`;
                            preview.classList.remove('hidden');
                            suggestions.classList.add('hidden');
                        });
                    });
                } else {
                    suggestions.classList.add('hidden');
                }
            } else {
                suggestions.classList.add('hidden');
            }
        });
        
        // Hide suggestions when clicking outside
        document.addEventListener('click', (e) => {
            if (!container.contains(e.target)) {
                suggestions.classList.add('hidden');
            }
        });
        
        // Update preview on blur if value exists
        input.addEventListener('blur', () => {
            const value = input.value.trim();
            if (value && preview) {
                const iconClass = value.startsWith('fa-') ? value : `fa-${value}`;
                preview.innerHTML = `<i class="fas ${iconClass}"></i>`;
                preview.classList.remove('hidden');
            }
        });
    });
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initIconSearch);
} else {
    initIconSearch();
}

