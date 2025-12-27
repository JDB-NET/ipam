document.addEventListener('DOMContentLoaded', () => {
    // Only target the form on the subnet page, not the header search form
    // Look for a form that's not in the header (header forms have action="/search")
    const allForms = document.querySelectorAll('form');
    let form = null;
    for (let f of allForms) {
        if (f.action !== '/search' && f.method === 'POST') {
            form = f;
            break;
        }
    }
    if (form) {
        // Check if search input already exists to prevent duplicates
        if (!document.querySelector('input[placeholder="Search by IP or Hostname"]')) {
            form.addEventListener('submit', (event) => {
                event.preventDefault();
            });

            const searchInput = document.createElement('input');
            searchInput.type = 'text';
            searchInput.placeholder = 'Search by IP or Hostname';
            searchInput.className = 'p-2 w-full rounded-lg bg-gray-200 dark:bg-zinc-800 border border-gray-600 focus:outline-none focus:border-blue-400 mb-4 text-center';
            form.insertAdjacentElement('beforebegin', searchInput);

            searchInput.addEventListener('keypress', (event) => {
                if (event.key === 'Enter') {
                    event.preventDefault();
                    const searchTerm = searchInput.value.toLowerCase();
                    const rows = document.querySelectorAll('tbody tr');

                    rows.forEach(row => {
                        const ipCell = row.querySelector('td:nth-child(1)').textContent.toLowerCase();
                        const hostnameCell = row.querySelector('td:nth-child(2)').textContent.toLowerCase();
                        const descCell = row.querySelector('td:nth-child(3)');
                        const descText = descCell ? descCell.textContent.toLowerCase() : '';

                        if (ipCell.includes(searchTerm) || hostnameCell.includes(searchTerm) || descText.includes(searchTerm)) {
                            row.style.backgroundColor = 'rgba(59, 130, 246, 0.5)';
                            row.scrollIntoView({ behavior: 'smooth', block: 'center' });

                            setTimeout(() => {
                                row.style.backgroundColor = '';
                            }, 3000);
                        } else {
                            row.style.backgroundColor = '';
                        }
                    });
                }
            });
        }
    }

    // Description toggle functionality
    const toggleBtn = document.getElementById('toggle-desc');
    const descCols = document.querySelectorAll('.desc-col');
    const descHeader = document.getElementById('desc-col-header');
    let shown = false;
    if (toggleBtn) {
        toggleBtn.addEventListener('click', function() {
            shown = !shown;
            descCols.forEach(col => col.classList.toggle('hidden', !shown));
            if (descHeader) descHeader.classList.toggle('hidden', !shown);
            toggleBtn.textContent = shown ? 'Hide Descriptions' : 'Show Descriptions';
        });
    }

    // Scroll to Top Button
    const scrollToTopButton = document.createElement('button');
    scrollToTopButton.innerHTML = '<i class="fas fa-arrow-up"></i>';
    scrollToTopButton.style.fontSize = '26px';
    scrollToTopButton.className = 'fixed bottom-5 right-5 bg-gray-200 dark:bg-zinc-800 text-black dark:text-white p-3 rounded-full shadow-lg hidden';
    scrollToTopButton.style.width = '60px';
    scrollToTopButton.style.height = '60px';
    scrollToTopButton.style.borderRadius = '50%';
    document.body.appendChild(scrollToTopButton);

    const style = document.createElement('style');
    style.textContent = `
        @keyframes bob {
            0%, 100% {
                transform: translateY(0);
            }
            50% {
                transform: translateY(-5px);
            }
        }

        .bobbing {
            animation: bob 1.5s infinite;
        }
    `;
    document.head.appendChild(style);

    scrollToTopButton.classList.add('bobbing');

    window.addEventListener('scroll', () => {
        if (window.scrollY > 200) {
            scrollToTopButton.classList.remove('hidden');
        } else {
            scrollToTopButton.classList.add('hidden');
        }
    });

    scrollToTopButton.addEventListener('click', () => {
        window.scrollTo({ top: 0, behavior: 'smooth' });
    });

    // Force scrollbar thumb to render on page load
    // This fixes the issue where scrollbar thumb is missing on initial page load
    // The scrollbar only renders its thumb after a scroll event has occurred
    requestAnimationFrame(() => {
        const isScrollable = document.documentElement.scrollHeight > document.documentElement.clientHeight;
        if (isScrollable && window.scrollY === 0) {
            // Trigger a minimal scroll to force scrollbar rendering, then scroll back
            window.scrollBy(0, 1);
            requestAnimationFrame(() => {
                window.scrollBy(0, -1);
            });
        }
    });

    // Scroll to IP anchor if present in URL hash
    if (window.location.hash) {
        const hash = window.location.hash.substring(1);
        const element = document.getElementById(hash);
        if (element) {
            setTimeout(() => {
                element.scrollIntoView({ behavior: 'smooth', block: 'center' });
                // Highlight the row briefly
                element.style.backgroundColor = 'rgba(59, 130, 246, 0.5)';
                setTimeout(() => {
                    element.style.backgroundColor = '';
                }, 3000);
            }, 100);
        }
    }

    // Auto-resize all description textareas (both editable and readonly)
    const allDescTextareas = document.querySelectorAll('.desc-col textarea');
    allDescTextareas.forEach(textarea => {
        textarea.style.overflow = 'hidden';
        textarea.style.resize = 'none';
        function autoResize() {
            textarea.style.height = 'auto';
            textarea.style.height = textarea.scrollHeight + 'px';
        }
        autoResize();
    });

    // IP Notes inline editing functionality
    const ipNotesTextareas = document.querySelectorAll('.ip-notes-textarea');
    const originalValues = new Map();
    
    // Helper function to show toast notification
    function showToast(message, type = 'success') {
        const toast = document.createElement('div');
        toast.className = `fixed top-20 right-4 px-4 py-3 rounded-lg shadow-lg z-50 ${
            type === 'success' 
                ? 'bg-green-500 text-white' 
                : 'bg-red-500 text-white'
        }`;
        toast.textContent = message;
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.style.transition = 'opacity 0.3s';
            toast.style.opacity = '0';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    ipNotesTextareas.forEach(textarea => {
        // Store original value
        originalValues.set(textarea, textarea.value);
        
        // Ensure overflow is hidden and resize is disabled
        textarea.style.overflow = 'hidden';
        textarea.style.resize = 'none';
        
        // Auto-resize textarea
        function autoResize() {
            textarea.style.height = 'auto';
            textarea.style.height = textarea.scrollHeight + 'px';
        }
        autoResize();
        
        // Handle input to auto-resize
        textarea.addEventListener('input', autoResize);
        
        // Handle blur event to save notes
        textarea.addEventListener('blur', async function() {
            const ipId = this.getAttribute('data-ip-id');
            const deviceDesc = this.getAttribute('data-device-desc') || '';
            const fullValue = this.value;
            const originalValue = originalValues.get(this);
            
            // Extract IP notes: everything after the device description
            let ipNotes = '';
            if (deviceDesc) {
                // If device description exists, check if textarea starts with it
                const deviceDescTrimmed = deviceDesc.trim();
                const fullValueTrimmed = fullValue.trim();
                
                if (fullValueTrimmed.startsWith(deviceDescTrimmed)) {
                    // Remove device description from the beginning
                    ipNotes = fullValueTrimmed.substring(deviceDescTrimmed.length).trim();
                    // Also handle case where there's a newline separator
                    if (ipNotes.startsWith('\n')) {
                        ipNotes = ipNotes.substring(1).trim();
                    }
                } else {
                    // Device description was modified or removed - extract everything as IP notes
                    // This shouldn't normally happen, but handle gracefully
                    ipNotes = fullValueTrimmed;
                }
            } else {
                // No device description, so entire value is IP notes
                ipNotes = fullValue.trim();
            }
            
            // Only save if value changed
            if (fullValue !== originalValue) {
                // Show loading indicator
                const originalBg = this.style.backgroundColor;
                this.style.backgroundColor = 'rgba(59, 130, 246, 0.2)';
                this.disabled = true;
                
                try {
                    const response = await fetch(`/ip/${ipId}/update_notes`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ notes: ipNotes })
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        // Update the displayed value to reflect what was saved
                        let newDisplayValue = '';
                        if (deviceDesc) {
                            newDisplayValue = deviceDesc;
                            if (ipNotes) {
                                newDisplayValue += '\n' + ipNotes;
                            }
                        } else {
                            newDisplayValue = ipNotes;
                        }
                        this.value = newDisplayValue;
                        originalValues.set(this, newDisplayValue);
                        autoResize();
                        showToast('Notes saved successfully', 'success');
                    } else {
                        // Restore original value on error
                        this.value = originalValue;
                        autoResize();
                        showToast(data.error || 'Failed to save notes', 'error');
                    }
                } catch (error) {
                    // Restore original value on error
                    this.value = originalValue;
                    autoResize();
                    showToast('Error saving notes. Please try again.', 'error');
                    console.error('Error saving IP notes:', error);
                } finally {
                    this.style.backgroundColor = originalBg;
                    this.disabled = false;
                }
            }
        });
        
        // Handle Escape key to cancel editing
        textarea.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                this.value = originalValues.get(this);
                autoResize();
                this.blur();
            }
        });
    });
});