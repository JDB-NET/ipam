document.addEventListener('DOMContentLoaded', function() {
    // Filter toggle functionality
    const filterToggle = document.getElementById('filter-toggle');
    const filterForm = document.getElementById('audit-filter-form');
    const filterArrow = document.getElementById('filter-arrow');
    
    if (filterToggle && filterForm && filterArrow) {
        filterToggle.addEventListener('click', function() {
            filterForm.classList.toggle('hidden');
            // Toggle rotation using inline style for better compatibility
            if (filterForm.classList.contains('hidden')) {
                filterArrow.style.transform = 'rotate(0deg)';
            } else {
                filterArrow.style.transform = 'rotate(180deg)';
            }
        });
        
        // Set initial arrow rotation if form is visible (has active filters or expand_filters param)
        if (!filterForm.classList.contains('hidden')) {
            filterArrow.style.transform = 'rotate(180deg)';
        }
    }
    
    // Format timestamps
    document.querySelectorAll('td[data-utc]').forEach(function(td) {
        const utc = td.getAttribute('data-utc');
        if (utc) {
            const date = new Date(utc + 'Z');
            td.textContent = date.toLocaleString();
        }
    });
    
    // Parse and display visual diffs
    document.querySelectorAll('.diff-container').forEach(function(container) {
        const details = container.getAttribute('data-details');
        if (!details) return;
        
        // Try to parse common change patterns
        let html = details;
        
        // Pattern 1: "Changed X from 'old' to 'new'"
        html = html.replace(/Changed (.+?) from ['"](.+?)['"] to ['"](.+?)['"]/gi, function(match, field, oldVal, newVal) {
            return `Changed ${field} from <span class="diff-removed">${oldVal}</span> to <span class="diff-added">${newVal}</span>`;
        });
        
        // Pattern 2: "Renamed X to Y"
        html = html.replace(/Renamed (.+?) to ['"](.+?)['"]/gi, function(match, oldVal, newVal) {
            return `Renamed <span class="diff-removed">${oldVal}</span> to <span class="diff-added">${newVal}</span>`;
        });
        
        // Pattern 3: "Updated X: old -> new"
        html = html.replace(/Updated (.+?):\s*(.+?)\s*->\s*(.+?)(?:\s|$)/gi, function(match, field, oldVal, newVal) {
            return `Updated ${field}: <span class="diff-removed">${oldVal}</span> → <span class="diff-added">${newVal}</span>`;
        });
        
        // Pattern 4: "Set X to Y" (when it was previously something else, look for context)
        html = html.replace(/Set (.+?) to ['"](.+?)['"]/gi, function(match, field, newVal) {
            return `Set ${field} to <span class="diff-added">${newVal}</span>`;
        });
        
        // Pattern 5: "Removed X" or "Deleted X"
        html = html.replace(/(Removed|Deleted) ['"](.+?)['"]/gi, function(match, action, val) {
            return `${action} <span class="diff-removed">${val}</span>`;
        });
        
        // Pattern 6: "Added X"
        html = html.replace(/Added ['"](.+?)['"]/gi, function(match, val) {
            return `Added <span class="diff-added">${val}</span>`;
        });
        
        // Pattern 7: "Assigned X to Y" or "Unassigned X from Y"
        html = html.replace(/(Assigned|Unassigned) (.+?) (to|from) (.+?)(?:\s|$)/gi, function(match, action, item, prep, target) {
            const actionClass = action === 'Assigned' ? 'diff-added' : 'diff-removed';
            return `${action} <span class="${actionClass}">${item}</span> ${prep} ${target}`;
        });
        
        // Pattern 8: Generic "from X to Y" pattern
        html = html.replace(/from ['"](.+?)['"] to ['"](.+?)['"]/gi, function(match, oldVal, newVal) {
            return `from <span class="diff-removed">${oldVal}</span> to <span class="diff-added">${newVal}</span>`;
        });
        
        container.innerHTML = html || details;
    });
    
    // Export button handler
    const exportBtn = document.getElementById('export-btn');
    if (exportBtn) {
        exportBtn.addEventListener('click', function() {
            const form = document.getElementById('audit-filter-form');
            const formData = new FormData(form);
            const params = new URLSearchParams();
            
            // Add all form fields to params
            for (const [key, value] of formData.entries()) {
                if (value) {
                    if (key === 'user_ids') {
                        // Handle multiple user_ids
                        params.append('user_ids', value);
                    } else {
                        params.append(key, value);
                    }
                }
            }
            
            // Handle multiple user_ids separately
            const userSelect = form.querySelector('select[name="user_ids"]');
            if (userSelect) {
                const selectedUsers = Array.from(userSelect.selectedOptions).map(opt => opt.value);
                params.delete('user_ids');
                selectedUsers.forEach(userId => {
                    params.append('user_ids', userId);
                });
            }
            
            // Redirect to export endpoint
            window.location.href = '/audit/export_csv?' + params.toString();
        });
    }
});

