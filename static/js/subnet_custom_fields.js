// Auto-save custom fields on blur (subnet page)
document.addEventListener('DOMContentLoaded', () => {
    const customFieldsForm = document.getElementById('custom-fields-form');
    if (!customFieldsForm) {
        return; // No custom fields form on this page
    }

    const subnetId = customFieldsForm.action.match(/\/subnet\/(\d+)\/update_custom_fields/)?.[1];
    if (!subnetId) {
        return;
    }

    // Get all form fields
    const formFields = customFieldsForm.querySelectorAll('input, textarea, select');
    const originalValues = new Map();
    
    // Store original values
    formFields.forEach(field => {
        if (field.type === 'checkbox') {
            originalValues.set(field, field.checked);
        } else {
            originalValues.set(field, field.value);
        }
    });

    // Helper function to show toast notification (reuse from subnet.js if available)
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

    // Auto-resize textareas
    const textareas = customFieldsForm.querySelectorAll('textarea');
    textareas.forEach(textarea => {
        textarea.style.overflow = 'hidden';
        textarea.style.resize = 'none';
        
        function autoResize() {
            textarea.style.height = 'auto';
            textarea.style.height = textarea.scrollHeight + 'px';
        }
        autoResize();
        textarea.addEventListener('input', autoResize);
    });

    // Check if form has changes
    function hasChanges() {
        for (const field of formFields) {
            let currentValue;
            if (field.type === 'checkbox') {
                currentValue = field.checked;
            } else {
                currentValue = field.value;
            }
            
            const originalValue = originalValues.get(field);
            if (currentValue !== originalValue) {
                return true;
            }
        }
        return false;
    }

    // Save all custom fields
    let saveInProgress = false;
    async function saveCustomFields() {
        if (saveInProgress) {
            return; // Prevent multiple simultaneous saves
        }

        if (!hasChanges()) {
            return; // No changes to save
        }

        saveInProgress = true;

        // Show loading indicator on form
        const originalOpacity = customFieldsForm.style.opacity;
        customFieldsForm.style.opacity = '0.6';
        customFieldsForm.style.pointerEvents = 'none';

        try {
            // Create FormData from form and convert to JSON
            const formData = new FormData(customFieldsForm);
            const data = {};
            
            // Process all fields
            for (const [key, value] of formData.entries()) {
                data[key] = value;
            }
            
            // Handle checkboxes that weren't checked (they don't appear in FormData)
            formFields.forEach(field => {
                if (field.type === 'checkbox' && !field.checked) {
                    data[field.name] = '';
                }
            });

            const response = await fetch(customFieldsForm.action, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            });

            if (response.ok) {
                // Update original values
                formFields.forEach(field => {
                    if (field.type === 'checkbox') {
                        originalValues.set(field, field.checked);
                    } else {
                        originalValues.set(field, field.value);
                    }
                });
                
                showToast('Custom fields saved successfully', 'success');
            } else {
                const data = await response.json().catch(() => ({}));
                const errorMsg = data.errors ? data.errors.join(', ') : (data.error || 'Failed to save custom fields');
                showToast(errorMsg, 'error');
            }
        } catch (error) {
            showToast('Error saving custom fields. Please try again.', 'error');
            console.error('Error saving custom fields:', error);
        } finally {
            customFieldsForm.style.opacity = originalOpacity;
            customFieldsForm.style.pointerEvents = '';
            saveInProgress = false;
        }
    }

    // Add blur event listeners to all fields
    formFields.forEach(field => {
        // Skip if it's a checkbox (we'll handle change event instead)
        if (field.type === 'checkbox') {
            field.addEventListener('change', () => {
                // Small delay to ensure value is updated
                setTimeout(saveCustomFields, 100);
            });
        } else {
            field.addEventListener('blur', saveCustomFields);
        }
    });

    // Prevent form submission (since we're using auto-save)
    customFieldsForm.addEventListener('submit', (e) => {
        e.preventDefault();
        saveCustomFields();
    });
});

