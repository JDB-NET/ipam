// Custom Fields Management JavaScript

// Get initial tab from URL parameter or default to 'device'
const urlParams = new URLSearchParams(window.location.search);
let currentTab = urlParams.get('tab') || 'device';
if (currentTab !== 'device' && currentTab !== 'subnet') {
    currentTab = 'device';
}

// Switch to the correct tab on page load
if (currentTab === 'subnet') {
    switchTab('subnet');
} else {
    // Ensure device tab is active on load
    switchTab('device');
}

// Function to get current active tab
function getCurrentTab() {
    return currentTab;
}

let fieldData = {};

// Tab switching
function switchTab(entityType) {
    currentTab = entityType;
    
    // Update tab buttons
    document.getElementById('tab-device').classList.remove('border-gray-600', 'text-gray-900', 'dark:text-gray-100');
    document.getElementById('tab-device').classList.add('border-transparent', 'text-gray-500');
    document.getElementById('tab-subnet').classList.remove('border-gray-600', 'text-gray-900', 'dark:text-gray-100');
    document.getElementById('tab-subnet').classList.add('border-transparent', 'text-gray-500');
    
    if (entityType === 'device') {
        document.getElementById('tab-device').classList.remove('border-transparent', 'text-gray-500');
        document.getElementById('tab-device').classList.add('border-gray-600', 'text-gray-900', 'dark:text-gray-100');
        document.getElementById('device-fields-tab').classList.remove('hidden');
        document.getElementById('subnet-fields-tab').classList.add('hidden');
    } else {
        document.getElementById('tab-subnet').classList.remove('border-transparent', 'text-gray-500');
        document.getElementById('tab-subnet').classList.add('border-gray-600', 'text-gray-900', 'dark:text-gray-100');
        document.getElementById('device-fields-tab').classList.add('hidden');
        document.getElementById('subnet-fields-tab').classList.remove('hidden');
    }
    
    // Update URL without reloading page
    const newUrl = new URL(window.location);
    newUrl.searchParams.set('tab', entityType);
    window.history.pushState({}, '', newUrl);
}

// Show add field modal
function showAddFieldModal(entityType) {
    // Determine the target entity type - prioritize explicit parameter, then read from DOM
    let targetEntityType = entityType;
    
    if (!targetEntityType) {
        // Read from active tab button - check which tab has the active styling
        const deviceTab = document.getElementById('tab-device');
        const subnetTab = document.getElementById('tab-subnet');
        
        if (deviceTab && deviceTab.classList.contains('border-gray-600')) {
            targetEntityType = 'device';
        } else if (subnetTab && subnetTab.classList.contains('border-gray-600')) {
            targetEntityType = 'subnet';
        } else {
            // Fallback to currentTab variable
            targetEntityType = currentTab || 'device';
        }
    }
    
    // Ensure targetEntityType is valid
    if (targetEntityType !== 'device' && targetEntityType !== 'subnet') {
        targetEntityType = 'device';
    }
    
    // Ensure we're on the correct tab
    if (targetEntityType !== currentTab) {
        switchTab(targetEntityType);
    }
    
    document.getElementById('modal-title').textContent = 'Add Custom Field';
    document.getElementById('form-action').value = 'add_field';
    document.getElementById('form-field-id').value = '';
    
    // Always set entity_type explicitly - double check it's set
    const entityTypeInput = document.getElementById('form-entity-type');
    entityTypeInput.value = targetEntityType;
    
    // Debug: log to verify
    console.log('Opening modal for entity type:', targetEntityType, 'currentTab:', currentTab, 'input value:', entityTypeInput.value);
    
    // Reset form
    document.getElementById('field-name').value = '';
    document.getElementById('field-key').value = '';
    document.getElementById('field-type').value = 'text';
    document.getElementById('field-required').checked = false;
    document.getElementById('field-default-value').value = '';
    document.getElementById('field-help-text').value = '';
    document.getElementById('field-display-order').value = '0';
    document.getElementById('field-searchable').checked = false;
    
    // Reset validation fields
    document.getElementById('field-min-length').value = '';
    document.getElementById('field-max-length').value = '';
    document.getElementById('field-regex-pattern').value = '';
    document.getElementById('field-min-value').value = '';
    document.getElementById('field-max-value').value = '';
    document.getElementById('field-select-options').value = '';
    
    updateFieldTypeOptions();
    document.getElementById('field-modal').classList.remove('hidden');
}

// Close field modal
function closeFieldModal() {
    document.getElementById('field-modal').classList.add('hidden');
}

// Update field type options visibility
function updateFieldTypeOptions() {
    const fieldType = document.getElementById('field-type').value;
    
    // Hide all validation sections
    document.getElementById('text-validation').classList.add('hidden');
    document.getElementById('number-validation').classList.add('hidden');
    document.getElementById('select-validation').classList.add('hidden');
    
    // Show relevant validation section
    if (fieldType === 'text' || fieldType === 'textarea') {
        document.getElementById('text-validation').classList.remove('hidden');
    } else if (fieldType === 'number' || fieldType === 'decimal') {
        document.getElementById('number-validation').classList.remove('hidden');
    } else if (fieldType === 'select') {
        document.getElementById('select-validation').classList.remove('hidden');
    }
}

// Auto-generate field key from name
function generateFieldKey(name) {
    return name.toLowerCase()
        .replace(/[^a-z0-9]+/g, '_')
        .replace(/^_+|_+$/g, '');
}

// Edit field
function editField(fieldId, entityType) {
    // Get field data from embedded JSON
    const fieldsDataElement = document.getElementById('fields-data');
    if (!fieldsDataElement) {
        console.error('Fields data not found');
        return;
    }
    
    try {
        const fieldsData = JSON.parse(fieldsDataElement.textContent);
        const fields = fieldsData[entityType] || [];
        const field = fields.find(f => f.id === fieldId);
        
        if (field) {
            populateEditForm(field, entityType);
        } else {
            console.error('Field not found:', fieldId, entityType);
        }
    } catch (error) {
        console.error('Error parsing fields data:', error);
    }
}

function populateEditForm(field, entityType) {
    document.getElementById('modal-title').textContent = 'Edit Custom Field';
    document.getElementById('form-action').value = 'edit_field';
    document.getElementById('form-field-id').value = field.id;
    document.getElementById('form-entity-type').value = entityType;
    
    document.getElementById('field-name').value = field.name || '';
    document.getElementById('field-key').value = field.field_key || '';
    document.getElementById('field-type').value = field.field_type || 'text';
    document.getElementById('field-required').checked = field.required || false;
    document.getElementById('field-default-value').value = field.default_value || '';
    document.getElementById('field-help-text').value = field.help_text || '';
    document.getElementById('field-display-order').value = field.display_order || 0;
    document.getElementById('field-searchable').checked = field.searchable || false;
    
    // Parse validation rules
    let validationRules = {};
    if (field.validation_rules) {
        if (typeof field.validation_rules === 'string') {
            try {
                validationRules = JSON.parse(field.validation_rules);
            } catch (e) {
                validationRules = {};
            }
        } else {
            validationRules = field.validation_rules;
        }
    }
    
    // Populate validation fields
    document.getElementById('field-min-length').value = validationRules.min_length || '';
    document.getElementById('field-max-length').value = validationRules.max_length || '';
    document.getElementById('field-regex-pattern').value = validationRules.regex_pattern || '';
    document.getElementById('field-min-value').value = validationRules.min_value || '';
    document.getElementById('field-max-value').value = validationRules.max_value || '';
    
    if (validationRules.select_options) {
        document.getElementById('field-select-options').value = validationRules.select_options.join(', ');
    } else {
        document.getElementById('field-select-options').value = '';
    }
    
    updateFieldTypeOptions();
    document.getElementById('field-modal').classList.remove('hidden');
}

// Move field up/down
function moveField(entityType, fieldId, direction) {
    // Get all fields for this entity type
    const tbody = document.getElementById(`${entityType}-fields-tbody`);
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const currentIndex = rows.findIndex(row => row.dataset.fieldId == fieldId);
    
    if (currentIndex === -1) return;
    
    let targetIndex;
    if (direction === 'up' && currentIndex > 0) {
        targetIndex = currentIndex - 1;
    } else if (direction === 'down' && currentIndex < rows.length - 1) {
        targetIndex = currentIndex + 1;
    } else {
        return;
    }
    
    // Swap rows
    const currentRow = rows[currentIndex];
    const targetRow = rows[targetIndex];
    tbody.insertBefore(currentRow, direction === 'up' ? targetRow : targetRow.nextSibling);
    
    // Update display orders and submit
    const fieldOrders = {};
    Array.from(tbody.querySelectorAll('tr')).forEach((row, index) => {
        fieldOrders[row.dataset.fieldId] = index;
    });
    
    // Submit reorder
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = '/custom_fields';
    
    const actionInput = document.createElement('input');
    actionInput.type = 'hidden';
    actionInput.name = 'action';
    actionInput.value = 'reorder';
    form.appendChild(actionInput);
    
    const entityTypeInput = document.createElement('input');
    entityTypeInput.type = 'hidden';
    entityTypeInput.name = 'entity_type';
    entityTypeInput.value = entityType;
    form.appendChild(entityTypeInput);
    
    const ordersInput = document.createElement('input');
    ordersInput.type = 'hidden';
    ordersInput.name = 'field_orders';
    ordersInput.value = JSON.stringify(fieldOrders);
    form.appendChild(ordersInput);
    
    document.body.appendChild(form);
    form.submit();
}

// Event listeners
document.addEventListener('DOMContentLoaded', function() {
    // Auto-generate field key from name
    const nameInput = document.getElementById('field-name');
    const keyInput = document.getElementById('field-key');
    
    if (nameInput && keyInput) {
        nameInput.addEventListener('input', function() {
            // Only auto-generate if key is empty or matches previous generated value
            if (!keyInput.value || keyInput.dataset.autoGenerated === 'true') {
                keyInput.value = generateFieldKey(this.value);
                keyInput.dataset.autoGenerated = 'true';
            }
        });
        
        keyInput.addEventListener('input', function() {
            // Mark as manually edited
            this.dataset.autoGenerated = 'false';
        });
    }
    
    // Update field type options when type changes
    const fieldTypeSelect = document.getElementById('field-type');
    if (fieldTypeSelect) {
        fieldTypeSelect.addEventListener('change', updateFieldTypeOptions);
    }
    
    // Ensure entity_type is set correctly before form submission
    const fieldForm = document.getElementById('field-form');
    if (fieldForm) {
        fieldForm.addEventListener('submit', function(e) {
            const entityTypeInput = document.getElementById('form-entity-type');
            // Always ensure entity_type is set to currentTab
            // This handles cases where the modal was opened without explicitly setting it
            if (!entityTypeInput.value || entityTypeInput.value.trim() === '') {
                entityTypeInput.value = currentTab;
                console.log('Entity type was empty, setting to:', currentTab);
            }
            // Double-check it's a valid value
            if (entityTypeInput.value !== 'device' && entityTypeInput.value !== 'subnet') {
                entityTypeInput.value = currentTab;
                console.log('Entity type was invalid, setting to currentTab:', currentTab);
            }
            console.log('Submitting form with entity_type:', entityTypeInput.value, 'currentTab:', currentTab);
        });
    }
});

// Close modal when clicking outside
window.onclick = function(event) {
    const modal = document.getElementById('field-modal');
    if (event.target === modal) {
        closeFieldModal();
    }
}

