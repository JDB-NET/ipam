function showAddSubnetModal() {
    document.getElementById('add-subnet-modal').classList.remove('hidden');
    document.getElementById('add-subnet-name').value = '';
    document.getElementById('add-subnet-cidr').value = '';
    document.getElementById('add-subnet-site').value = '';
    document.getElementById('add-subnet-vlan-id').value = '';
    document.getElementById('add-subnet-vlan-description').value = '';
    document.getElementById('add-subnet-vlan-notes').value = '';
    document.getElementById('vlan-id-error').classList.add('hidden');
}

function closeAddSubnetModal() {
    document.getElementById('add-subnet-modal').classList.add('hidden');
    document.getElementById('cidr-error').classList.add('hidden');
    document.getElementById('vlan-id-error').classList.add('hidden');
}

function editSubnet(subnetId, name, cidr, site, vlanId, vlanDescription, vlanNotes) {
    document.getElementById('edit-subnet-id').value = subnetId;
    document.getElementById('edit-subnet-name').value = name;
    document.getElementById('edit-subnet-cidr').value = cidr;
    document.getElementById('edit-subnet-site').value = site;
    document.getElementById('edit-subnet-vlan-id').value = vlanId || '';
    document.getElementById('edit-subnet-vlan-description').value = vlanDescription || '';
    document.getElementById('edit-subnet-vlan-notes').value = vlanNotes || '';
    document.getElementById('edit-subnet-modal').classList.remove('hidden');
}

function closeEditSubnetModal() {
    document.getElementById('edit-subnet-modal').classList.add('hidden');
    document.getElementById('edit-cidr-error').classList.add('hidden');
    document.getElementById('edit-vlan-id-error').classList.add('hidden');
}

function validateVlanId(vlanIdValue, errorElementId) {
    if (!vlanIdValue || vlanIdValue.trim() === '') {
        return true; // VLAN ID is optional
    }
    
    const vlanId = parseInt(vlanIdValue.trim());
    if (isNaN(vlanId)) {
        const errorElement = document.getElementById(errorElementId);
        if (errorElement) {
            errorElement.textContent = 'VLAN ID must be a valid integer';
            errorElement.classList.remove('hidden');
        }
        return false;
    }
    
    if (vlanId < 1 || vlanId > 4094) {
        const errorElement = document.getElementById(errorElementId);
        if (errorElement) {
            errorElement.textContent = 'VLAN ID must be between 1 and 4094';
            errorElement.classList.remove('hidden');
        }
        return false;
    }
    
    const errorElement = document.getElementById(errorElementId);
    if (errorElement) {
        errorElement.classList.add('hidden');
    }
    return true;
}

function validateSubnetForm() {
    const cidrInput = document.getElementById('add-subnet-cidr');
    const cidrError = document.getElementById('cidr-error');
    const cidr = cidrInput.value.trim();
    
    // Basic CIDR validation
    const cidrPattern = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    if (!cidrPattern.test(cidr)) {
        cidrError.textContent = 'Invalid CIDR format. Use format like 192.168.1.0/24';
        cidrError.classList.remove('hidden');
        return false;
    }
    
    // Check prefix length
    const parts = cidr.split('/');
    if (parts.length === 2) {
        const prefixLen = parseInt(parts[1]);
        if (prefixLen < 24 || prefixLen > 32) {
            cidrError.textContent = 'Subnet must be /24 or smaller (e.g., /24, /25, ... /32)';
            cidrError.classList.remove('hidden');
            return false;
        }
    }
    
    cidrError.classList.add('hidden');
    
    // Validate VLAN ID
    const vlanIdInput = document.getElementById('add-subnet-vlan-id');
    if (!validateVlanId(vlanIdInput.value, 'vlan-id-error')) {
        return false;
    }
    
    return true;
}

function validateEditSubnetForm() {
    const cidrInput = document.getElementById('edit-subnet-cidr');
    const cidrError = document.getElementById('edit-cidr-error');
    const cidr = cidrInput.value.trim();
    
    // Basic CIDR validation
    const cidrPattern = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    if (!cidrPattern.test(cidr)) {
        cidrError.textContent = 'Invalid CIDR format. Use format like 192.168.1.0/24';
        cidrError.classList.remove('hidden');
        return false;
    }
    
    // Check prefix length
    const parts = cidr.split('/');
    if (parts.length === 2) {
        const prefixLen = parseInt(parts[1]);
        if (prefixLen < 24 || prefixLen > 32) {
            cidrError.textContent = 'Subnet must be /24 or smaller (e.g., /24, /25, ... /32)';
            cidrError.classList.remove('hidden');
            return false;
        }
    }
    
    cidrError.classList.add('hidden');
    
    // Validate VLAN ID
    const vlanIdInput = document.getElementById('edit-subnet-vlan-id');
    if (!validateVlanId(vlanIdInput.value, 'edit-vlan-id-error')) {
        return false;
    }
    
    return true;
}

// Close modals when clicking outside
window.onclick = function(event) {
    const addModal = document.getElementById('add-subnet-modal');
    const editModal = document.getElementById('edit-subnet-modal');
    if (event.target === addModal) {
        closeAddSubnetModal();
    }
    if (event.target === editModal) {
        closeEditSubnetModal();
    }
}

