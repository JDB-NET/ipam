function showAddSubnetModal() {
    document.getElementById('add-subnet-modal').classList.remove('hidden');
    document.getElementById('add-subnet-name').value = '';
    document.getElementById('add-subnet-cidr').value = '';
    document.getElementById('add-subnet-site').value = '';
}

function closeAddSubnetModal() {
    document.getElementById('add-subnet-modal').classList.add('hidden');
    document.getElementById('cidr-error').classList.add('hidden');
}

function editSubnet(subnetId, name, cidr, site) {
    document.getElementById('edit-subnet-id').value = subnetId;
    document.getElementById('edit-subnet-name').value = name;
    document.getElementById('edit-subnet-cidr').value = cidr;
    document.getElementById('edit-subnet-site').value = site;
    document.getElementById('edit-subnet-modal').classList.remove('hidden');
}

function closeEditSubnetModal() {
    document.getElementById('edit-subnet-modal').classList.add('hidden');
    document.getElementById('edit-cidr-error').classList.add('hidden');
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

