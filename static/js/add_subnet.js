function validateSubnetForm() {
    const cidrInput = document.getElementById('cidr-input');
    const errorSpan = document.getElementById('cidr-error');
    const cidrPattern = /^(?:\d{1,3}\.){3}\d{1,3}\/([0-9]|[1-2][0-9]|3[0-2])$/;
    if (!cidrPattern.test(cidrInput.value.trim())) {
        errorSpan.textContent = 'Please enter a valid CIDR (e.g., 192.168.1.0/24)';
        errorSpan.classList.remove('hidden');
        cidrInput.classList.add('border-red-500');
        return false;
    }
    errorSpan.textContent = '';
    errorSpan.classList.add('hidden');
    cidrInput.classList.remove('border-red-500');
    return true;
}