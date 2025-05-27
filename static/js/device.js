document.addEventListener('DOMContentLoaded', function() {
    const siteSelect = document.getElementById('site-select');
    const subnetSelect = document.getElementById('subnet-select');
    const ipSelect = document.getElementById('ip-select');
    const renameBtn = document.querySelector('.rename-btn');
    const saveBtn = document.querySelector('.save-btn');
    const cancelBtn = document.querySelector('.cancel-btn');
    const nameInput = document.querySelector('input[name="new_name"]');
    const h1 = document.querySelector('h1');
    siteSelect.addEventListener('change', function() {
        const selectedSite = this.value;
        let firstSubnet = null;
        Array.from(subnetSelect.options).forEach(option => {
            if (!option.value) return;
            if (option.getAttribute('data-site') === selectedSite) {
                option.style.display = '';
                if (!firstSubnet) firstSubnet = option.value;
            } else {
                option.style.display = 'none';
            }
        });
        subnetSelect.value = firstSubnet || '';
        const event = new Event('change', { bubbles: true });
        subnetSelect.dispatchEvent(event);
    });
    subnetSelect.addEventListener('change', function() {
        const subnetId = this.value;
        if (!subnetId) {
            ipSelect.innerHTML = '<option value="" disabled selected>Select IP</option>';
            return;
        }
        fetch(`/get_available_ips?subnet_id=${subnetId}`)
            .then(response => response.json())
            .then(data => {
                ipSelect.innerHTML = '<option value="" disabled selected>Select IP</option>';
                data.available_ips.forEach(ip => {
                    const option = document.createElement('option');
                    option.value = ip.id;
                    option.textContent = ip.ip;
                    ipSelect.appendChild(option);
                });
            });
    });
    if (renameBtn && saveBtn && cancelBtn && nameInput && h1) {
        renameBtn.addEventListener('click', function(e) {
            e.preventDefault();
            nameInput.classList.remove('hidden');
            saveBtn.classList.remove('hidden');
            cancelBtn.classList.remove('hidden');
            h1.classList.add('hidden');
            nameInput.focus();
        });
        cancelBtn.addEventListener('click', function(e) {
            e.preventDefault();
            nameInput.classList.add('hidden');
            saveBtn.classList.add('hidden');
            cancelBtn.classList.add('hidden');
            h1.classList.remove('hidden');
        });
    }
});