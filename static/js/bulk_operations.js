function showTab(tabName) {
    // Hide all panels
    document.querySelectorAll('.tab-panel').forEach(panel => panel.classList.add('hidden'));
    
    // Update all tab buttons to inactive state
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('border-gray-600', 'text-gray-900', 'dark:text-gray-100');
        btn.classList.add('border-transparent', 'text-gray-500');
    });
    
    // Show selected panel
    document.getElementById('panel-' + tabName).classList.remove('hidden');
    
    // Update selected tab to active state
    const activeTab = document.getElementById('tab-' + tabName);
    activeTab.classList.remove('border-transparent', 'text-gray-500');
    activeTab.classList.add('border-gray-600', 'text-gray-900', 'dark:text-gray-100');
}

document.addEventListener('DOMContentLoaded', function() {
    // Update selected IP count
    document.getElementById('bulk-ip-select')?.addEventListener('change', function() {
        document.getElementById('selected-ip-count').textContent = this.selectedOptions.length;
    });
    
    document.getElementById('bulk-tag-device-select')?.addEventListener('change', function() {
        document.getElementById('selected-tag-device-count').textContent = this.selectedOptions.length;
    });
    
    // Load available IPs when subnet changes
    document.getElementById('bulk-subnet-select')?.addEventListener('change', function() {
        const subnetId = this.value;
        const ipSelect = document.getElementById('bulk-ip-select');
        if (!subnetId) {
            ipSelect.innerHTML = '<option value="" disabled>Select a subnet first...</option>';
            document.getElementById('selected-ip-count').textContent = '0';
            return;
        }
        ipSelect.innerHTML = '<option value="" disabled>Loading...</option>';
        fetch(`/get_available_ips?subnet_id=${subnetId}`)
            .then(response => response.json())
            .then(data => {
                ipSelect.innerHTML = '';
                if (data.available_ips.length === 0) {
                    ipSelect.innerHTML = '<option value="" disabled>No available IPs in this subnet</option>';
                } else {
                    data.available_ips.forEach(ip => {
                        const option = document.createElement('option');
                        option.value = ip.id;
                        option.textContent = ip.ip;
                        ipSelect.appendChild(option);
                    });
                }
                document.getElementById('selected-ip-count').textContent = '0';
            })
            .catch(() => {
                ipSelect.innerHTML = '<option value="" disabled>Error loading IPs</option>';
            });
    });
    
    // Bulk IP Assignment
    document.getElementById('bulk-assign-ips-form')?.addEventListener('submit', function(e) {
        e.preventDefault();
        const formData = new FormData(this);
        const resultDiv = document.getElementById('assign-ips-result');
        resultDiv.classList.remove('hidden');
        resultDiv.innerHTML = '<p class="text-blue-500">Processing...</p>';
        
        fetch('/bulk/assign_ips', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            let html = '<div class="space-y-2">';
            if (data.success.length > 0) {
                html += `<div class="text-green-600 dark:text-green-400"><strong>Successfully assigned ${data.success.length} IP(s):</strong><ul class="list-disc list-inside mt-2">`;
                data.success.forEach(item => {
                    html += `<li>${item.ip}</li>`;
                });
                html += '</ul></div>';
            }
            if (data.failed.length > 0) {
                html += `<div class="text-red-600 dark:text-red-400"><strong>Failed ${data.failed.length} assignment(s):</strong><ul class="list-disc list-inside mt-2">`;
                data.failed.forEach(item => {
                    const ipDisplay = item.ip ? ` (${item.ip})` : '';
                    html += `<li>IP ID ${item.ip_id}${ipDisplay}: ${item.reason}</li>`;
                });
                html += '</ul></div>';
            }
            html += '</div>';
            resultDiv.innerHTML = html;
            // Reload IP list if successful
            if (data.success.length > 0) {
                const subnetSelect = document.getElementById('bulk-subnet-select');
                if (subnetSelect.value) {
                    subnetSelect.dispatchEvent(new Event('change'));
                }
            }
        })
        .catch(error => {
            resultDiv.innerHTML = `<p class="text-red-600">Error: ${error.message}</p>`;
        });
    });
    
    // Bulk Device Creation
    document.getElementById('bulk-create-devices-form')?.addEventListener('submit', function(e) {
        e.preventDefault();
        const formData = new FormData(this);
        const resultDiv = document.getElementById('create-devices-result');
        resultDiv.classList.remove('hidden');
        resultDiv.innerHTML = '<p class="text-blue-500">Processing...</p>';
        
        fetch('/bulk/create_devices', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            let html = '<div class="space-y-2">';
            if (data.success.length > 0) {
                html += `<div class="text-green-600 dark:text-green-400"><strong>Successfully created ${data.success.length} device(s):</strong><ul class="list-disc list-inside mt-2">`;
                data.success.forEach(item => {
                    html += `<li>${item.name}</li>`;
                });
                html += '</ul></div>';
            }
            if (data.failed.length > 0) {
                html += `<div class="text-red-600 dark:text-red-400"><strong>Failed ${data.failed.length} creation(s):</strong><ul class="list-disc list-inside mt-2">`;
                data.failed.forEach(item => {
                    html += `<li>${item.name}: ${item.reason}</li>`;
                });
                html += '</ul></div>';
            }
            html += '</div>';
            resultDiv.innerHTML = html;
            if (data.success.length > 0) {
                setTimeout(() => window.location.reload(), 2000);
            }
        })
        .catch(error => {
            resultDiv.innerHTML = `<p class="text-red-600">Error: ${error.message}</p>`;
        });
    });
    
    // Bulk Tag Assignment
    document.getElementById('bulk-assign-tags-form')?.addEventListener('submit', function(e) {
        e.preventDefault();
        const formData = new FormData(this);
        const resultDiv = document.getElementById('assign-tags-result');
        resultDiv.classList.remove('hidden');
        resultDiv.innerHTML = '<p class="text-blue-500">Processing...</p>';
        
        fetch('/bulk/assign_tags', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            let html = '<div class="space-y-2">';
            if (data.success.length > 0) {
                html += `<div class="text-green-600 dark:text-green-400"><strong>Successfully assigned ${data.success.length} tag(s):</strong><ul class="list-disc list-inside mt-2">`;
                data.success.forEach(item => {
                    html += `<li>${item.device_name}: ${item.tag_name}</li>`;
                });
                html += '</ul></div>';
            }
            if (data.failed.length > 0) {
                html += `<div class="text-red-600 dark:text-red-400"><strong>Failed ${data.failed.length} assignment(s):</strong><ul class="list-disc list-inside mt-2">`;
                data.failed.forEach(item => {
                    html += `<li>Device ID ${item.device_id}, Tag ID ${item.tag_id}: ${item.reason}</li>`;
                });
                html += '</ul></div>';
            }
            html += '</div>';
            resultDiv.innerHTML = html;
        })
        .catch(error => {
            resultDiv.innerHTML = `<p class="text-red-600">Error: ${error.message}</p>`;
        });
    });
});

