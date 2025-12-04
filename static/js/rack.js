document.addEventListener('DOMContentLoaded', function() {
    // Export CSV button
    const exportBtn = document.getElementById('export-csv');
    if (exportBtn) {
        exportBtn.addEventListener('click', function() {
            const rackId = exportBtn.getAttribute('data-rack-id');
            if (rackId) {
                window.location = '/rack/' + rackId + '/export_csv';
            }
        });
    }
    
    // Form toggle functionality
    function showBothAddButtons() {
        document.getElementById('show-add-device-form').classList.remove('hidden');
        document.getElementById('show-nonnet-form').classList.remove('hidden');
    }
    
    showBothAddButtons();
    
    document.getElementById('show-nonnet-form').onclick = function() {
        document.getElementById('nonnet-form').classList.remove('hidden');
        this.classList.add('hidden');
    };
    
    document.getElementById('hide-nonnet-form').onclick = function() {
        document.getElementById('nonnet-form').classList.add('hidden');
        showBothAddButtons();
    };
    
    document.getElementById('show-add-device-form').onclick = function() {
        document.getElementById('add-device-form').classList.remove('hidden');
        this.classList.add('hidden');
    };
    
    document.getElementById('hide-add-device-form').onclick = function() {
        document.getElementById('add-device-form').classList.add('hidden');
        showBothAddButtons();
    };
});

