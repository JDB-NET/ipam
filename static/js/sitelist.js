document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.site-header').forEach(header => {
        header.addEventListener('click', function(e) {
            if (e.target.closest('button')) return;
            const subnetList = this.closest('.site-group').querySelector('.subnet-list');
            const icon = this.querySelector('.expand-btn i');
            if (subnetList.classList.contains('hidden')) {
                subnetList.classList.remove('hidden');
                icon.classList.remove('fa-chevron-down');
                icon.classList.add('fa-chevron-up');
            } else {
                subnetList.classList.add('hidden');
                icon.classList.remove('fa-chevron-up');
                icon.classList.add('fa-chevron-down');
            }
        });
    });
    document.querySelectorAll('.expand-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const subnetList = this.closest('.site-group').querySelector('.subnet-list');
            const icon = this.querySelector('i');
            if (subnetList.classList.contains('hidden')) {
                subnetList.classList.remove('hidden');
                icon.classList.remove('fa-chevron-down');
                icon.classList.add('fa-chevron-up');
            } else {
                subnetList.classList.add('hidden');
                icon.classList.remove('fa-chevron-up');
                icon.classList.add('fa-chevron-down');
            }
        });
    });
});