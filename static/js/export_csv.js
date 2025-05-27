document.querySelectorAll('.export-csv-btn').forEach(btn => {
    btn.addEventListener('click', function(e) {
        e.stopPropagation();
        const subnetId = this.getAttribute('data-subnet-id');
        window.location.href = `/subnet/${subnetId}/export_csv`;
    });
});