document.addEventListener('DOMContentLoaded', function() {
    const messageDiv = document.getElementById('message');
    
    function showMessage(text, isError = false) {
        messageDiv.textContent = text;
        messageDiv.className = isError 
            ? 'mb-4 p-4 rounded-lg bg-red-200 dark:bg-red-800 text-red-800 dark:text-red-200'
            : 'mb-4 p-4 rounded-lg bg-green-200 dark:bg-green-800 text-green-800 dark:text-green-200';
        messageDiv.classList.remove('hidden');
        setTimeout(() => {
            messageDiv.classList.add('hidden');
        }, 5000);
    }
    
    // Create backup button
    const createBackupBtn = document.getElementById('create-backup-btn');
    if (createBackupBtn) {
        createBackupBtn.addEventListener('click', function() {
            createBackupBtn.disabled = true;
            createBackupBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Creating...';
            
            fetch('/backup/create', {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showMessage(`Backup created successfully: ${data.filename}`);
                    setTimeout(() => window.location.reload(), 1500);
                } else {
                    showMessage(data.error || 'Failed to create backup', true);
                    createBackupBtn.disabled = false;
                    createBackupBtn.innerHTML = '<i class="fas fa-database"></i> <span>Create Backup</span>';
                }
            })
            .catch(error => {
                showMessage('Error creating backup: ' + error.message, true);
                createBackupBtn.disabled = false;
                createBackupBtn.innerHTML = '<i class="fas fa-database"></i> <span>Create Backup</span>';
            });
        });
    }
    
    // Upload and restore form
    const uploadRestoreForm = document.getElementById('upload-restore-form');
    if (uploadRestoreForm) {
        uploadRestoreForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            if (!confirm('WARNING: This will replace all current database data with the backup. Are you sure you want to continue?')) {
                return;
            }
            
            const formData = new FormData(this);
            const submitBtn = this.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerHTML;
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Restoring...';
            
            fetch('/backup/restore', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showMessage('Database restored successfully. Page will reload...');
                    setTimeout(() => window.location.reload(), 2000);
                } else {
                    showMessage(data.error || 'Failed to restore backup', true);
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = originalText;
                }
            })
            .catch(error => {
                showMessage('Error restoring backup: ' + error.message, true);
                submitBtn.disabled = false;
                submitBtn.innerHTML = originalText;
            });
        });
    }
    
    // Existing backup restore form
    const existingRestoreForm = document.getElementById('existing-restore-form');
    if (existingRestoreForm) {
        existingRestoreForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            if (!confirm('WARNING: This will replace all current database data with the backup. Are you sure you want to continue?')) {
                return;
            }
            
            const formData = new FormData(this);
            const submitBtn = this.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerHTML;
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Restoring...';
            
            fetch('/backup/restore', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showMessage('Database restored successfully. Page will reload...');
                    setTimeout(() => window.location.reload(), 2000);
                } else {
                    showMessage(data.error || 'Failed to restore backup', true);
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = originalText;
                }
            })
            .catch(error => {
                showMessage('Error restoring backup: ' + error.message, true);
                submitBtn.disabled = false;
                submitBtn.innerHTML = originalText;
            });
        });
    }
});

function deleteBackup(filename) {
    if (!confirm(`Are you sure you want to delete backup "${filename}"?`)) {
        return;
    }
    
    fetch(`/backup/delete/${filename}`, {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            window.location.reload();
        } else {
            alert('Error: ' + (data.error || 'Failed to delete backup'));
        }
    })
    .catch(error => {
        alert('Error: ' + error.message);
    });
}

