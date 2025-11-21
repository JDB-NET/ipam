// Tag Management JavaScript

function showAddTagModal() {
    document.getElementById('add-tag-modal').classList.remove('hidden');
    document.getElementById('add-tag-name').value = '';
    document.getElementById('add-tag-color').value = '#6B7280';
    document.getElementById('add-tag-description').value = '';
    updateColorPreview('add');
}

function closeAddTagModal() {
    document.getElementById('add-tag-modal').classList.add('hidden');
}

function editTag(tagId, name, color, description) {
    document.getElementById('edit-tag-id').value = tagId;
    document.getElementById('edit-tag-name').value = name;
    document.getElementById('edit-tag-color').value = color;
    document.getElementById('edit-tag-description').value = description || '';
    updateColorPreview('edit');
    document.getElementById('edit-tag-modal').classList.remove('hidden');
}

function closeEditTagModal() {
    document.getElementById('edit-tag-modal').classList.add('hidden');
}

function updateColorPreview(mode) {
    const colorInput = document.getElementById(`${mode}-tag-color`);
    const preview = document.getElementById(`${mode}-color-preview`);
    preview.textContent = colorInput.value.toUpperCase();
}

// Event listeners
document.addEventListener('DOMContentLoaded', function() {
    const addColorInput = document.getElementById('add-tag-color');
    const editColorInput = document.getElementById('edit-tag-color');
    
    if (addColorInput) {
        addColorInput.addEventListener('input', () => updateColorPreview('add'));
    }
    
    if (editColorInput) {
        editColorInput.addEventListener('input', () => updateColorPreview('edit'));
    }
    
    // Handle edit tag button clicks
    document.querySelectorAll('.edit-tag-btn').forEach(button => {
        button.addEventListener('click', function() {
            const tagId = this.dataset.tagId;
            const tagName = this.dataset.tagName;
            const tagColor = this.dataset.tagColor;
            const tagDescription = this.dataset.tagDescription;
            editTag(tagId, tagName, tagColor, tagDescription);
        });
    });
});

// Close modals when clicking outside
window.onclick = function(event) {
    const addModal = document.getElementById('add-tag-modal');
    const editModal = document.getElementById('edit-tag-modal');
    if (event.target === addModal) {
        closeAddTagModal();
    }
    if (event.target === editModal) {
        closeEditTagModal();
    }
}