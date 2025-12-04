// These variables are set inline in the template from server data
// permissions and rolePermissions are passed from the template

function showTab(tab) {
    document.getElementById('users-tab').classList.add('hidden');
    document.getElementById('roles-tab').classList.add('hidden');
    document.getElementById('tab-users').classList.remove('border-blue-500', 'text-blue-600', 'dark:text-blue-400');
    document.getElementById('tab-users').classList.add('border-transparent', 'text-gray-600', 'dark:text-gray-400');
    document.getElementById('tab-roles').classList.remove('border-blue-500', 'text-blue-600', 'dark:text-blue-400');
    document.getElementById('tab-roles').classList.add('border-transparent', 'text-gray-600', 'dark:text-gray-400');
    
    if (tab === 'users') {
        document.getElementById('users-tab').classList.remove('hidden');
        document.getElementById('tab-users').classList.remove('border-transparent', 'text-gray-600', 'dark:text-gray-400');
        document.getElementById('tab-users').classList.add('border-blue-500', 'text-blue-600', 'dark:text-blue-400');
    } else {
        document.getElementById('roles-tab').classList.remove('hidden');
        document.getElementById('tab-roles').classList.remove('border-transparent', 'text-gray-600', 'dark:text-gray-400');
        document.getElementById('tab-roles').classList.add('border-blue-500', 'text-blue-600', 'dark:text-blue-400');
    }
}

function editUser(userId, name, email, roleId, apiKey) {
    document.getElementById('edit-user-id').value = userId;
    document.getElementById('edit-user-name').value = name;
    document.getElementById('edit-user-email').value = email;
    document.getElementById('edit-user-password').value = '';
    document.getElementById('edit-user-role').value = (roleId === null || roleId === 'null') ? '' : roleId;
    document.getElementById('edit-user-api-key').textContent = apiKey || 'No API Key';
    document.getElementById('edit-user-modal').classList.remove('hidden');
}

function closeEditUserModal() {
    document.getElementById('edit-user-modal').classList.add('hidden');
}

function showAddRoleModal() {
    // Make sure edit modal is closed first
    document.getElementById('edit-role-modal').classList.add('hidden');
    // Clear any form data
    const addForm = document.querySelector('#add-role-modal form');
    if (addForm) {
        addForm.reset();
    }
    // Show add modal
    document.getElementById('add-role-modal').classList.remove('hidden');
}

function closeAddRoleModal() {
    document.getElementById('add-role-modal').classList.add('hidden');
}

function editRole(roleId, roleName, roleDescription) {
    // Make sure add modal is closed first
    document.getElementById('add-role-modal').classList.add('hidden');
    document.getElementById('edit-role-id').value = roleId;
    document.getElementById('edit-role-name').value = roleName;
    document.getElementById('edit-role-description').value = roleDescription || '';
    
    const permissionsDiv = document.getElementById('edit-role-permissions');
    permissionsDiv.innerHTML = '';
    
    const rolePerms = rolePermissions[roleId] || [];
    
    // Group permissions by merged categories
    const viewPerms = permissions.filter(p => p[3] === 'View');
    const devicePerms = permissions.filter(p => p[3] === 'Device');
    const deviceTypePerms = permissions.filter(p => p[3] === 'Device Type');
    const subnetPerms = permissions.filter(p => p[3] === 'Subnet');
    const dhcpPerms = permissions.filter(p => p[3] === 'DHCP');
    const rackPerms = permissions.filter(p => p[3] === 'Rack');
    const adminPerms = permissions.filter(p => p[3] === 'Admin');
    
    let html = '';
    
    // View Permissions
    html += '                        <!-- View Permissions -->\n';
    html += '                        <div class="col-span-full">\n';
    html += '                            <h4 class="font-semibold text-base mb-2 border-b border-gray-500 pb-1">View Permissions</h4>\n';
    html += '                            <div class="grid grid-cols-1 md:grid-cols-2 gap-2">\n';
    viewPerms.forEach(perm => {
        const checked = rolePerms.includes(perm[0]) ? 'checked' : '';
        html += `                            <label class="flex items-center mb-2 cursor-pointer hover:bg-gray-200 dark:hover:bg-zinc-800 p-2 rounded">
                                <input type="checkbox" name="permissions" value="${perm[0]}" ${checked} class="mr-2">
                                <span class="text-sm">${perm[2]}</span>
                            </label>\n`;
    });
    html += '                            </div>\n';
    html += '                        </div>\n';
    html += '                        \n';
    
    // Device Management
    html += '                        <!-- Device Management -->\n';
    html += '                        <div>\n';
    html += '                            <h4 class="font-semibold text-base mb-2 border-b border-gray-500 pb-1">Device Management</h4>\n';
    devicePerms.forEach(perm => {
        const checked = rolePerms.includes(perm[0]) ? 'checked' : '';
        html += `                            <label class="flex items-center mb-2 cursor-pointer hover:bg-gray-200 dark:hover:bg-zinc-800 p-2 rounded">
                                <input type="checkbox" name="permissions" value="${perm[0]}" ${checked} class="mr-2">
                                <span class="text-sm">${perm[2]}</span>
                            </label>\n`;
    });
    deviceTypePerms.forEach(perm => {
        const checked = rolePerms.includes(perm[0]) ? 'checked' : '';
        html += `                            <label class="flex items-center mb-2 cursor-pointer hover:bg-gray-200 dark:hover:bg-zinc-800 p-2 rounded">
                                <input type="checkbox" name="permissions" value="${perm[0]}" ${checked} class="mr-2">
                                <span class="text-sm">${perm[2]}</span>
                            </label>\n`;
    });
    html += '                        </div>\n';
    html += '                        \n';
    
    // Network Management
    html += '                        <!-- Network Management -->\n';
    html += '                        <div>\n';
    html += '                            <h4 class="font-semibold text-base mb-2 border-b border-gray-500 pb-1">Network Management</h4>\n';
    subnetPerms.forEach(perm => {
        const checked = rolePerms.includes(perm[0]) ? 'checked' : '';
        html += `                            <label class="flex items-center mb-2 cursor-pointer hover:bg-gray-200 dark:hover:bg-zinc-800 p-2 rounded">
                                <input type="checkbox" name="permissions" value="${perm[0]}" ${checked} class="mr-2">
                                <span class="text-sm">${perm[2]}</span>
                            </label>\n`;
    });
    dhcpPerms.forEach(perm => {
        const checked = rolePerms.includes(perm[0]) ? 'checked' : '';
        html += `                            <label class="flex items-center mb-2 cursor-pointer hover:bg-gray-200 dark:hover:bg-zinc-800 p-2 rounded">
                                <input type="checkbox" name="permissions" value="${perm[0]}" ${checked} class="mr-2">
                                <span class="text-sm">${perm[2]}</span>
                            </label>\n`;
    });
    html += '                        </div>\n';
    html += '                        \n';
    
    // Rack Management
    html += '                        <!-- Rack Management -->\n';
    html += '                        <div>\n';
    html += '                            <h4 class="font-semibold text-base mb-2 border-b border-gray-500 pb-1">Rack Management</h4>\n';
    rackPerms.forEach(perm => {
        const checked = rolePerms.includes(perm[0]) ? 'checked' : '';
        html += `                            <label class="flex items-center mb-2 cursor-pointer hover:bg-gray-200 dark:hover:bg-zinc-800 p-2 rounded">
                                <input type="checkbox" name="permissions" value="${perm[0]}" ${checked} class="mr-2">
                                <span class="text-sm">${perm[2]}</span>
                            </label>\n`;
    });
    html += '                        </div>\n';
    html += '                        \n';
    
    // Admin
    html += '                        <!-- Admin -->\n';
    html += '                        <div>\n';
    html += '                            <h4 class="font-semibold text-base mb-2 border-b border-gray-500 pb-1">Administration</h4>\n';
    adminPerms.forEach(perm => {
        const checked = rolePerms.includes(perm[0]) ? 'checked' : '';
        html += `                            <label class="flex items-center mb-2 cursor-pointer hover:bg-gray-200 dark:hover:bg-zinc-800 p-2 rounded">
                                <input type="checkbox" name="permissions" value="${perm[0]}" ${checked} class="mr-2">
                                <span class="text-sm">${perm[2]}</span>
                            </label>\n`;
    });
    html += '                        </div>\n';
    
    permissionsDiv.innerHTML = html;
    
    document.getElementById('edit-role-modal').classList.remove('hidden');
}

function closeEditRoleModal() {
    document.getElementById('edit-role-modal').classList.add('hidden');
}

function deleteRole(roleId, roleName) {
    if (confirm(`Are you sure you want to delete the role "${roleName}"?`)) {
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = '/users';
        form.innerHTML = `
            <input type="hidden" name="action" value="delete_role">
            <input type="hidden" name="role_id" value="${roleId}">
        `;
        document.body.appendChild(form);
        form.submit();
    }
}

// Close modals when clicking outside
window.onclick = function(event) {
    const editUserModal = document.getElementById('edit-user-modal');
    const editRoleModal = document.getElementById('edit-role-modal');
    const addRoleModal = document.getElementById('add-role-modal');
    if (event.target === editUserModal) {
        closeEditUserModal();
    }
    if (event.target === editRoleModal) {
        closeEditRoleModal();
    }
    if (event.target === addRoleModal) {
        closeAddRoleModal();
    }
}

