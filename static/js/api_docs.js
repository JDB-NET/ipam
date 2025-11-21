// API Documentation Interactive Functions

function getApiKey() {
    return document.getElementById('apiKey').value;
}

function showStatus(message, isError = false) {
    const status = document.getElementById('connectionStatus');
    status.textContent = message;
    status.className = `mt-2 text-sm ${isError ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'}`;
}

async function testConnection() {
    const apiKey = getApiKey();
    if (!apiKey) {
        showStatus('Please enter your API key', true);
        return;
    }

    try {
        const response = await axios.get('/api/v1/devices', {
            headers: { 'X-API-Key': apiKey }
        });
        showStatus('✓ Connection successful');
    } catch (error) {
        if (error.response?.status === 401) {
            showStatus('✗ Invalid API key', true);
        } else if (error.response?.status === 403) {
            showStatus('✗ Insufficient permissions', true);
        } else {
            showStatus('✗ Connection failed', true);
        }
    }
}

async function tryEndpoint(method, url, data, responseId) {
    const apiKey = getApiKey();
    if (!apiKey) {
        showStatus('Please enter your API key first', true);
        return;
    }

    try {
        const config = {
            method: method,
            url: url,
            headers: { 'X-API-Key': apiKey }
        };
        
        if (data) {
            config.data = data;
        }

        const response = await axios(config);
        document.getElementById(responseId + '-response').classList.remove('hidden');
        document.getElementById(responseId).textContent = JSON.stringify(response.data, null, 2);
    } catch (error) {
        document.getElementById(responseId + '-response').classList.remove('hidden');
        const errorMessage = error.response?.data?.error || error.message;
        document.getElementById(responseId).textContent = `Error (${error.response?.status || 'Network'}): ${errorMessage}`;
    }
}

async function tryEndpointWithId(method, baseUrl, inputId, responseId) {
    const id = document.getElementById(inputId).value;
    if (!id) {
        alert('Please enter an ID');
        return;
    }
    await tryEndpoint(method, baseUrl + encodeURIComponent(id), null, responseId);
}

// Auto-populate API key if user is logged in
document.addEventListener('DOMContentLoaded', function() {
    const apiKeyInput = document.getElementById('apiKey');
    if (apiKeyInput && apiKeyInput.value) {
        testConnection();
    }
});