export function updateScanStatus(message, isError = false) {
    const scanStatus = document.querySelector('.scan-status');
    const statusIndicator = document.querySelector('.status-indicator');
    const scannerStatus = document.getElementById('scanner-status');
    
    if (scanStatus) {
        scanStatus.textContent = message;
        scanStatus.style.display = 'block';
        
        if (isError) {
            scanStatus.classList.add('error');
            statusIndicator?.classList.replace('status-active', 'status-error');
            scannerStatus.textContent = 'Scanner Status: Error';
        } else {
            scanStatus.classList.remove('error');
            statusIndicator?.classList.replace('status-error', 'status-active');
            scannerStatus.textContent = 'Scanner Status: Ready';
        }
    }
    
    console.log(`Scan status: ${message}`);
}
  
async function pollScanStatus(scanId) {
    const maxAttempts = 180;
    let attempts = 0;
    let lastProgress = 0;

    while (attempts < maxAttempts) {
        try {
            const response = await fetch(`/api/scan/${scanId}/status`);
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            
            const statusData = await response.json();
            console.log('Poll response:', statusData);

            if (statusData.status === 'completed') {
                const resultsResponse = await fetch(`/api/scan/${scanId}/results`);
                if (!resultsResponse.ok) throw new Error('Failed to fetch results');
                
                const results = await resultsResponse.json();
                updateScanStatus(`Scan complete! Found ${results.summary.total_hosts} hosts, ${results.summary.active_hosts} active.`);
                updateMetricsPanel(results);
                displayResults(results);
                await updateTopologyVisualization(scanId);
                await updatePortAnalysis(scanId);
                return;
            } else if (statusData.status === 'failed') {
                throw new Error(statusData.error || 'Scan failed');
            } else {
                const progress = statusData.progress || lastProgress;
                lastProgress = progress;
                updateScanStatus(`Scanning... ${progress}% complete. This may take several minutes.`);
            }

            const pollInterval = Math.min(5000 + (attempts * 100), 10000);
            await new Promise(resolve => setTimeout(resolve, pollInterval));
            attempts++;
        } catch (error) {
            console.error('Polling error:', error);
            throw error;
        }
    }
    
    throw new Error('Scan timed out. The network might be too large or unresponsive.');
}
  
export async function startScan() {
    const networkSelect = document.getElementById('network-select');
    const customInput = document.getElementById('custom-network-input');
    const scanTypeSelect = document.getElementById('scan-type-select');
    const scanButton = document.getElementById('scan-button');
    
    let target;
    if (networkSelect.value === 'custom' && customInput) {
        target = customInput.value.trim();
    } else {
        target = networkSelect.value;
    }
    
    const scanType = scanTypeSelect.value;
    
    if (!target) {
        alert('Please select a network/subnet to scan');
        return;
    }

    try {
        scanButton.disabled = true;
        scanButton.innerHTML = 'Scanning... <div class="loading"></div>';
        document.getElementById('stop-button').style.display = 'block';
        updateScanStatus(`Initializing ${scanType} scan of ${target}. This may take several minutes...`);
        
        console.log(`Starting ${scanType} of ${target}`);

        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                subnet: target,
                scan_type: scanType
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        console.log('Scan response:', data);

        if (data.status === 'started' && data.scan_id) {
            updateScanStatus(`Scan started with ID: ${data.scan_id}. This may take several minutes depending on the network size...`);
            await pollScanStatus(data.scan_id);
        } else if (data.summary) {
            updateScanStatus(`${scanType} complete! Found ${data.summary.total_hosts} hosts, ${data.summary.active_hosts} active.`);
            updateMetricsPanel(data);
            displayResults(data);
            await updateTopologyVisualization(data.scan_id);
            await updatePortAnalysis(data.scan_id);
        } else {
            throw new Error('Invalid response format from server');
        }

    } catch (error) {
        console.error('Scan failed:', error);
        updateScanStatus(`Scan failed: ${error.message}. Try reducing the scan scope or using a quick scan.`, true);
    } finally {
        scanButton.disabled = false;
        scanButton.textContent = 'Start Network Scan';
        document.getElementById('stop-button').style.display = 'none';
    }
}

export function updateMetricsPanel(data) {
    document.getElementById('total-nodes').textContent = data.summary.total_hosts;
    document.getElementById('active-hosts').textContent = data.summary.active_hosts;
    document.getElementById('open-ports').textContent = data.summary.total_ports;
    document.getElementById('vulnerabilities').textContent = data.summary.total_vulnerabilities;
    document.getElementById('last-scan').textContent = new Date().toLocaleTimeString();
}

export function displayResults(data) {
    const resultsPanel = document.getElementById('results-panel');
    resultsPanel.style.display = 'block';
    resultsPanel.dataset.scanId = data.scan_id;

    let summaryHtml = `
        <h3>Scan Summary</h3>
        <table class="results-table">
            <tr>
                <th>Total Hosts</th>
                <td>${data.summary.total_hosts}</td>
            </tr>
            <tr>
                <th>Active Hosts</th>
                <td>${data.summary.active_hosts}</td>
            </tr>
            <tr>
                <th>Total Ports</th>
                <td>${data.summary.total_ports}</td>
            </tr>
            <tr>
                <th>Services Detected</th>
                <td>${data.summary.total_services}</td>
            </tr>
            <tr>
                <th>Vulnerabilities Found</th>
                <td>${data.summary.total_vulnerabilities}</td>
            </tr>
        </table>`;

    resultsPanel.innerHTML = summaryHtml;
}

// Export all functions that need to be called from HTML
export async function loadNetworks() {
    const networkSelect = document.getElementById('network-select');
    try {
        networkSelect.disabled = true;
        console.log('Starting network discovery...');
        
        const response = await fetch('/api/networks');
        console.log('Response received:', response);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        console.log('Network data received:', data);
        
        // Clear and set default option
        networkSelect.innerHTML = '<option value="">Select Network/Subnet</option>';
        
        // Check if data.networks exists and is an array before processing
        if (data && data.networks && Array.isArray(data.networks)) {
            console.log(`Processing ${data.networks.length} networks`);
            
            // Add each network to the select
            data.networks.forEach(network => {
                if (!network || typeof network !== 'object') {
                    console.warn('Invalid network object:', network);
                    return;
                }
                
                console.log('Adding network:', network);
                const option = document.createElement('option');
                
                if (network.network === 'custom') {
                    option.value = 'custom';
                    option.textContent = 'Enter Custom Network/IP';
                } else {
                    option.value = network.network || '';
                    option.textContent = network.interface ? 
                        `${network.network} (${network.interface})` : 
                        network.network;
                    option.dataset.interface = network.interface || '';
                    option.dataset.ip = network.ip || '';
                }
                networkSelect.appendChild(option);
            });
        } else {
            console.warn('Invalid or empty networks data:', data);
            throw new Error('No valid networks data received');
        }

    } catch (error) {
        console.error('Error in loadNetworks:', error);
        networkSelect.innerHTML = `
            <option value="">Error loading networks - ${error.message}</option>
            <option value="custom">Enter Custom Network/IP</option>
        `;
        updateScanStatus('Error loading networks: ' + error.message, true);
    } finally {
        networkSelect.disabled = false;
        console.log('Network loading process completed');
    }
}

// Initialize everything when the module loads
(async function() {
    try {
        console.log('Starting initialization...');
        
        // Wait for DOM to be ready
        await new Promise(resolve => {
            if (document.readyState !== 'loading') {
                console.log('DOM already ready');
                resolve();
            } else {
                console.log('Waiting for DOM...');
                document.addEventListener('DOMContentLoaded', () => {
                    console.log('DOM loaded');
                    resolve();
                });
            }
        });

        console.log('DOM ready, loading networks...');
        await loadNetworks();
        console.log('Networks loaded');

    } catch (error) {
        console.error('Initialization error:', error);
        updateScanStatus('Error during initialization: ' + error.message, true);
    }
})();

// Make functions available globally
window.startScan = startScan;
window.updateScanStatus = updateScanStatus;
window.pollScanStatus = pollScanStatus;
window.updateMetricsPanel = updateMetricsPanel;
window.displayResults = displayResults;
window.loadNetworks = loadNetworks;

// Add this function to app.js
export async function stopScan() {
    try {
        const stopButton = document.getElementById('stop-button');
        const scanButton = document.getElementById('scan-button');
        
        stopButton.disabled = true;
        updateScanStatus('Stopping scan...');
        
        const response = await fetch('/api/scan/stop', {
            method: 'POST'
        });
        
        if (!response.ok) {
            throw new Error('Failed to stop scan');
        }
        
        const data = await response.json();
        updateScanStatus('Scan stopped by user');
        
        // Reset buttons
        stopButton.style.display = 'none';
        scanButton.disabled = false;
        scanButton.textContent = 'Start Network Scan';
        
    } catch (error) {
        console.error('Error stopping scan:', error);
        updateScanStatus(`Failed to stop scan: ${error.message}`, true);
    }
}

// Add to global exports
window.stopScan = stopScan;
  