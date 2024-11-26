import { refreshTopology } from './topology.js';

export async function loadNetworks() {
    try {
        const networkSelect = document.getElementById('network-select');
        if (!networkSelect) {
            console.error('Network select element not found');
            return;
        }

        // Show loading state
        networkSelect.innerHTML = '<option value="">Loading networks...</option>';
        networkSelect.disabled = true;

        const response = await fetch('/api/networks');
        const data = await response.json();
        
        // Clear loading state
        networkSelect.innerHTML = '';
        networkSelect.disabled = false;
        
        if (data.status === 'success' && Array.isArray(data.networks)) {
            // Add default option
            const defaultOption = document.createElement('option');
            defaultOption.value = '';
            defaultOption.textContent = 'Select a network';
            networkSelect.appendChild(defaultOption);
            
            // Add network options
            data.networks.forEach(network => {
                const option = document.createElement('option');
                option.value = network.network;
                option.textContent = network.name;
                if (network.description) {
                    option.title = network.description;
                }
                networkSelect.appendChild(option);
            });
        } else {
            console.error('Failed to load networks:', data.message);
            networkSelect.innerHTML = '<option value="">Error loading networks</option>';
        }
    } catch (error) {
        console.error('Error loading networks:', error);
        const networkSelect = document.getElementById('network-select');
        if (networkSelect) {
            networkSelect.innerHTML = '<option value="">Error loading networks</option>';
            networkSelect.disabled = false;
        }
    }
}

export async function startScan() {
    try {
        const networkSelect = document.getElementById('network-select');
        const scanTypeSelect = document.getElementById('scan-type-select');
        const subnet = networkSelect.value;
        const scanType = scanTypeSelect.value;

        if (!subnet) {
            alert('Please select a network');
            return;
        }

        // Disable scan button and show loading state
        const scanButton = document.getElementById('scan-button');
        const stopButton = document.getElementById('stop-button');
        if (scanButton) {
            scanButton.disabled = true;
            scanButton.textContent = 'Starting scan...';
        }

        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                subnet: subnet,
                scan_type: scanType
            })
        });

        const data = await response.json();
        if (data.scan_id) {
            // Hide scan button, show stop button
            if (scanButton) scanButton.style.display = 'none';
            if (stopButton) stopButton.style.display = 'inline-block';
            
            // Start polling for scan status
            updateScanStatus(data.scan_id);
        } else {
            alert('Failed to start scan: ' + (data.message || 'Unknown error'));
            if (scanButton) {
                scanButton.disabled = false;
                scanButton.textContent = 'Start Scan';
            }
        }
    } catch (error) {
        console.error('Error starting scan:', error);
        alert('Error starting scan');
        const scanButton = document.getElementById('scan-button');
        if (scanButton) {
            scanButton.disabled = false;
            scanButton.textContent = 'Start Scan';
        }
    }
}

export async function stopScan() {
    try {
        const response = await fetch('/api/scan/stop', {
            method: 'POST'
        });
        const data = await response.json();
        
        if (data.status === 'success') {
            const scanButton = document.getElementById('scan-button');
            const stopButton = document.getElementById('stop-button');
            if (scanButton) scanButton.style.display = 'inline-block';
            if (stopButton) stopButton.style.display = 'none';
        } else {
            alert('Failed to stop scan: ' + (data.message || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error stopping scan:', error);
        alert('Error stopping scan');
    }
}

async function updateScanStatus(scanId) {
    try {
        const response = await fetch(`/api/scan/${scanId}/status`);
        const data = await response.json();
        
        const statusElement = document.querySelector('.scan-status');
        if (statusElement) {
            statusElement.style.display = 'block';
            statusElement.textContent = `Scan Status: ${data.status} (${data.progress || 0}%)`;
        }
        
        if (data.status === 'completed') {
            const scanButton = document.getElementById('scan-button');
            const stopButton = document.getElementById('stop-button');
            if (scanButton) scanButton.style.display = 'inline-block';
            if (stopButton) stopButton.style.display = 'none';
            
            // Update metrics
            if (data.summary) {
                document.getElementById('total-nodes').textContent = data.summary.total_hosts || 0;
                document.getElementById('active-hosts').textContent = data.summary.active_hosts || 0;
                document.getElementById('open-ports').textContent = data.summary.total_ports || 0;
                document.getElementById('vulnerabilities').textContent = data.summary.total_vulnerabilities || 0;
                document.getElementById('last-scan').textContent = new Date().toLocaleString();
            }
            
            // Get and display detailed scan results
            const resultsResponse = await fetch(`/api/scan/${scanId}/results`);
            const scanResults = await resultsResponse.json();
            updateHostDetails(scanResults);
            
            // Refresh topology visualization
            refreshTopology(scanId);
            
        } else if (data.status === 'failed') {
            const scanButton = document.getElementById('scan-button');
            const stopButton = document.getElementById('stop-button');
            if (scanButton) scanButton.style.display = 'inline-block';
            if (stopButton) stopButton.style.display = 'none';
            if (statusElement) statusElement.style.color = '#dc3545';  // Red color for error
        } else if (data.status === 'running') {
            // Continue polling for updates
            setTimeout(() => updateScanStatus(scanId), 2000);
        }
    } catch (error) {
        console.error('Error updating scan status:', error);
    }
}

function updateHostDetails(scanResults) {
    const tbody = document.getElementById('host-details-body');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    
    scanResults.hosts.forEach(host => {
        const row = document.createElement('tr');
        
        // IP Address
        const ipCell = document.createElement('td');
        ipCell.textContent = host.ip_address;
        row.appendChild(ipCell);
        
        // Hostname
        const hostnameCell = document.createElement('td');
        const hostname = host.hostnames?.find(h => h.name)?.name || 'N/A';
        hostnameCell.textContent = hostname;
        row.appendChild(hostnameCell);
        
        // Open Ports
        const portsCell = document.createElement('td');
        const openPorts = host.ports?.filter(p => p.state === 'open') || [];
        if (openPorts.length > 0) {
            openPorts.forEach((port, index) => {
                const portSpan = document.createElement('span');
                portSpan.className = 'port-number';
                portSpan.textContent = port.port;
                portsCell.appendChild(portSpan);
                if (index < openPorts.length - 1) {
                    portsCell.appendChild(document.createTextNode(', '));
                }
            });
        } else {
            portsCell.textContent = 'None';
        }
        row.appendChild(portsCell);
        
        // Services
        const servicesCell = document.createElement('td');
        const services = openPorts.map(p => {
            const serviceDiv = document.createElement('div');
            serviceDiv.className = 'service-info';
            let serviceInfo = `${p.port}/${p.protocol}: ${p.service}`;
            if (p.product) {
                serviceInfo += ` (${p.product}`;
                if (p.version) serviceInfo += ` ${p.version}`;
                if (p.extra_info) serviceInfo += ` - ${p.extra_info}`;
                serviceInfo += ')';
            }
            serviceDiv.textContent = serviceInfo;
            return serviceDiv.outerHTML;
        });
        servicesCell.innerHTML = services.join('') || 'None';
        row.appendChild(servicesCell);
        
        // OS Info
        const osCell = document.createElement('td');
        const osInfo = host.os_info || {};
        if (osInfo.os_match && osInfo.os_match !== 'unknown') {
            osCell.textContent = `${osInfo.os_match} (${osInfo.os_accuracy}% accuracy)`;
        } else if (osInfo.os_vendor && osInfo.os_vendor !== 'unknown') {
            osCell.textContent = `${osInfo.os_vendor} ${osInfo.os_family || ''} ${osInfo.os_generation || ''}`.trim();
        } else {
            osCell.textContent = 'Unknown';
        }
        row.appendChild(osCell);
        
        tbody.appendChild(row);
    });
}

// Initialize when the page loads
document.addEventListener('DOMContentLoaded', () => {
    loadNetworks();
    
    // Add event listeners for scan buttons
    const scanButton = document.getElementById('scan-button');
    const stopButton = document.getElementById('stop-button');
    
    if (scanButton) {
        scanButton.addEventListener('click', startScan);
    }
    
    if (stopButton) {
        stopButton.addEventListener('click', stopScan);
    }
});
  