import { refreshTopology } from './topology.js';

// Function to update host details table
function updateHostDetails(scanData) {
    const tbody = document.getElementById('host-details-body');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    
    scanData.hosts.forEach(host => {
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
            const portsList = document.createElement('ul');
            portsList.style.listStyle = 'none';
            portsList.style.padding = '0';
            openPorts.forEach(port => {
                const portItem = document.createElement('li');
                portItem.textContent = `${port.port}/${port.protocol || 'tcp'}`;
                portsList.appendChild(portItem);
            });
            portsCell.appendChild(portsList);
        } else {
            portsCell.textContent = 'None';
        }
        row.appendChild(portsCell);
        
        // Services
        const servicesCell = document.createElement('td');
        if (openPorts.length > 0) {
            const servicesList = document.createElement('ul');
            servicesList.style.listStyle = 'none';
            servicesList.style.padding = '0';
            openPorts.forEach(port => {
                const serviceItem = document.createElement('li');
                let serviceInfo = port.service || 'unknown';
                if (port.service_details) {
                    serviceInfo += ` (${port.service_details})`;
                }
                serviceItem.textContent = serviceInfo;
                servicesList.appendChild(serviceItem);
            });
            servicesCell.appendChild(servicesList);
        } else {
            servicesCell.textContent = 'None';
        }
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

// Function to update network metrics
function updateNetworkMetrics(scanData) {
    // Update basic metrics
    document.getElementById('total-hosts').textContent = scanData.summary?.total_hosts || '-';
    document.getElementById('active-hosts').textContent = scanData.summary?.active_hosts || '-';
    document.getElementById('total-ports').textContent = scanData.summary?.total_ports || '-';
    document.getElementById('total-services').textContent = scanData.summary?.total_services || '-';
    document.getElementById('total-vulnerabilities').textContent = scanData.summary?.total_vulnerabilities || '-';
    
    // Update host details table
    updateHostDetails(scanData);
}

// Function to update port analysis metrics
async function updatePortAnalysis(scanId) {
    try {
        const response = await fetch(`/api/analysis/ports/${scanId}`);
        const data = await response.json();
        
        if (response.ok) {
            // Update port metrics
            document.getElementById('open-ports-count').textContent = data.total_open_ports || '-';
            document.getElementById('high-risk-services').textContent = data.interesting_ports?.high_risk?.length || '-';
            document.getElementById('remote-access-services').textContent = data.interesting_ports?.remote_access?.length || '-';
            document.getElementById('web-services').textContent = data.interesting_ports?.web_services?.length || '-';
            
            // Update port charts
            updatePortCharts(data);
        } else {
            console.error('Failed to fetch port analysis:', data.error);
        }
    } catch (error) {
        console.error('Error updating port analysis:', error);
    }
}

// Function to update port charts
function updatePortCharts(portData) {
    // Update common ports chart
    const commonPortsCtx = document.getElementById('commonPortsChart')?.getContext('2d');
    if (commonPortsCtx && portData.most_common_ports) {
        new Chart(commonPortsCtx, {
            type: 'bar',
            data: {
                labels: portData.most_common_ports.map(p => `Port ${p[0]}`),
                datasets: [{
                    label: 'Number of Hosts',
                    data: portData.most_common_ports.map(p => p[1]),
                    backgroundColor: 'rgba(54, 162, 235, 0.5)',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { color: '#ffffff' }
                    },
                    x: {
                        ticks: { color: '#ffffff' }
                    }
                },
                plugins: {
                    legend: {
                        labels: { color: '#ffffff' }
                    },
                    title: {
                        display: true,
                        text: 'Most Common Open Ports',
                        color: '#ffffff'
                    }
                }
            }
        });
    }

    // Update services chart
    const servicesCtx = document.getElementById('servicesChart')?.getContext('2d');
    if (servicesCtx && portData.most_common_services) {
        new Chart(servicesCtx, {
            type: 'bar',
            data: {
                labels: portData.most_common_services.map(s => s[0]),
                datasets: [{
                    label: 'Number of Instances',
                    data: portData.most_common_services.map(s => s[1]),
                    backgroundColor: 'rgba(75, 192, 192, 0.5)',
                    borderColor: 'rgba(75, 192, 192, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { color: '#ffffff' }
                    },
                    x: {
                        ticks: { color: '#ffffff' }
                    }
                },
                plugins: {
                    legend: {
                        labels: { color: '#ffffff' }
                    },
                    title: {
                        display: true,
                        text: 'Most Common Services',
                        color: '#ffffff'
                    }
                }
            }
        });
    }
}

// Function to load available networks
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

// Function to start a network scan
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

// Function to check scan status and update UI
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
            if (scanButton) {
                scanButton.disabled = false;
                scanButton.textContent = 'Start Scan';
            }
            
            // Load scan results
            const resultsResponse = await fetch(`/api/scan/${scanId}/results`);
            const scanData = await resultsResponse.json();
            
            if (resultsResponse.ok) {
                // Update network metrics
                updateNetworkMetrics(scanData);
                
                // Update port analysis
                await updatePortAnalysis(scanId);
                
                // Update topology
                await refreshTopology(scanId);
            }
        } else if (data.status === 'failed') {
            const scanButton = document.getElementById('scan-button');
            if (scanButton) {
                scanButton.disabled = false;
                scanButton.textContent = 'Start Scan';
            }
            if (statusElement) {
                statusElement.style.color = '#dc3545';  // Red color for error
            }
        } else if (data.status === 'running') {
            // Continue polling for updates
            setTimeout(() => updateScanStatus(scanId), 2000);
        }
    } catch (error) {
        console.error('Error checking scan status:', error);
    }
}

// Initialize when the page loads
document.addEventListener('DOMContentLoaded', () => {
    loadNetworks();
    
    // Add event listener for scan button
    const scanButton = document.getElementById('scan-button');
    if (scanButton) {
        scanButton.addEventListener('click', startScan);
    }
});
  