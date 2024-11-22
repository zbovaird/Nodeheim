export async function loadNetworks() {
    try {
        const response = await fetch('/api/networks');
        const data = await response.json();
        
        if (data.status === 'success') {
            const networkSelect = document.getElementById('network-select');
            networkSelect.innerHTML = '';
            
            data.networks.forEach(network => {
                const option = document.createElement('option');
                option.value = network.network;
                // Use network name if available, otherwise use network address
                option.textContent = network.name || network.network;
                networkSelect.appendChild(option);
            });
        } else {
            console.error('Failed to load networks:', data.message);
        }
    } catch (error) {
        console.error('Error loading networks:', error);
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
            document.getElementById('scan-button').style.display = 'none';
            document.getElementById('stop-button').style.display = 'inline-block';
            updateScanStatus(data.scan_id);
        } else {
            alert('Failed to start scan: ' + data.message);
        }
    } catch (error) {
        console.error('Error starting scan:', error);
        alert('Error starting scan');
    }
}

export async function stopScan() {
    try {
        const response = await fetch('/api/scan/stop', {
            method: 'POST'
        });
        const data = await response.json();
        
        if (data.status === 'success') {
            document.getElementById('scan-button').style.display = 'inline-block';
            document.getElementById('stop-button').style.display = 'none';
        } else {
            alert('Failed to stop scan: ' + data.message);
        }
    } catch (error) {
        console.error('Error stopping scan:', error);
        alert('Error stopping scan');
    }
}

export async function updateScanStatus(scanId) {
    try {
        const response = await fetch(`/api/scan/${scanId}/status`);
        const data = await response.json();
        
        const statusElement = document.querySelector('.scan-status');
        statusElement.style.display = 'block';
        statusElement.textContent = `Scan Status: ${data.status} (${data.progress}%)`;
        
        if (data.status === 'completed') {
            document.getElementById('scan-button').style.display = 'inline-block';
            document.getElementById('stop-button').style.display = 'none';
            
            // Update metrics
            if (data.summary) {
                document.getElementById('total-nodes').textContent = data.summary.total_hosts || 0;
                document.getElementById('active-hosts').textContent = data.summary.active_hosts || 0;
                document.getElementById('open-ports').textContent = data.summary.total_ports || 0;
                document.getElementById('vulnerabilities').textContent = data.summary.total_vulnerabilities || 0;
                document.getElementById('last-scan').textContent = new Date().toLocaleString();
            }
            
            // Refresh topology visualization
            refreshTopology(scanId);
            
        } else if (data.status === 'failed') {
            document.getElementById('scan-button').style.display = 'inline-block';
            document.getElementById('stop-button').style.display = 'none';
            statusElement.style.color = '#dc3545';  // Red color for error
        } else {
            // Continue polling for updates
            setTimeout(() => updateScanStatus(scanId), 2000);
        }
    } catch (error) {
        console.error('Error updating scan status:', error);
    }
}

// Load networks when the page loads
document.addEventListener('DOMContentLoaded', loadNetworks);
  
// Add this function to app.js
async function refreshTopology(scanId) {
    try {
        const response = await fetch(`/api/topology/${scanId}`);
        const data = await response.json();
        
        if (!data.nodes || !data.links) {
            console.error('Invalid topology data format:', data);
            return;
        }
        
        // Create the visualization
        const container = document.getElementById('network-visualization');
        const nodes = new vis.DataSet(data.nodes.map(node => ({
            id: node.id,
            label: node.id,
            title: generateNodeTooltip(node),
            color: getNodeColor(node),
            size: getNodeSize(node)
        })));

        const edges = new vis.DataSet(data.links.map(link => ({
            from: link.source,
            to: link.target,
            color: getEdgeColor(link)
        })));

        const options = {
            nodes: {
                shape: 'dot',
                scaling: {
                    min: 10,
                    max: 30
                }
            },
            physics: {
                stabilization: true,
                barnesHut: {
                    gravitationalConstant: -80000,
                    springConstant: 0.001,
                    springLength: 200
                }
            }
        };

        window.network = new vis.Network(container, { nodes, edges }, options);
    } catch (error) {
        console.error('Error refreshing topology:', error);
    }
}
  
function generateNodeTooltip(node) {
    return `
        <div class="node-tooltip">
            <strong>IP:</strong> ${node.id}<br>
            <strong>Type:</strong> ${node.type}<br>
            <strong>OS:</strong> ${node.os}<br>
            <strong>Open Ports:</strong> ${node.ports.length}<br>
            <strong>Services:</strong> ${node.services.map(s => s.name).join(', ')}
        </div>
    `;
}

function getNodeColor(node) {
    const typeColors = {
        'router': '#ff4444',
        'server': '#4444ff',
        'workstation': '#44ff44',
        'unknown': '#cccccc'
    };
    return typeColors[node.type] || typeColors.unknown;
}

function getNodeSize(node) {
    return 10 + (node.services.length * 2);
}

function getEdgeColor(link) {
    return link.type === 'subnet' ? '#666666' : '#999999';
}
  