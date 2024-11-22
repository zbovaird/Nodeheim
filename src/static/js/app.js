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
            
            // Add this line to update the network analysis
            updateNetworkAnalysis(scanId);
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
            // Include hostname in label if available
            label: node.hostname ? `${node.id}\n${node.hostname}` : node.id,
            title: generateNodeTooltip(node),
            color: getNodeColor(node),
            size: getNodeSize(node),
            font: {
                size: 12,
                color: '#ffffff',
                face: 'arial',
                strokeWidth: 2,
                strokeColor: '#000000',
                multi: true,
                align: 'center'
            }
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
                },
                labelHighlightBold: true,
                font: {
                    size: 12,
                    face: 'arial'
                }
            },
            edges: {
                smooth: {
                    type: 'continuous'
                },
                length: 200
            },
            physics: {
                stabilization: true,
                barnesHut: {
                    gravitationalConstant: -80000,
                    springConstant: 0.001,
                    springLength: 200
                }
            },
            interaction: {
                hover: true,
                tooltipDelay: 200
            }
        };

        window.network = new vis.Network(container, { nodes, edges }, options);
    } catch (error) {
        console.error('Error refreshing topology:', error);
    }
}
  
function generateNodeTooltip(node) {
    // Format ports and services
    const portServices = node.ports.map(port => {
        const serviceName = port.service_details || port.service || 'unknown';
        return `${port.port}/${port.protocol || 'tcp'} (${serviceName})`;
    }).join('<br>');

    return `
        <div class="node-tooltip">
            <strong>IP:</strong> ${node.id}<br>
            ${node.hostname ? `<strong>Hostname:</strong> ${node.hostname}<br>` : ''}
            <strong>Type:</strong> ${node.type}<br>
            <strong>OS:</strong> ${node.os}<br>
            <strong>Open Ports & Services:</strong><br>
            ${portServices || 'No open ports'}<br>
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
  
// Add this function to create and update the charts
function updateNetworkAnalysis(scanId) {
    fetch(`/api/topology/${scanId}`)
        .then(response => response.json())
        .then(data => {
            // Process data for device type chart
            const deviceTypes = data.nodes.reduce((acc, node) => {
                acc[node.type] = (acc[node.type] || 0) + 1;
                return acc;
            }, {});

            // Process data for OS distribution chart
            const osDistribution = data.nodes.reduce((acc, node) => {
                acc[node.os] = (acc[node.os] || 0) + 1;
                return acc;
            }, {});

            // Create device type chart
            new Chart(document.getElementById('deviceTypeChart'), {
                type: 'pie',
                data: {
                    labels: Object.keys(deviceTypes),
                    datasets: [{
                        data: Object.values(deviceTypes),
                        backgroundColor: ['#ff4444', '#4444ff', '#44ff44', '#cccccc']
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        title: {
                            display: true,
                            text: 'Device Type Distribution',
                            color: '#ffffff'
                        },
                        legend: {
                            labels: {
                                color: '#ffffff'
                            }
                        }
                    }
                }
            });

            // Create OS distribution chart
            new Chart(document.getElementById('osDistributionChart'), {
                type: 'pie',
                data: {
                    labels: Object.keys(osDistribution),
                    datasets: [{
                        data: Object.values(osDistribution),
                        backgroundColor: ['#ff4444', '#4444ff', '#44ff44', '#cccccc']
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        title: {
                            display: true,
                            text: 'OS Distribution',
                            color: '#ffffff'
                        },
                        legend: {
                            labels: {
                                color: '#ffffff'
                            }
                        }
                    }
                }
            });

            // Update host details table
            const tableBody = document.getElementById('hostDetailsTable');
            tableBody.innerHTML = data.nodes.map(node => `
                <tr>
                    <td>${node.id}</td>
                    <td>${node.hostname || 'N/A'}</td>
                    <td>${node.type}</td>
                    <td>${node.os}</td>
                    <td>${node.ports.map(p => `${p.port} (${p.service})`).join(', ') || 'None'}</td>
                </tr>
            `).join('');
        });
}
  