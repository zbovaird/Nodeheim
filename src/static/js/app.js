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
        // First try to get topology for specific scan
        const response = await fetch(`/api/topology/scan/${scanId}`);
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
        
        // If specific scan topology fails, try getting latest topology
        try {
            const latestResponse = await fetch('/api/topology/latest');
            const latestData = await latestResponse.json();
            
            if (latestData.nodes && latestData.links) {
                // Create visualization with latest data
                // ... (same visualization code as above)
                const container = document.getElementById('network-visualization');
                const nodes = new vis.DataSet(latestData.nodes.map(node => ({
                    id: node.id,
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

                const edges = new vis.DataSet(latestData.links.map(link => ({
                    from: link.source,
                    to: link.target,
                    color: getEdgeColor(link)
                })));

                window.network = new vis.Network(container, { nodes, edges }, options);
            }
        } catch (latestError) {
            console.error('Error getting latest topology:', latestError);
        }
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
    fetch(`/api/topology/scan/${scanId}`)
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

            // Update charts
            updateDeviceTypeChart(deviceTypes);
            updateOSDistributionChart(osDistribution);
        })
        .catch(error => {
            console.error('Error updating network analysis:', error);
            // Try getting latest topology data
            fetch('/api/topology/latest')
                .then(response => response.json())
                .then(data => {
                    const deviceTypes = data.nodes.reduce((acc, node) => {
                        acc[node.type] = (acc[node.type] || 0) + 1;
                        return acc;
                    }, {});

                    const osDistribution = data.nodes.reduce((acc, node) => {
                        acc[node.os] = (acc[node.os] || 0) + 1;
                        return acc;
                    }, {});

                    updateDeviceTypeChart(deviceTypes);
                    updateOSDistributionChart(osDistribution);
                })
                .catch(latestError => {
                    console.error('Error getting latest topology for analysis:', latestError);
                });
        });
}
  
// Network comparison functionality
async function compareSnapshots() {
    const beforeSelect = document.getElementById('beforeSnapshot');
    const afterSelect = document.getElementById('afterSnapshot');
    
    if (!beforeSelect || !afterSelect) {
        console.error('Comparison selectors not found');
        return;
    }

    const beforeId = beforeSelect.value;
    const afterId = afterSelect.value;
    
    if (!beforeId || !afterId) {
        showAlert('Please select both before and after snapshots', 'warning');
        return;
    }

    try {
        showSpinner('Comparing network snapshots...');
        
        // Load scan data
        const [beforeData, afterData] = await Promise.all([
            fetch(`/api/scan/${beforeId}`).then(r => r.json()),
            fetch(`/api/scan/${afterId}`).then(r => r.json())
        ]);
        
        // Check for errors
        if (beforeData.error || afterData.error) {
            throw new Error(beforeData.error || afterData.error);
        }
        
        // Create comparison
        const response = await fetch('/api/comparison/create', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                before_scan: beforeId,
                after_scan: afterId,
                before_data: beforeData,
                after_data: afterData
            })
        });
        
        const result = await response.json();
        
        if (result.error) {
            throw new Error(result.error);
        }
        
        // Update comparison view
        await updateComparisonView(result.comparison_id);
        hideSpinner();
        
    } catch (error) {
        console.error('Error comparing snapshots:', error);
        hideSpinner();
        showAlert('Error comparing snapshots: ' + error.message, 'error');
    }
}

// Update comparison view with results
async function updateComparisonView(comparisonId) {
    try {
        // Load comparison results
        const response = await fetch(`/api/comparison/${comparisonId}`);
        const comparison = await response.json();
        
        if (comparison.error) {
            throw new Error(comparison.error);
        }
        
        // Update metrics table
        updateMetricsTable(comparison);
        
        // Update changes visualization
        updateChangesVisualization(comparison);
        
        // Update vulnerability analysis
        updateVulnerabilityAnalysis(comparison);
        
        // Show comparison container
        document.getElementById('comparisonContainer').style.display = 'block';
        
    } catch (error) {
        console.error('Error updating comparison view:', error);
        showAlert('Error updating comparison view: ' + error.message, 'error');
    }
}

// Update metrics table with comparison data
function updateMetricsTable(comparison) {
    const table = document.getElementById('metricsTable');
    if (!table) return;
    
    const metrics = comparison.metrics || {};
    const rows = [];
    
    for (const [metric, values] of Object.entries(metrics)) {
        const change = values.after - values.before;
        const changeClass = change > 0 ? 'text-success' : change < 0 ? 'text-danger' : '';
        
        rows.push(`
            <tr>
                <td>${metric.replace(/_/g, ' ')}</td>
                <td>${values.before}</td>
                <td>${values.after}</td>
                <td class="${changeClass}">${change > 0 ? '+' : ''}${change}</td>
            </tr>
        `);
    }
    
    table.querySelector('tbody').innerHTML = rows.join('');
}

// Update changes visualization
function updateChangesVisualization(comparison) {
    const container = document.getElementById('changesVisualization');
    if (!container) return;
    
    // Clear existing visualization
    container.innerHTML = '';
    
    // Create network visualization
    const nodes = comparison.changes.nodes || [];
    const links = comparison.changes.links || [];
    
    createNetworkGraph(container, nodes, links, {
        nodeColor: d => d.change === 'added' ? '#28a745' : 
                       d.change === 'removed' ? '#dc3545' : 
                       d.change === 'modified' ? '#ffc107' : '#6c757d',
        linkColor: d => d.change === 'added' ? '#28a745' : 
                       d.change === 'removed' ? '#dc3545' : '#6c757d',
        nodeSize: 8,
        linkWidth: 2,
        showLabels: true
    });
}

// Update vulnerability analysis section
function updateVulnerabilityAnalysis(comparison) {
    const container = document.getElementById('vulnerabilityAnalysis');
    if (!container) return;
    
    const vulns = comparison.vulnerability_changes || {};
    
    const sections = [
        {
            title: 'New Vulnerabilities',
            data: vulns.added || [],
            class: 'text-danger'
        },
        {
            title: 'Resolved Vulnerabilities',
            data: vulns.removed || [],
            class: 'text-success'
        },
        {
            title: 'Unchanged Vulnerabilities',
            data: vulns.unchanged || [],
            class: 'text-warning'
        }
    ];
    
    container.innerHTML = sections.map(section => `
        <div class="mb-4">
            <h5 class="${section.class}">${section.title} (${section.data.length})</h5>
            ${section.data.length ? `
                <ul class="list-group">
                    ${section.data.map(v => `
                        <li class="list-group-item">
                            <strong>${v.name}</strong> (${v.severity})
                            <br>
                            <small>${v.description}</small>
                        </li>
                    `).join('')}
                </ul>
            ` : '<p>None found</p>'}
        </div>
    `).join('');
}
  