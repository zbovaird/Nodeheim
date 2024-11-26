// Network topology visualization using vis.js
let network = null;
let nodes = new vis.DataSet();
let edges = new vis.DataSet();

// Node color definitions
const nodeColors = {
    highRisk: '#dc3545',    // Red for high risk
    mediumRisk: '#ffc107',  // Yellow for medium risk
    lowRisk: '#28a745',     // Green for low risk
    noServices: '#2196F3'   // Blue for no services
};

// Function to format host details for tooltip
function formatHostDetails(node) {
    let details = [];
    details.push(`IP Address: ${node.ip_address || node.id}`);
    
    if (node.hostnames && node.hostnames.length > 0) {
        details.push(`Hostname: ${node.hostnames.map(h => h.name).join(', ')}`);
    }
    
    if (node.os_info) {
        const os = [];
        if (node.os_info.os_match && node.os_info.os_match !== 'unknown') {
            os.push(node.os_info.os_match);
        }
        if (node.os_info.os_accuracy) {
            os.push(`${node.os_info.os_accuracy}% accuracy`);
        }
        if (os.length > 0) {
            details.push(`OS: ${os.join(' - ')}`);
        }
    }
    
    if (node.ports && node.ports.length > 0) {
        details.push('\nOpen Ports:');
        node.ports.forEach(port => {
            let portInfo = `${port.port}/${port.protocol || 'tcp'}`;
            if (port.service) {
                portInfo += ` - ${port.service}`;
                if (port.service_details) {
                    portInfo += ` (${port.service_details})`;
                }
            }
            details.push(portInfo);
        });
    }
    
    return details.join('\n');
}

// Function to determine node risk level
function getNodeRiskLevel(node) {
    if (!node.ports || node.ports.length === 0) return 'noServices';
    
    // Check for high-risk services (common vulnerable ports)
    const highRiskPorts = ['21', '23', '445', '3389'];
    const remoteAccessPorts = ['22', '3389', '5900'];
    
    const hasHighRiskService = node.ports.some(port => 
        highRiskPorts.includes(port.port.toString()) && port.state === 'open'
    );
    if (hasHighRiskService) return 'highRisk';
    
    // Check for medium-risk services (remote access)
    const hasMediumRiskService = node.ports.some(port => 
        remoteAccessPorts.includes(port.port.toString()) && port.state === 'open'
    );
    if (hasMediumRiskService) return 'mediumRisk';
    
    // If has services but no high/medium risk ones
    return 'lowRisk';
}

// Configuration for the network visualization
const options = {
    nodes: {
        shape: 'dot',
        size: 30,
        font: {
            size: 14,
            color: '#ffffff',
            face: 'monospace',
            strokeWidth: 2,
            strokeColor: '#000000'
        },
        borderWidth: 2,
        shadow: true
    },
    edges: {
        width: 2,
        color: {
            color: '#848484',
            highlight: '#848484',
            hover: '#848484'
        },
        shadow: true,
        smooth: {
            type: 'continuous'
        }
    },
    physics: {
        enabled: true,
        solver: 'forceAtlas2Based',
        forceAtlas2Based: {
            gravitationalConstant: -26,
            centralGravity: 0.005,
            springLength: 230,
            springConstant: 0.18,
            damping: 0.4
        },
        stabilization: {
            enabled: true,
            iterations: 1000,
            updateInterval: 25
        }
    },
    interaction: {
        hover: true,
        tooltipDelay: 200,
        zoomView: true,
        dragView: true
    }
};

// Create legend
function createLegend(container) {
    const legend = document.createElement('div');
    legend.className = 'topology-legend';
    legend.style.cssText = `
        position: absolute;
        bottom: 20px;
        left: 20px;
        background-color: rgba(0, 0, 0, 0.7);
        padding: 10px;
        border-radius: 5px;
        z-index: 1000;
    `;
    
    const legendItems = [
        { color: nodeColors.highRisk, label: 'High Risk (Known Vulnerable Ports)' },
        { color: nodeColors.mediumRisk, label: 'Medium Risk (Remote Access)' },
        { color: nodeColors.lowRisk, label: 'Low Risk (Other Services)' },
        { color: nodeColors.noServices, label: 'No Open Services' }
    ];
    
    legendItems.forEach(item => {
        const legendItem = document.createElement('div');
        legendItem.style.cssText = `
            display: flex;
            align-items: center;
            margin: 5px 0;
            color: white;
            font-size: 12px;
        `;
        
        const colorDot = document.createElement('span');
        colorDot.style.cssText = `
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background-color: ${item.color};
            margin-right: 8px;
            display: inline-block;
        `;
        
        legendItem.appendChild(colorDot);
        legendItem.appendChild(document.createTextNode(item.label));
        legend.appendChild(legendItem);
    });
    
    container.appendChild(legend);
}

// Initialize the network visualization
function initNetwork() {
    const container = document.getElementById('network-topology');
    if (!container) {
        console.error('Network topology container not found');
        return;
    }

    network = new vis.Network(container, { nodes, edges }, options);
    
    // Add reset view button handler
    const resetButton = document.getElementById('resetViewButton');
    if (resetButton) {
        resetButton.addEventListener('click', () => {
            network.fit();
        });
    }
    
    // Create and add the legend
    createLegend(container);
}

// Update the network visualization with new data
export async function refreshTopology(scanId) {
    try {
        const response = await fetch(`/api/topology/scan/${scanId}`);
        const data = await response.json();
        
        if (response.ok) {
            // Clear existing nodes and edges
            nodes.clear();
            edges.clear();
            
            // Add nodes with service information
            data.nodes.forEach(node => {
                const riskLevel = getNodeRiskLevel(node);
                nodes.add({
                    id: node.id,
                    label: node.label || node.id,
                    title: formatHostDetails(node),
                    color: {
                        background: nodeColors[riskLevel],
                        border: '#ffffff'
                    }
                });
            });
            
            // Add edges
            data.links.forEach(link => {
                edges.add({
                    from: link.source,
                    to: link.target
                });
            });
            
            // If network doesn't exist, initialize it
            if (!network) {
                initNetwork();
            }
            
            // Fit the network to view all nodes
            network.fit();
        } else {
            console.error('Failed to fetch topology data:', data.error);
        }
    } catch (error) {
        console.error('Error refreshing topology:', error);
    }
}

// Initialize when the page loads
document.addEventListener('DOMContentLoaded', initNetwork); 