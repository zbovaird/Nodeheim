// Network topology visualization using vis.js
let network = null;
let nodes = new vis.DataSet();
let edges = new vis.DataSet();

// Configuration for the network visualization
const options = {
    nodes: {
        shape: 'dot',
        size: 30,
        font: {
            size: 14,
            color: '#ffffff'
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
        shadow: true
    },
    physics: {
        stabilization: false,
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

export function initializeTopology() {
    const container = document.getElementById('network-visualization');
    if (!container) return;
    
    network = new vis.Network(container, { nodes, edges }, options);
    
    // Add event listeners
    network.on('hoverNode', function(params) {
        const node = nodes.get(params.node);
        showNodeTooltip(node, params.event);
    });
    
    network.on('blurNode', function() {
        hideNodeTooltip();
    });
}

export async function refreshTopology(scanId) {
    try {
        const response = await fetch(`/api/topology/scan/${scanId}`);
        const data = await response.json();
        
        // Clear existing data
        nodes.clear();
        edges.clear();
        
        // Add nodes
        const nodeData = data.nodes.map(node => ({
            id: node.id,
            label: node.ip_address,
            title: getNodeTitle(node),
            color: getNodeColor(node.risk_level || 'low'),
            device_type: node.device_type,
            os_info: node.os_info,
            services: node.services,
            risk_level: node.risk_level
        }));
        nodes.add(nodeData);
        
        // Add edges
        const edgeData = data.edges.map(edge => ({
            from: edge.from,
            to: edge.to,
            arrows: edge.directed ? 'to' : undefined
        }));
        edges.add(edgeData);
        
        // Apply layout
        const layout = document.getElementById('layout-select').value;
        applyLayout(layout);
        
    } catch (error) {
        console.error('Error refreshing topology:', error);
    }
}

function getNodeTitle(node) {
    let title = `IP: ${node.ip_address}\n`;
    if (node.hostname) title += `Hostname: ${node.hostname}\n`;
    if (node.device_type) title += `Type: ${node.device_type}\n`;
    if (node.os_info?.os_match) title += `OS: ${node.os_info.os_match}\n`;
    if (node.services?.length) {
        title += 'Services:\n';
        node.services.forEach(svc => {
            title += `- ${svc.port}/${svc.protocol}: ${svc.name}`;
            if (svc.product) title += ` (${svc.product}`;
            if (svc.version) title += ` ${svc.version}`;
            if (svc.extra_info) title += ` - ${svc.extra_info}`;
            if (svc.product) title += ')';
            title += '\n';
        });
    }
    return title;
}

function getNodeColor(riskLevel) {
    switch (riskLevel.toLowerCase()) {
        case 'high':
            return '#dc3545';
        case 'medium':
            return '#ffc107';
        case 'low':
        default:
            return '#28a745';
    }
}

function applyLayout(layout) {
    if (!network) return;
    
    switch (layout) {
        case 'circular':
            network.setOptions({
                layout: {
                    randomSeed: 42,
                    improvedLayout: true,
                    hierarchical: false
                },
                physics: {
                    enabled: true,
                    solver: 'forceAtlas2Based'
                }
            });
            break;
            
        case 'hierarchical':
            network.setOptions({
                layout: {
                    hierarchical: {
                        direction: 'UD',
                        sortMethod: 'hubsize',
                        nodeSpacing: 150
                    }
                },
                physics: false
            });
            break;
            
        case 'force':
        default:
            network.setOptions({
                layout: {
                    randomSeed: undefined,
                    improvedLayout: true,
                    hierarchical: false
                },
                physics: {
                    enabled: true,
                    solver: 'barnesHut',
                    barnesHut: {
                        gravitationalConstant: -80000,
                        springConstant: 0.001,
                        springLength: 200
                    }
                }
            });
            break;
    }
}

// Tooltip functions
function showNodeTooltip(node, event) {
    const tooltip = document.createElement('div');
    tooltip.className = 'node-tooltip';
    tooltip.innerHTML = node.title.replace(/\n/g, '<br>');
    
    // Position tooltip near the node
    tooltip.style.left = event.pageX + 10 + 'px';
    tooltip.style.top = event.pageY + 10 + 'px';
    
    // Remove any existing tooltips
    hideNodeTooltip();
    
    // Add tooltip to body
    document.body.appendChild(tooltip);
}

function hideNodeTooltip() {
    const tooltips = document.getElementsByClassName('node-tooltip');
    while (tooltips.length > 0) {
        tooltips[0].parentNode.removeChild(tooltips[0]);
    }
}

// Export functions for use in HTML
window.changeLayout = function() {
    const layout = document.getElementById('layout-select').value;
    applyLayout(layout);
};

window.refreshTopology = refreshTopology;

// Initialize topology when the page loads
document.addEventListener('DOMContentLoaded', initializeTopology); 