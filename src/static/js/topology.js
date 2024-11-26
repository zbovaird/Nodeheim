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
        hideEdgesOnDrag: true,
        multiselect: true
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
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        
        if (!data.nodes || !data.links) {
            console.error('Invalid topology data format:', data);
            return;
        }
        
        // Clear existing data
        nodes.clear();
        edges.clear();
        
        // Add nodes with enhanced visualization
        const nodeData = data.nodes.map(node => ({
            id: node.id,
            label: `${node.id}\n${node.hostname || ''}`,
            title: getNodeTitle(node),
            color: getNodeColor(node.risk_level || 'low'),
            shape: 'dot',
            size: 30,
            font: {
                size: 14,
                color: '#ffffff',
                face: 'monospace',
                strokeWidth: 2,
                strokeColor: '#000000'
            },
            device_type: node.device_type,
            os_info: node.os_info,
            services: node.services,
            risk_level: node.risk_level
        }));
        
        // Add edges with enhanced visualization
        const edgeData = data.links.map(link => ({
            from: link.source,
            to: link.target,
            arrows: 'to',
            color: {
                color: '#848484',
                highlight: '#848484',
                hover: '#848484'
            },
            width: 2,
            smooth: {
                type: 'continuous'
            }
        }));
        
        // Add the data to the visualization
        nodes.add(nodeData);
        edges.add(edgeData);
        
        // Ensure the network is initialized
        if (!network) {
            initializeTopology();
        }
        
        // Apply physics settings for better visualization
        network.setOptions({
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
            }
        });
        
        // Fit the network to view
        network.fit();
        
    } catch (error) {
        console.error('Error refreshing topology:', error);
    }
}

function getNodeTitle(node) {
    let title = `IP: ${node.id}\n`;
    if (node.hostname) title += `Hostname: ${node.hostname}\n`;
    if (node.device_type) title += `Type: ${node.device_type}\n`;
    if (node.os_info?.os_match) title += `OS: ${node.os_info.os_match}\n`;
    if (node.services?.length) {
        title += 'Services:\n';
        node.services.forEach(svc => {
            title += `- ${svc}\n`;
        });
    }
    if (node.ports?.length) {
        title += 'Open Ports:\n';
        title += node.ports.join(', ');
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