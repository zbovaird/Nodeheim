import { refreshTopology } from './topology.js';

// Add this at the top of your file
let currentScanId = null;

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
            // Store the scan ID when scan completes successfully
            currentScanId = scanId;
            window.lastSuccessfulScanId = scanId;
            
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
                
                // Update host details
                updateHostDetails(scanData);
                
                // Update port analysis
                await updatePortAnalysis(scanId);
                
                // Update topology
                await refreshTopology(scanId);
            }
            
            // Enable only the Analyze Network button
            updateUIState('scan_completed');
            
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
    
    // Initialize UI state
    updateUIState('initial');
    
    // Add event listener for scan button
    const scanButton = document.getElementById('scan-button');
    if (scanButton) {
        scanButton.addEventListener('click', startScan);
    }
});

// Network Analysis Handler
document.getElementById('analyze-network').addEventListener('click', async () => {
    if (!currentScanId) {
        alert('Please perform a network scan first');
        return;
    }

    try {
        const response = await fetch(`/api/analysis/${currentScanId}`);
        const data = await response.json();
        
        if (response.ok) {
            // Update basic metrics
            updateBasicMetrics(data.metrics);
            
            // Update network structure metrics
            updateStructureMetrics(data.structure_analysis);
            
            // Update security metrics
            updateSecurityMetrics(data.security_metrics);
            
            // Update spectral metrics
            updateSpectralMetrics(data.spectral_metrics);
            
            // Update bottleneck analysis
            updateBottleneckAnalysis(data.bottleneck_analysis);
            
            // Update risk visualization
            updateRiskVisualization(data.risk_scores);
            
            // Update centrality measures
            updateCentralityVisualization(data.network_analysis);
            
            // Update topology visualization
            await refreshTopology(currentScanId);
            
            // Show the analysis panel
            document.querySelector('.network-analysis-panel').style.display = 'block';
            
            // Enable generate report button
            updateUIState('analysis_completed');
            window.analysisCompleted = true;
            
        } else {
            throw new Error(data.error || 'Failed to analyze network');
        }
    } catch (error) {
        console.error('Error analyzing network:', error);
        alert('Error analyzing network: ' + error.message);
    }
});

// Report Generation Handler
document.getElementById('generate-report').addEventListener('click', async () => {
    if (!window.analysisCompleted) {
        alert('Please analyze the network first');
        return;
    }

    try {
        const response = await fetch(`/api/comparison/${currentScanId}/report`);
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = `network_analysis_report_${currentScanId}.md`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        } else {
            const data = await response.json();
            throw new Error(data.error || 'Failed to generate report');
        }
    } catch (error) {
        console.error('Error generating report:', error);
        alert('Error generating report: ' + error.message);
    }
});

// Report History Handler
document.getElementById('report-history').addEventListener('click', async () => {
    try {
        const response = await fetch('/api/analysis/history');
        const data = await response.json();
        
        if (response.ok) {
            const modalHtml = `
                <div class="modal fade" id="reportHistoryModal" tabindex="-1">
                    <div class="modal-dialog modal-lg">
                        <div class="modal-content bg-dark text-light">
                            <div class="modal-header">
                                <h5 class="modal-title">Network Analysis History</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                            </div>
                            <div class="modal-body">
                                <div class="table-responsive">
                                    <table class="table table-dark">
                                        <thead>
                                            <tr>
                                                <th>Date</th>
                                                <th>Network</th>
                                                <th>Summary</th>
                                                <th>Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            ${data.map(report => `
                                                <tr>
                                                    <td>${new Date(report.timestamp).toLocaleString()}</td>
                                                    <td>${report.scan_id}</td>
                                                    <td>
                                                        Hosts: ${report.metrics?.total_hosts || 0}<br>
                                                        Active: ${report.metrics?.active_hosts || 0}<br>
                                                        Services: ${report.metrics?.total_services || 0}
                                                    </td>
                                                    <td>
                                                        <button class="btn btn-sm btn-primary" 
                                                                onclick="window.location.href='/api/comparison/${report.scan_id}/report'">
                                                            Download Report
                                                        </button>
                                                        <button class="btn btn-sm btn-info" 
                                                                onclick="viewAnalysis('${report.scan_id}')">
                                                            View Analysis
                                                        </button>
                                                    </td>
                                                </tr>
                                            `).join('')}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            const modalContainer = document.createElement('div');
            modalContainer.innerHTML = modalHtml;
            document.body.appendChild(modalContainer);
            
            const modal = new bootstrap.Modal(document.getElementById('reportHistoryModal'));
            modal.show();
            
            document.getElementById('reportHistoryModal').addEventListener('hidden.bs.modal', function () {
                document.body.removeChild(modalContainer);
            });
        } else {
            throw new Error(data.error || 'Failed to fetch report history');
        }
    } catch (error) {
        console.error('Error fetching report history:', error);
        alert('Error fetching report history: ' + error.message);
    }
});

// Update the UI state function to handle different states
function updateUIState(state) {
    const analyzeBtn = document.getElementById('analyze-network');
    const generateReportBtn = document.getElementById('generate-report');
    
    switch (state) {
        case 'initial':
            // Initial state - only scan button enabled
            analyzeBtn.classList.add('disabled');
            generateReportBtn.classList.add('disabled');
            break;
            
        case 'scan_completed':
            // After scan completes - enable analyze button
            analyzeBtn.classList.remove('disabled');
            generateReportBtn.classList.add('disabled');
            break;
            
        case 'analysis_completed':
            // After analysis completes - enable generate report button
            analyzeBtn.classList.remove('disabled');
            generateReportBtn.classList.remove('disabled');
            break;
    }
}

// Add helper functions to update each section
function updateStructureMetrics(analysis) {
    const container = document.getElementById('structure-metrics');
    if (!analysis) {
        console.warn('No structure analysis data provided');
        analysis = {
            density: 0,
            components: [],
            cycles: [],
            endpoints: []
        };
    }

    container.innerHTML = `
        <div class="metric-item">
            <div class="metric-label">Network Density</div>
            <div class="metric-value">${(analysis.density || 0).toFixed(3)}</div>
        </div>
        <div class="metric-item">
            <div class="metric-label">Components</div>
            <div class="metric-value">${(analysis.components || []).length}</div>
        </div>
        <div class="metric-item">
            <div class="metric-label">Cycles</div>
            <div class="metric-value">${(analysis.cycles || []).length}</div>
        </div>
        <div class="metric-item">
            <div class="metric-label">Endpoints</div>
            <div class="metric-value">${(analysis.endpoints || []).length}</div>
        </div>
    `;
}

function updateBasicMetrics(metrics) {
    document.getElementById('total-hosts').textContent = metrics?.total_hosts || '-';
    document.getElementById('active-hosts').textContent = metrics?.active_hosts || '-';
    document.getElementById('total-ports').textContent = metrics?.total_ports || '-';
    document.getElementById('total-services').textContent = metrics?.total_services || '-';
    document.getElementById('total-vulnerabilities').textContent = metrics?.total_vulnerabilities || '-';
}

function updateSecurityMetrics(metrics) {
    const container = document.getElementById('security-metrics');
    if (!metrics) return;

    container.innerHTML = `
        <div class="metric-item">
            <div class="metric-label">High Risk Hosts</div>
            <div class="metric-value">${metrics.high_risk_hosts || 0}</div>
        </div>
        <div class="metric-item">
            <div class="metric-label">Critical Services</div>
            <div class="metric-value">${metrics.critical_services || 0}</div>
        </div>
        <div class="metric-item">
            <div class="metric-label">Exposed Ports</div>
            <div class="metric-value">${metrics.exposed_ports || 0}</div>
        </div>
        <div class="metric-item">
            <div class="metric-label">Security Score</div>
            <div class="metric-value">${metrics.security_score?.toFixed(1) || 0}/10</div>
        </div>
    `;
}

function updateBottleneckAnalysis(analysis) {
    const container = document.getElementById('bottleneck-analysis');
    if (!analysis) return;

    container.innerHTML = `
        <table class="table table-dark">
            <thead>
                <tr>
                    <th>Node</th>
                    <th>Impact Score</th>
                    <th>Traffic Load</th>
                    <th>Risk Level</th>
                    <th>Recommended Action</th>
                </tr>
            </thead>
            <tbody>
                ${Object.entries(analysis)
                    .sort((a, b) => b[1].spectral_score - a[1].spectral_score)
                    .slice(0, 5)
                    .map(([node, data]) => `
                        <tr>
                            <td>${node}</td>
                            <td>${data.spectral_score.toFixed(3)}</td>
                            <td>${data.flow_centrality.toFixed(3)}</td>
                            <td>
                                <span class="badge ${data.is_critical === 'true' ? 'bg-danger' : 'bg-warning'}">
                                    ${data.is_critical === 'true' ? 'Critical' : 'Moderate'}
                                </span>
                            </td>
                            <td>${data.is_critical === 'true' ? 'Immediate Review' : 'Monitor'}</td>
                        </tr>
                    `).join('')}
            </tbody>
        </table>
    `;
}

function updateRiskVisualization(riskScores) {
    const container = document.getElementById('riskDistributionChart').parentElement;
    if (!riskScores || !riskScores.length) return;

    // Get existing chart instance
    const existingChart = Chart.getChart('riskDistributionChart');
    if (existingChart) {
        existingChart.destroy();
    }

    // Get or create canvas
    let canvas = document.getElementById('riskDistributionChart');
    if (!canvas) {
        canvas = document.createElement('canvas');
        canvas.id = 'riskDistributionChart';
        container.appendChild(canvas);
    }

    // Remove any existing risk details table
    const existingTable = container.querySelector('.risk-details');
    if (existingTable) {
        existingTable.remove();
    }

    // Calculate risk distribution
    const riskLevels = {
        'Critical (75-100)': 0,
        'High (50-74)': 0,
        'Medium (25-49)': 0,
        'Low (0-24)': 0
    };

    // Create detailed risk data
    const detailedRisks = {
        'Critical (75-100)': [],
        'High (50-74)': [],
        'Medium (25-49)': [],
        'Low (0-24)': []
    };

    riskScores.forEach((nodeData) => {
        const score = nodeData.score;
        const nodeInfo = {
            ip: nodeData.ip || 'Unknown',
            hostname: nodeData.hostname || 'N/A',
            score: score
        };

        if (score >= 75) {
            riskLevels['Critical (75-100)']++;
            detailedRisks['Critical (75-100)'].push(nodeInfo);
        } else if (score >= 50) {
            riskLevels['High (50-74)']++;
            detailedRisks['High (50-74)'].push(nodeInfo);
        } else if (score >= 25) {
            riskLevels['Medium (25-49)']++;
            detailedRisks['Medium (25-49)'].push(nodeInfo);
        } else {
            riskLevels['Low (0-24)']++;
            detailedRisks['Low (0-24)'].push(nodeInfo);
        }
    });

    // Create new chart
    new Chart(canvas.getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: Object.keys(riskLevels),
            datasets: [{
                data: Object.values(riskLevels),
                backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745']
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: '#ffffff' }
                },
                title: {
                    display: true,
                    text: 'Risk Level Distribution',
                    color: '#ffffff'
                }
            }
        }
    });

    // Create and add the detailed risk table
    const tableHtml = `
        <div class="risk-details mt-3">
            <h6>Detailed Risk Analysis</h6>
            <div class="table-responsive">
                <table class="table table-dark table-sm">
                    <thead>
                        <tr>
                            <th>Risk Level</th>
                            <th>IP Address</th>
                            <th>Hostname</th>
                            <th>Risk Score</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${Object.entries(detailedRisks).map(([level, nodes]) => 
                            nodes.map(node => `
                                <tr>
                                    <td>
                                        <span class="badge ${
                                            level.startsWith('Critical') ? 'bg-danger' :
                                            level.startsWith('High') ? 'bg-warning text-dark' :
                                            level.startsWith('Medium') ? 'bg-info text-dark' :
                                            'bg-success'
                                        }">
                                            ${level.split(' ')[0]}
                                        </span>
                                    </td>
                                    <td>${node.ip}</td>
                                    <td>${node.hostname}</td>
                                    <td>${node.score.toFixed(1)}</td>
                                </tr>
                            `).join('')
                        ).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;

    // Add the table to the container
    const tableContainer = document.createElement('div');
    tableContainer.innerHTML = tableHtml;
    container.appendChild(tableContainer);
}

function updateSpectralMetrics(spectralMetrics) {
    const container = document.getElementById('spectral-metrics');
    if (!spectralMetrics) {
        console.warn('No spectral metrics data provided');
        return;
    }

    container.innerHTML = `
        <div class="metric-item">
            <div class="metric-label">Spectral Radius</div>
            <div class="metric-value">${spectralMetrics.spectral_radius?.toFixed(3) || 0}</div>
        </div>
        <div class="metric-item">
            <div class="metric-label">Fiedler Value</div>
            <div class="metric-value">${spectralMetrics.fiedler_value?.toFixed(3) || 0}</div>
        </div>
        <div class="metric-item">
            <div class="metric-label">Network Connectivity</div>
            <div class="metric-value">${(1/spectralMetrics.fiedler_value)?.toFixed(3) || 0}</div>
        </div>
        <div class="metric-item">
            <div class="metric-label">Algebraic Connectivity</div>
            <div class="metric-value">${Math.abs(spectralMetrics.fiedler_value)?.toFixed(3) || 0}</div>
        </div>
    `;
}

// Update the centrality visualization function
function updateCentralityVisualization(networkAnalysis) {
    const ctx = document.getElementById('centralityChart').getContext('2d');
    if (!networkAnalysis?.centrality_measures) return;

    const measures = networkAnalysis.centrality_measures;
    const nodes = Object.keys(measures.Degree_Centrality || {});
    
    // Calculate statistics for each centrality measure
    const datasets = Object.entries(measures).map(([measure, values]) => {
        const data = nodes.map(node => values[node] || 0);
        return {
            label: measure.replace('_', ' '),
            data: data,
            backgroundColor: measure === 'Degree_Centrality' ? 'rgba(54, 162, 235, 0.5)' :
                           measure === 'Betweenness_Centrality' ? 'rgba(255, 99, 132, 0.5)' :
                           measure === 'Closeness_Centrality' ? 'rgba(75, 192, 192, 0.5)' :
                           'rgba(153, 102, 255, 0.5)',
            borderColor: measure === 'Degree_Centrality' ? 'rgba(54, 162, 235, 1)' :
                        measure === 'Betweenness_Centrality' ? 'rgba(255, 99, 132, 1)' :
                        measure === 'Closeness_Centrality' ? 'rgba(75, 192, 192, 1)' :
                        'rgba(153, 102, 255, 1)',
            borderWidth: 1
        };
    });

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: nodes,
            datasets: datasets
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { color: '#ffffff' }
                },
                x: {
                    ticks: { 
                        color: '#ffffff',
                        maxRotation: 45,
                        minRotation: 45
                    }
                }
            },
            plugins: {
                legend: {
                    labels: { color: '#ffffff' }
                },
                title: {
                    display: true,
                    text: 'Node Centrality Measures',
                    color: '#ffffff'
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `${context.dataset.label}: ${context.raw.toFixed(3)}`;
                        }
                    }
                }
            }
        }
    });
}
  