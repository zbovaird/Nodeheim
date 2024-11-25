// Store snapshots in sessionStorage to persist between page reloads
export async function loadSnapshots() {
    try {
        // Try to get cached snapshots from sessionStorage
        const cachedData = sessionStorage.getItem('cachedSnapshots');
        if (cachedData) {
            console.log("Using cached snapshots from sessionStorage");
            const snapshots = JSON.parse(cachedData);
            updateSnapshotSelect(snapshots);
            return;
        }

        console.log("Starting to load snapshots...");
        const response = await fetch('/api/snapshots');
        console.log("Received response from /api/snapshots");
        const data = await response.json();
        console.log("Parsed snapshot data:", data);
        
        // Cache the snapshots in sessionStorage
        if (data.snapshots) {
            sessionStorage.setItem('cachedSnapshots', JSON.stringify(data.snapshots));
            updateSnapshotSelect(data.snapshots);
        }
    } catch (error) {
        console.error('Error loading snapshots:', error);
        const select = document.getElementById('snapshotSelect');
        select.innerHTML = '<option disabled>Error loading snapshots</option>';
    }
}

// Add function to force refresh snapshots
export async function refreshSnapshots() {
    sessionStorage.removeItem('cachedSnapshots');  // Clear cache
    await loadSnapshots();
}

export async function compareSnapshots() {
    const select = document.getElementById('snapshotSelect');
    const selectedOptions = Array.from(select.selectedOptions);
    
    if (selectedOptions.length !== 2) {
        alert('Please select exactly 2 snapshots to compare');
        return;
    }

    console.log('Starting comparison with snapshots:', selectedOptions.map(opt => opt.dataset));

    try {
        // Show loading state
        const resultsDiv = document.getElementById('comparisonResults');
        resultsDiv.style.display = 'block';
        resultsDiv.innerHTML = '<div class="text-center p-4">Loading comparison results...</div>';

        const response = await fetch('/api/comparison/create', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                before_scan: selectedOptions[0].dataset.scanId,
                after_scan: selectedOptions[1].dataset.scanId
            })
        });

        console.log('Response status:', response.status);
        const data = await response.json();
        console.log('Received comparison data:', data);

        if (data.error) {
            throw new Error(data.error);
        }

        // Update comparison results
        updateComparisonResults(data, selectedOptions[0].dataset, selectedOptions[1].dataset);

    } catch (error) {
        console.error('Comparison failed:', error);
        document.getElementById('comparisonResults').innerHTML = `
            <div class="alert alert-danger">
                Comparison failed: ${error.message}
            </div>
        `;
    }
}

function updateComparisonResults(data, beforeSnapshot, afterSnapshot) {
    const resultsDiv = document.getElementById('comparisonResults');
    
    // Format timestamps for display
    const beforeTime = new Date(beforeSnapshot.timestamp).toLocaleString('en-US', {
        month: 'short',
        day: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: true
    });
    const afterTime = new Date(afterSnapshot.timestamp).toLocaleString('en-US', {
        month: 'short',
        day: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: true
    });
    
    // Extract structural changes
    const changes = data.structural_changes || {};
    const newNodes = parseInt(changes.New_Nodes) || 0;
    const removedNodes = parseInt(changes.Removed_Nodes) || 0;
    const newEdges = parseInt(changes.New_Edges) || 0;
    const removedEdges = parseInt(changes.Removed_Edges) || 0;
    
    // Extract metric changes
    const metrics = data.metric_changes || {};
    const avgClustering = (metrics.Average_Clustering || 0).toFixed(3);
    const networkDensity = (metrics.Network_Density || 0).toFixed(3);
    const avgDegree = (metrics.Average_Degree || 0).toFixed(1);
    const components = metrics.Components || 0;
    
    resultsDiv.innerHTML = `
        <div class="card bg-darker mb-3">
            <div class="card-header">
                <h5>Network Comparison</h5>
                <div class="text-muted">
                    <small>Before: ${beforeSnapshot.subnet} [${beforeTime}]</small><br>
                    <small>After: ${afterSnapshot.subnet} [${afterTime}]</small>
                </div>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <div class="card bg-darker mb-3">
                            <div class="card-header">Network Changes</div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-6">
                                        <div class="metric-card ${newNodes > 0 ? 'text-success' : ''}">
                                            <div class="metric-title">New Nodes</div>
                                            <div class="metric-value">${newNodes}</div>
                                        </div>
                                    </div>
                                    <div class="col-6">
                                        <div class="metric-card ${removedNodes > 0 ? 'text-danger' : ''}">
                                            <div class="metric-title">Removed Nodes</div>
                                            <div class="metric-value">${removedNodes}</div>
                                        </div>
                                    </div>
                                </div>
                                <div class="row mt-3">
                                    <div class="col-6">
                                        <div class="metric-card ${newEdges > 0 ? 'text-success' : ''}">
                                            <div class="metric-title">New Connections</div>
                                            <div class="metric-value">${newEdges}</div>
                                        </div>
                                    </div>
                                    <div class="col-6">
                                        <div class="metric-card ${removedEdges > 0 ? 'text-danger' : ''}">
                                            <div class="metric-title">Removed Connections</div>
                                            <div class="metric-value">${removedEdges}</div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card bg-darker mb-3">
                            <div class="card-header">Network Metrics</div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-6">
                                        <div class="metric-card">
                                            <div class="metric-title">Avg. Clustering</div>
                                            <div class="metric-value">${avgClustering}</div>
                                        </div>
                                    </div>
                                    <div class="col-6">
                                        <div class="metric-card">
                                            <div class="metric-title">Network Density</div>
                                            <div class="metric-value">${networkDensity}</div>
                                        </div>
                                    </div>
                                </div>
                                <div class="row mt-3">
                                    <div class="col-6">
                                        <div class="metric-card">
                                            <div class="metric-title">Avg. Degree</div>
                                            <div class="metric-value">${avgDegree}</div>
                                        </div>
                                    </div>
                                    <div class="col-6">
                                        <div class="metric-card">
                                            <div class="metric-title">Components</div>
                                            <div class="metric-value">${components}</div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function updateNetworkMetrics(beforeMetrics, afterMetrics) {
    const ctx = document.getElementById('metricsChart').getContext('2d');
    const metrics = ['Average_Clustering', 'Network_Density', 'Average_Degree'];
    
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: metrics.map(m => m.replace('_', ' ')),
            datasets: [
                {
                    label: 'Before',
                    data: metrics.map(m => beforeMetrics[m] || 0),
                    backgroundColor: 'rgba(54, 162, 235, 0.5)'
                },
                {
                    label: 'After',
                    data: metrics.map(m => afterMetrics[m] || 0),
                    backgroundColor: 'rgba(255, 99, 132, 0.5)'
                }
            ]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#fff'
                    }
                },
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#fff'
                    }
                }
            },
            plugins: {
                legend: {
                    labels: {
                        color: '#fff'
                    }
                }
            }
        }
    });
}

function updateSnapshotSelect(snapshots) {
    const select = document.getElementById('snapshotSelect');
    select.innerHTML = '';
    
    // Sort snapshots by timestamp, most recent first
    snapshots.sort((a, b) => {
        const dateA = new Date(a.timestamp);
        const dateB = new Date(b.timestamp);
        return dateB - dateA;
    });
    
    snapshots.forEach(snapshot => {
        const option = document.createElement('option');
        option.value = snapshot.id;
        
        // Parse and format the timestamp
        let formattedDate = 'Invalid Date';
        try {
            // Parse ISO timestamp
            const date = new Date(snapshot.timestamp);
            
            // Check if date is valid
            if (!isNaN(date.getTime())) {
                formattedDate = date.toLocaleString('en-US', {
                    month: 'short',
                    day: '2-digit',
                    year: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit',
                    hour12: true
                });
            } else {
                console.warn('Invalid timestamp:', snapshot.timestamp);
                
                // Try parsing from filename format
                const match = snapshot.id.match(/_(\d{8})_(\d{6})_/);
                if (match) {
                    const [_, date, time] = match;
                    const year = date.slice(0, 4);
                    const month = date.slice(4, 6);
                    const day = date.slice(6, 8);
                    const hour = time.slice(0, 2);
                    const minute = time.slice(2, 4);
                    const second = time.slice(4, 6);
                    
                    const parsedDate = new Date(`${year}-${month}-${day}T${hour}:${minute}:${second}`);
                    if (!isNaN(parsedDate.getTime())) {
                        formattedDate = parsedDate.toLocaleString('en-US', {
                            month: 'short',
                            day: '2-digit',
                            year: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit',
                            hour12: true
                        });
                    }
                }
            }
        } catch (e) {
            console.error('Error parsing timestamp:', e);
        }
        
        // Format subnet for display (remove /24 if present)
        const displaySubnet = (snapshot.subnet || '').replace('/24', '');
        
        // Create descriptive label
        option.textContent = `${displaySubnet} - ${formattedDate}`;
        
        // Store data for comparison
        option.dataset.scanId = snapshot.id;
        option.dataset.timestamp = snapshot.timestamp;
        option.dataset.subnet = snapshot.subnet;
        
        select.appendChild(option);
    });
    
    // Enable multiple selection
    select.multiple = true;
    select.size = Math.min(6, snapshots.length);
    
    // Add helper text
    const helperText = document.createElement('div');
    helperText.className = 'text-muted small mt-2';
    helperText.textContent = 'Select two snapshots to compare';
    select.parentNode.appendChild(helperText);
}

export function resetComparison() {
    const select = document.getElementById('snapshotSelect');
    select.selectedIndex = -1;
    document.getElementById('selectedFiles').innerHTML = '';
    document.getElementById('comparisonResults').style.display = 'none';
}

// Update selected files display
export function updateSelectedFiles() {
    const select = document.getElementById('snapshotSelect');
    const selectedList = document.getElementById('selectedFiles');
    selectedList.innerHTML = '';
    
    Array.from(select.selectedOptions).forEach(option => {
        const li = document.createElement('li');
        li.textContent = option.text;
        selectedList.appendChild(li);
    });
} 