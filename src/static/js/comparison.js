// Function to format timestamp
function formatTimestamp(isoString) {
    const date = new Date(isoString);
    return date.toLocaleString('en-US', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false
    });
}

// Function to load available snapshots
export async function loadSnapshots() {
    try {
        const select = document.getElementById('snapshotSelect');
        if (!select) {
            console.error('Snapshot select element not found');
            return;
        }

        // Show loading state
        select.innerHTML = '<option value="">Loading snapshots...</option>';
        select.disabled = true;

        const response = await fetch('/api/snapshots');
        const data = await response.json();
        
        if (data.status === 'success' && Array.isArray(data.snapshots)) {
            // Clear loading state
            select.innerHTML = '';
            select.disabled = false;

            // Add snapshots to select
            data.snapshots.forEach(snapshot => {
                const option = document.createElement('option');
                option.value = snapshot.id;
                option.dataset.network = snapshot.network;
                option.dataset.timestamp = snapshot.timestamp;
                option.dataset.totalHosts = snapshot.total_hosts;
                option.dataset.activeHosts = snapshot.active_hosts;
                
                // Format the display text
                const timestamp = formatTimestamp(snapshot.timestamp);
                option.textContent = `${snapshot.network} - ${timestamp} (${snapshot.active_hosts}/${snapshot.total_hosts} hosts)`;
                
                select.appendChild(option);
            });

            // Enable multiple selection
            select.multiple = true;
            select.size = Math.min(6, data.snapshots.length);
        } else {
            console.error('Failed to load snapshots:', data.message);
            select.innerHTML = '<option value="">Error loading snapshots</option>';
        }
    } catch (error) {
        console.error('Error loading snapshots:', error);
        const select = document.getElementById('snapshotSelect');
        if (select) {
            select.innerHTML = '<option value="">Error loading snapshots</option>';
            select.disabled = false;
        }
    }
}

// Function to compare selected snapshots
export async function compareSnapshots() {
    const select = document.getElementById('snapshotSelect');
    const selectedOptions = Array.from(select.selectedOptions);
    
    if (selectedOptions.length !== 2) {
        alert('Please select exactly 2 snapshots to compare');
        return;
    }

    const snapshot1 = selectedOptions[0].value;
    const snapshot2 = selectedOptions[1].value;
    
    try {
        // Show loading state
        const resultsDiv = document.getElementById('comparisonResults');
        resultsDiv.innerHTML = '<div class="text-center">Loading comparison results...</div>';

        const response = await fetch('/api/compare', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                snapshot1: snapshot1,
                snapshot2: snapshot2
            })
        });

        const data = await response.json();
        
        if (response.ok) {
            displayComparisonResults(data, selectedOptions);
        } else {
            resultsDiv.innerHTML = `<div class="alert alert-danger">Error: ${data.error || 'Failed to compare snapshots'}</div>`;
        }
    } catch (error) {
        console.error('Error comparing snapshots:', error);
        const resultsDiv = document.getElementById('comparisonResults');
        resultsDiv.innerHTML = '<div class="alert alert-danger">Error comparing snapshots</div>';
    }
}

// Initialize when the page loads
document.addEventListener('DOMContentLoaded', () => {
    loadSnapshots();
    
    // Add event listener for compare button
    const compareButton = document.getElementById('compareButton');
    if (compareButton) {
        compareButton.addEventListener('click', compareSnapshots);
    }
    
    // Add event listener for refresh button
    const refreshButton = document.getElementById('refreshButton');
    if (refreshButton) {
        refreshButton.addEventListener('click', loadSnapshots);
    }
}); 