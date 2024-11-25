import { refreshTopology } from './topology.js';

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
  