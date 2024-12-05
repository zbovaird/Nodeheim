require([
    'jquery',
    'underscore',
    'splunkjs/mvc',
    'splunkjs/mvc/searchmanager',
    'splunkjs/mvc/simplexml/ready!'
], function($, _, mvc, SearchManager) {
    'use strict';
    
    // Initialize form inputs
    var subnetInput = mvc.Components.get('subnet');
    var scanType = mvc.Components.get('scan_type');
    var startScan = mvc.Components.get('start_scan');

    // Validate CIDR input
    function validateCIDR(cidr) {
        var pattern = /^([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[1-2][0-9]|3[0-2])$/;
        if (!pattern.test(cidr)) {
            return false;
        }
        
        // Validate IP address parts
        var ip = cidr.split('/')[0];
        var parts = ip.split('.');
        return parts.every(function(part) {
            var num = parseInt(part, 10);
            return num >= 0 && num <= 255;
        });
    }

    // Handle form submission
    startScan.on('change', function() {
        var subnet = subnetInput.val();
        
        // Validate subnet
        if (!validateCIDR(subnet)) {
            showError('Invalid network format. Please use CIDR notation (e.g., 192.168.1.0/24)');
            return;
        }

        // Update display values
        $('.network-value').text(subnet);
        $('.scan-type-value').text(scanType.val() === 'basic' ? 'Basic Scan (Fast)' : 'Full Scan (Detailed)');

        // Show progress indicator
        $('.scan-progress').show();
        
        // Create search manager for scan
        var scanSearch = new SearchManager({
            id: 'network_scan_search',
            preview: true,
            cache: false,
            search: '| nodeheim_scan subnet="' + subnet + '" scan_type="' + scanType.val() + '"',
            earliest_time: '-24h',
            latest_time: 'now'
        });

        // Handle search progress
        scanSearch.on('search:progress', function(properties) {
            updateProgress(properties);
        });

        // Handle search error
        scanSearch.on('search:error', function(properties) {
            showError('Error during scan: ' + properties.message);
            $('.scan-progress').hide();
        });

        // Handle search completion
        scanSearch.on('search:done', function(properties) {
            if (properties.content.resultCount === 0) {
                showError('No results found. Please check the network and try again.');
            }
            $('.scan-progress').hide();
            updateResults();
        });
    });

    // Update progress bar
    function updateProgress(properties) {
        var progress = properties.content.doneProgress * 100;
        $('.progress-bar').css('width', progress + '%');
    }

    // Show error message
    function showError(message) {
        var errorDiv = $('<div class="error-message"></div>')
            .text(message)
            .insertAfter('.fieldset');
        
        setTimeout(function() {
            errorDiv.fadeOut(function() {
                $(this).remove();
            });
        }, 5000);
    }

    // Update results panels
    function updateResults() {
        // Refresh all search panels
        mvc.Components.revokeInstance('network_scan_search');
        mvc.Components.get('network_overview').startSearch();
        mvc.Components.get('network_connections').startSearch();
        mvc.Components.get('risk_level').startSearch();
        // ... other panel updates
    }

    // Initialize tooltips
    $('.input-dropdown, .text-input').tooltip({
        container: 'body',
        placement: 'right',
        title: function() {
            if ($(this).hasClass('subnet')) {
                return 'Enter network in CIDR notation (e.g., 192.168.1.0/24)';
            }
            return '';
        }
    });
}); 