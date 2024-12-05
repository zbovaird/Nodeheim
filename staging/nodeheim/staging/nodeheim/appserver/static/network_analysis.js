require([
    'jquery',
    'underscore',
    'splunkjs/mvc',
    'splunkjs/mvc/searchmanager',
    'splunkjs/mvc/simplexml/ready!'
], function($, _, mvc, SearchManager) {
    'use strict';
    
    // Initialize network selection
    var networkSelect = mvc.Components.get('network_select');
    var customNetwork = mvc.Components.get('custom_network');
    var scanType = mvc.Components.get('scan_type');
    var startScan = mvc.Components.get('start_scan');

    // Handle network selection changes
    if (networkSelect) {
        networkSelect.on('change', function() {
            var value = networkSelect.val();
            if (value === 'custom') {
                $('#custom_network_container').show();
            } else {
                $('#custom_network_container').hide();
            }
        });
    }

    // Validate CIDR input
    function validateCIDR(cidr) {
        var pattern = /^([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[1-2][0-9]|3[0-2])$/;
        return pattern.test(cidr);
    }

    // Handle scan start
    if (startScan) {
        startScan.on('click', function() {
            var subnet = networkSelect.val() === 'custom' ? customNetwork.val() : networkSelect.val();
            
            // Validate subnet
            if (!validateCIDR(subnet)) {
                showError('Invalid network format. Please use CIDR notation (e.g., 192.168.1.0/24)');
                return;
            }

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
            });
        });
    }

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

    // Initialize tooltips
    $('.input-dropdown, .text-input').tooltip({
        container: 'body',
        placement: 'right'
    });
}); 