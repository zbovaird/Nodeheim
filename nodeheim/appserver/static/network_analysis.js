require([
    'jquery',
    'underscore',
    'splunkjs/mvc',
    'splunkjs/mvc/searchmanager',
    'splunkjs/mvc/simplexml/ready!'
], function($, _, mvc, SearchManager) {
    'use strict';
    
    console.log('Dashboard script loaded');
    
    // Initialize form inputs
    var subnetInput = mvc.Components.get('form.subnet');
    var scanType = mvc.Components.get('form.scan_type');
    
    console.log('Form inputs:', {
        subnet: subnetInput ? 'found' : 'not found',
        scanType: scanType ? 'found' : 'not found'
    });

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
    console.log('Setting up form submission handler');
    $('form').on('submit', function(e) {
        console.log('Form submitted');
        e.preventDefault();
        
        var subnet = subnetInput.val();
        console.log('Subnet value:', subnet);
        
        // Validate subnet
        if (!validateCIDR(subnet)) {
            showError('Invalid network format. Please use CIDR notation (e.g., 192.168.1.0/24)');
            return;
        }

        // Show progress indicator
        $('.scan-progress').show();
        
        // Create search manager for scan
        var searchStr = '| nodeheim_scan subnet="' + subnet + '" scan_type="' + scanType.val() + '"';
        console.log('Search string:', searchStr);
        
        var scanSearch = new SearchManager({
            id: 'network_scan_search',
            preview: true,
            cache: false,
            search: searchStr,
            earliest_time: '-24h',
            latest_time: 'now'
        });

        // Handle search progress
        scanSearch.on('search:progress', function(properties) {
            console.log('Search progress:', properties);
            updateProgress(properties);
        });

        // Handle search error
        scanSearch.on('search:error', function(properties) {
            console.error('Search error:', properties);
            showError('Error during scan: ' + properties.message);
            $('.scan-progress').hide();
        });

        // Handle search completion
        scanSearch.on('search:done', function(properties) {
            console.log('Search completed:', properties);
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
        console.error('Error:', message);
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
        
        // Trigger a new search in all panels
        $('panel search').each(function() {
            var search = mvc.Components.get($(this).attr('id'));
            if (search) {
                search.startSearch();
            }
        });
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