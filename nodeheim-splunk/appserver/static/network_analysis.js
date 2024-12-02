require([
    'jquery',
    'underscore',
    'splunkjs/mvc',
    'splunkjs/mvc/searchmanager',
    'splunkjs/mvc/simplexml/ready!'
], function($, _, mvc, SearchManager) {
    'use strict';
    
    // Use jQuery 3.5+ safe selectors
    $(function() {
        // Initialize any custom JavaScript functionality here
        console.log('Network Analysis Dashboard loaded');
        
        // Example of jQuery 3.5+ safe event handling
        $('.dashboard-panel').on('click', function(e) {
            var $panel = $(e.currentTarget);
            console.log('Panel clicked:', $panel.find('.panel-title').text());
        });
    });
}); 