require([
    "splunkjs/mvc",
    "splunkjs/mvc/searchmanager",
    "splunkjs/mvc/utils",
    "jquery"
], function(mvc, SearchManager, utils, $) {
    
    // Get references to form inputs
    const subnet = mvc.Components.get("subnet");
    const scanType = mvc.Components.get("scan_type");
    
    // Initialize search managers
    let scanSearch = null;
    
    // Handle Start Scan button
    $("#start-scan").on("click", function() {
        const subnetValue = subnet.val();
        const scanTypeValue = scanType.val();
        
        // Create and run the scan search
        scanSearch = new SearchManager({
            id: "network_scan_search",
            preview: true,
            cache: false,
            search: `| nodeheim_scan ${subnetValue} ${scanTypeValue}`,
            earliest_time: "-15m",
            latest_time: "now"
        });
        
        // Update UI to show scan is running
        $(this).prop("disabled", true);
        $("#stop-scan").show();
        $(".scan-status").text("Scan in progress...").show();
        
        // Handle search completion
        scanSearch.on("search:done", function(properties) {
            if (properties.content.resultCount > 0) {
                // Update metrics
                updateNetworkMetrics();
                // Run analysis
                runNetworkAnalysis();
            }
            
            // Reset UI
            $("#start-scan").prop("disabled", false);
            $("#stop-scan").hide();
            $(".scan-status").text("Scan completed").fadeOut(2000);
        });
    });
    
    // Function to update network metrics
    function updateNetworkMetrics() {
        const metricsSearch = new SearchManager({
            id: "metrics_search",
            preview: false,
            cache: false,
            search: `| nodeheim_scan ${subnet.val()} ${scanType.val()} 
                    | stats 
                        count(eval(status="up")) as active_hosts
                        count as total_hosts
                        sum(eval(len(ports))) as total_ports
                        sum(eval(len(services))) as total_services`,
            earliest_time: "-15m",
            latest_time: "now"
        });
        
        metricsSearch.on("search:done", function() {
            const results = metricsSearch.data("results");
            if (results && results.length > 0) {
                const data = results.at(0);
                $("#total-hosts").text(data.get("total_hosts"));
                $("#active-hosts").text(data.get("active_hosts"));
                $("#total-ports").text(data.get("total_ports"));
                $("#total-services").text(data.get("total_services"));
            }
        });
    }
    
    // Function to run network analysis
    function runNetworkAnalysis() {
        const analysisSearch = new SearchManager({
            id: "analysis_search",
            preview: false,
            cache: false,
            search: `| nodeheim_scan ${subnet.val()} ${scanType.val()} | nodeheim_analyze`,
            earliest_time: "-15m",
            latest_time: "now"
        });
        
        analysisSearch.on("search:done", function() {
            updateStructureMetrics();
            updateSecurityMetrics();
            updateTopologyVisualization();
        });
    }
    
    // Function to update structure metrics
    function updateStructureMetrics() {
        const structureSearch = new SearchManager({
            id: "structure_search",
            preview: false,
            cache: false,
            search: `| nodeheim_scan ${subnet.val()} ${scanType.val()} 
                    | nodeheim_analyze 
                    | spath input=network_structure`,
            earliest_time: "-15m",
            latest_time: "now"
        });
        
        structureSearch.on("search:done", function() {
            const results = structureSearch.data("results");
            if (results && results.length > 0) {
                const data = results.at(0);
                const metrics = {
                    "Components": data.get("components"),
                    "Density": data.get("density"),
                    "Diameter": data.get("diameter"),
                    "Connected": data.get("is_connected") ? "Yes" : "No"
                };
                
                let html = "";
                for (const [key, value] of Object.entries(metrics)) {
                    html += `
                        <div class="metric-item">
                            <span class="metric-label">${key}</span>
                            <span class="metric-value">${value}</span>
                        </div>
                    `;
                }
                $("#structure-metrics").html(html);
            }
        });
    }
    
    // Initialize the dashboard
    updateNetworkMetrics();
});
