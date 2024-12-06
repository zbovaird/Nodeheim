# Set version and app name
$VERSION = "1.0.0"
$APP_NAME = "nodeheim"

# Clean up any existing packages
Remove-Item -Force "${APP_NAME}-${VERSION}.tar.gz" -ErrorAction SilentlyContinue
Remove-Item -Force "${APP_NAME}-${VERSION}.spl" -ErrorAction SilentlyContinue

# Create a clean staging directory
$STAGING_DIR = "staging/${APP_NAME}"
Remove-Item -Recurse -Force staging -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $STAGING_DIR | Out-Null

# Copy required files and directories
Copy-Item -Recurse bin $STAGING_DIR
Copy-Item -Recurse default $STAGING_DIR
Copy-Item -Recurse appserver $STAGING_DIR

# Create the app manifest
$manifest = @{
    schemaVersion = "2.0.0"
    info = @{
        title = "Nodeheim Network Analysis"
        id = @{
            group = $null
            name = "nodeheim"
            version = $VERSION
        }
        author = @(
            @{
                name = "Your Name"
                email = "your.email@example.com"
                company = "Your Company"
            }
        )
        releaseDate = $null
        description = "Network scanning and analysis tool for Splunk"
        classification = @{
            intendedAudience = $null
            categories = @("Security", "Network Monitoring")
            developmentStatus = "Production"
        }
    }
    dependencies = @{
        splunk = @{
            version = "8.0"
        }
    }
    tasks = @()
    inputGroups = @{}
    incompatibleApps = @{}
    platformRequirements = @{
        splunk = @{
            Enterprise = "*"
        }
    }
}

$manifest | ConvertTo-Json -Depth 10 | Set-Content "$STAGING_DIR/app.manifest"

# Create README
@"
Nodeheim Network Analysis App for Splunk
Version $VERSION

This app provides network scanning and analysis capabilities for Splunk Enterprise.

Requirements:
- Splunk Enterprise 8.0 or later
- Python 3.7 or later
- Required Python packages (installed automatically):
  - splunk-sdk
  - networkx
  - matplotlib
  - numpy

Installation:
1. Install via Splunk Web:
   - Navigate to Apps > Manage Apps
   - Click "Install app from file"
   - Upload this .spl file
   - Restart Splunk

2. Manual Installation:
   - Extract this .spl file to `$SPLUNK_HOME/etc/apps/
   - Restart Splunk

Configuration:
No additional configuration required.

Support:
For support, please contact your.email@example.com
"@ | Set-Content "$STAGING_DIR/README.txt"

# Create the package (using 7-Zip for better compatibility)
$env:PATH = "$env:PATH;C:\Program Files\7-Zip"
Set-Location staging
& 7z a -ttar "${APP_NAME}.tar" $APP_NAME
& 7z a -tgzip "../${APP_NAME}-${VERSION}.spl" "${APP_NAME}.tar"
Set-Location ..

# Clean up
Remove-Item -Recurse -Force staging

Write-Host "Package created: ${APP_NAME}-${VERSION}.spl"