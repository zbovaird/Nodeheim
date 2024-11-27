# Clean up any existing package
Remove-Item -Path "nodeheim-splunk.tar.gz" -ErrorAction SilentlyContinue

# Create package
tar -czf nodeheim-splunk.tar.gz `
    --exclude="*.pyc" `
    --exclude="__pycache__" `
    --exclude=".git" `
    --exclude=".env" `
    --exclude="*.ps1" `
    --exclude="setup.py" `
    --exclude="nodeheim-splunk.tar.gz" `
    bin/ default/ appserver/ 