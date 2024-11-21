@echo off
echo Adding Firewall Rule for Nodeheim...
netsh advfirewall firewall add rule name="Nodeheim Server" dir=in action=allow protocol=TCP localport=5050
netsh advfirewall firewall add rule name="Nodeheim Server" dir=out action=allow protocol=TCP localport=5050
echo Firewall rules added.
pause 