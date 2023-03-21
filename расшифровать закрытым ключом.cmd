@echo off
chcp 65001
echo "Расшифруем..."
"RSA cipher.exe" -d %1 key.pem
pause
