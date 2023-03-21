@echo off
chcp 65001
echo "Шифруем..."
"RSA cipher.exe" -e %1 public-key.pem
pause
