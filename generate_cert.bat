@echo off
set OPENSSL_EXE=C:\Program Files\OpenSSL-Win64\bin\openssl.exe

if not exist "%OPENSSL_EXE%" (
    echo =========================================
    echo   ❌ OpenSSL no encontrado en:
    echo   C:\OpenSSL-Win64\bin\openssl.exe
    echo   Verifica que instalaste Win64OpenSSL.
    echo =========================================
    pause
    exit /b
)

echo ===== GENERANDO CLAVE PRIVADA =====
"%OPENSSL_EXE%" genrsa -out server.key 2048

echo ===== GENERANDO CERTIFICADO AUTOFIRMADO =====
"%OPENSSL_EXE%" req -new -x509 -key server.key -out server.cert -days 3650 -subj "/CN=localhost"

echo.
echo =============================================
echo   ✔ Certificados generados correctamente
echo   → server.key
echo   → server.cert
echo =============================================
pause
