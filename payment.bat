@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

:: 获取文件路径
set /p filepath=请输入文件路径（例如 C:\Path\To\Scripts\）： 

:: 检查文件路径是否存在
if not exist %filepath% (
    echo 文件路径不存在，请检查后重试。
    pause
    exit /b
)

:: 启动 CA.py
start "CA.py" python "%filepath%\CA.py"

:: 启动 cardholder.py
start "cardholder.py" python "%filepath%\cardholder.py"

:: 启动 marketer.py
start "marketer.py" python "%filepath%\marketer.py"

:: 启动 payment_Gateway.py
start "payment_Gateway.py" python "%filepath%\payment_Gateway.py"

:: 启动 bank.py
start "bank.py" python "%filepath%\bank.py"

pause
