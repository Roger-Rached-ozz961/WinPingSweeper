start powershell.exe -NoExit -ExecutionPolicy Bypass -Command "$env:TERM='xterm-256color'; & '%~dp0WinPingSweeper-env\Scripts\Activate.ps1'; python '%~dp0WinPingSweeper.py'"
