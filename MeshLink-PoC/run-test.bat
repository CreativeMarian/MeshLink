@echo off
rem ============================================================
rem  M0-4R DirectLink friend-mode launcher.
rem  NOTE: keep this file ASCII-only. cmd parses batch files with
rem  the ANSI codepage (GBK on zh-CN); UTF-8 Chinese here becomes
rem  mojibake commands. All logic/UI lives in run-test.ps1
rem  (saved as UTF-8 with BOM, which Windows PowerShell reads correctly).
rem ============================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run-test.ps1"
