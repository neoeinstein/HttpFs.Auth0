@echo off
cls

IF NOT EXIST .paket\paket.exe (
  .paket\paket.bootstrapper.exe
  if errorlevel 1 (
    exit /b %errorlevel%
  )
)

.paket\paket.exe restore
if errorlevel 1 (
  exit /b %errorlevel%
)

packages\build\FAKE\tools\FAKE.exe build.fsx %*
