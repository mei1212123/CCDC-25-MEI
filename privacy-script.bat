@echo off
:: https://privacy.sexy — v0.13.8 — Fri, 21 Mar 2025 15:28:57 GMT
:: Ensure PowerShell is available
where PowerShell >nul 2>&1 || (
    echo PowerShell is not available. Please install or enable PowerShell.
    pause & exit 1
)
:: Ensure admin privileges
fltmc >nul 2>&1 || (
    echo Administrator privileges are required.
    PowerShell Start -Verb RunAs '%0' 2> nul || (
        echo Right-click on the script and select "Run as administrator".
        pause & exit 1
    )
    exit 0
)
:: Initialize environment
setlocal EnableExtensions DisableDelayedExpansion


:: ----------------------------------------------------------
:: -------Enable strong Diffie-Hellman key requirement-------
:: ----------------------------------------------------------
echo --- Enable strong Diffie-Hellman key requirement
:: Require "Diffie-Hellman" key exchange algorithm to have at "2048" least bits keys for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman!ServerMinKeyBitLength"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman'; $data =  '2048'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' /v 'ServerMinKeyBitLength' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman!ClientMinKeyBitLength"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman'; $data =  '2048'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' /v 'ClientMinKeyBitLength' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Enable strong RSA key requirement (breaks Hyper-V VMs)--
:: ----------------------------------------------------------
echo --- Enable strong RSA key requirement (breaks Hyper-V VMs)
:: Require "PKCS" key exchange algorithm to have at "2048" least bits keys for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS!ServerMinKeyBitLength"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS'; $data =  '2048'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS' /v 'ServerMinKeyBitLength' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS!ClientMinKeyBitLength"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS'; $data =  '2048'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS' /v 'ClientMinKeyBitLength' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable insecure "RC2" ciphers--------------
:: ----------------------------------------------------------
echo --- Disable insecure "RC2" ciphers
:: Disable the use of "RC2 40/128" cipher algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Disable the use of "RC2 56/128" cipher algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Disable the use of "RC2 128/128" cipher algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable insecure "RC4" ciphers--------------
:: ----------------------------------------------------------
echo --- Disable insecure "RC4" ciphers
:: Disable the use of "RC4 128/128" cipher algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Disable the use of "RC4 64/128" cipher algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Disable the use of "RC4 56/128" cipher algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Disable the use of "RC4 40/128" cipher algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable insecure "DES" cipher---------------
:: ----------------------------------------------------------
echo --- Disable insecure "DES" cipher
:: Disable the use of "DES 56/56" cipher algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable insecure "Triple DES" cipher-----------
:: ----------------------------------------------------------
echo --- Disable insecure "Triple DES" cipher
:: Disable the use of "Triple DES 168" cipher algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Disable the use of "Triple DES 168/168" cipher algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable insecure "NULL" cipher--------------
:: ----------------------------------------------------------
echo --- Disable insecure "NULL" cipher
:: Disable the use of "NULL" cipher algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable insecure "MD5" hash----------------
:: ----------------------------------------------------------
echo --- Disable insecure "MD5" hash
:: Disable usage of "MD5" hash algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable insecure "SHA-1" hash---------------
:: ----------------------------------------------------------
echo --- Disable insecure "SHA-1" hash
:: Disable usage of "SHA" hash algorithm for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable insecure "SMBv1" protocol-------------
:: ----------------------------------------------------------
echo --- Disable insecure "SMBv1" protocol
:: Disable the "SMB1Protocol" feature
PowerShell -ExecutionPolicy Unrestricted -Command "$featureName = 'SMB1Protocol'; $feature = Get-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -ErrorAction Stop; if (-Not $feature) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is not found. No action required."^""; Exit 0; }; if ($feature.State -eq [Microsoft.Dism.Commands.FeatureState]::Disabled) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is already disabled. No action required."^""; Exit 0; }; try { Write-Host "^""Disabling feature: `"^""$featureName`"^""."^""; Disable-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -NoRestart -LogLevel ([Microsoft.Dism.Commands.LogLevel]::Errors) -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null; } catch { Write-Error "^""Failed to disable the feature `"^""$featureName`"^"": $($_.Exception.Message)"^""; Exit 1; }; Write-Output "^""Successfully disabled the feature `"^""$featureName`"^""."^""; Exit 0"
:: Disable the "SMB1Protocol-Client" feature
PowerShell -ExecutionPolicy Unrestricted -Command "$featureName = 'SMB1Protocol-Client'; $feature = Get-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -ErrorAction Stop; if (-Not $feature) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is not found. No action required."^""; Exit 0; }; if ($feature.State -eq [Microsoft.Dism.Commands.FeatureState]::Disabled) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is already disabled. No action required."^""; Exit 0; }; try { Write-Host "^""Disabling feature: `"^""$featureName`"^""."^""; Disable-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -NoRestart -LogLevel ([Microsoft.Dism.Commands.LogLevel]::Errors) -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null; } catch { Write-Error "^""Failed to disable the feature `"^""$featureName`"^"": $($_.Exception.Message)"^""; Exit 1; }; Write-Output "^""Successfully disabled the feature `"^""$featureName`"^""."^""; Exit 0"
:: Disable the "SMB1Protocol-Server" feature
PowerShell -ExecutionPolicy Unrestricted -Command "$featureName = 'SMB1Protocol-Server'; $feature = Get-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -ErrorAction Stop; if (-Not $feature) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is not found. No action required."^""; Exit 0; }; if ($feature.State -eq [Microsoft.Dism.Commands.FeatureState]::Disabled) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is already disabled. No action required."^""; Exit 0; }; try { Write-Host "^""Disabling feature: `"^""$featureName`"^""."^""; Disable-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -NoRestart -LogLevel ([Microsoft.Dism.Commands.LogLevel]::Errors) -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null; } catch { Write-Error "^""Failed to disable the feature `"^""$featureName`"^"": $($_.Exception.Message)"^""; Exit 1; }; Write-Output "^""Successfully disabled the feature `"^""$featureName`"^""."^""; Exit 0"
:: Disable service(s): `mrxsmb10`
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'mrxsmb10'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) { Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) { Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try { Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch { Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else { Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if (!$startupType) { $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) { $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if ($startupType -eq 'Disabled') { Write-Host "^""$serviceName is already disabled, no further action is needed"^""; Exit 0; }; <# -- 4. Disable service #>; try { Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch { Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"
sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters!SMBv1"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' /v 'SMBv1' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting computer for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart your computer.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable insecure "NetBios" protocol------------
:: ----------------------------------------------------------
echo --- Disable insecure "NetBios" protocol
PowerShell -ExecutionPolicy Unrestricted -Command "$key = 'HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces'; Get-ChildItem $key | ForEach { Set-ItemProperty -Path "^""$key\$($_.PSChildName)"^"" -Name NetbiosOptions -Value 2 -Verbose; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable insecure "SSL 2.0" protocol------------
:: ----------------------------------------------------------
echo --- Disable insecure "SSL 2.0" protocol
:: Disable usage of "SSL 2.0" protocol for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable insecure "SSL 3.0" protocol------------
:: ----------------------------------------------------------
echo --- Disable insecure "SSL 3.0" protocol
:: Disable usage of "SSL 3.0" protocol for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable insecure "TLS 1.0" protocol------------
:: ----------------------------------------------------------
echo --- Disable insecure "TLS 1.0" protocol
:: Disable usage of "TLS 1.0" protocol for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable insecure "TLS 1.1" protocol------------
:: ----------------------------------------------------------
echo --- Disable insecure "TLS 1.1" protocol
:: Disable usage of "TLS 1.1" protocol for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable insecure "DTLS 1.0" protocol-----------
:: ----------------------------------------------------------
echo --- Disable insecure "DTLS 1.0" protocol
:: Disable usage of "DTLS 1.0" protocol for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client!Enabled"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client!DisabledByDefault"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable insecure "LM & NTLM" protocols----------
:: ----------------------------------------------------------
echo --- Disable insecure "LM ^& NTLM" protocols
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\Lsa!LmCompatibilityLevel"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; $data =  '5'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v 'LmCompatibilityLevel' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable insecure renegotiation--------------
:: ----------------------------------------------------------
echo --- Disable insecure renegotiation
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL!AllowInsecureRenegoClients"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' /v 'AllowInsecureRenegoClients' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL!AllowInsecureRenegoServers"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' /v 'AllowInsecureRenegoServers' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL!DisableRenegoOnServer"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' /v 'DisableRenegoOnServer' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL!DisableRenegoOnClient"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' /v 'DisableRenegoOnClient' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL!UseScsvForTls"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' /v 'UseScsvForTls' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable insecure connections from .NET apps--------
:: ----------------------------------------------------------
echo --- Disable insecure connections from .NET apps
:: Configure "SchUseStrongCrypto" for .NET applications
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727!SchUseStrongCrypto"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727'; $data =  '1'; reg add 'HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' /v 'SchUseStrongCrypto' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727!SchUseStrongCrypto"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727'; $data =  '1'; reg add 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727' /v 'SchUseStrongCrypto' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319!SchUseStrongCrypto"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'; $data =  '1'; reg add 'HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' /v 'SchUseStrongCrypto' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319!SchUseStrongCrypto"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'; $data =  '1'; reg add 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' /v 'SchUseStrongCrypto' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Suggest restarting computer for changes to take effect
PowerShell -ExecutionPolicy Unrestricted -Command "$message = 'For the changes to fully take effect, please restart your computer.'; $warn =  $false; if ($warn) { Write-Warning "^""$message"^""; } else { Write-Host "^""Note: "^"" -ForegroundColor Blue -NoNewLine; Write-Output "^""$message"^""; }"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Enable secure "DTLS 1.2" protocol-------------
:: ----------------------------------------------------------
echo --- Enable secure "DTLS 1.2" protocol
:: Enable "DTLS 1.2" protocol as default for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Server!Enabled"
:: This operation will not run on Windows versions earlier than Windows10-1607.
PowerShell -ExecutionPolicy Unrestricted -Command "$versionName = 'Windows10-1607'; $buildNumber = switch ($versionName) { 'Windows11-FirstRelease' { '10.0.22000' }; 'Windows11-22H2' { '10.0.22621' }; 'Windows11-21H2' { '10.0.22000' }; 'Windows10-22H2' { '10.0.19045' }; 'Windows10-21H2' { '10.0.19044' }; 'Windows10-20H2' { '10.0.19042' }; 'Windows10-1909' { '10.0.18363' }; 'Windows10-1607' { '10.0.14393' }; default { throw "^""Internal privacy$([char]0x002E)sexy error: No build for minimum Windows '$versionName'"^""; }; }; $minVersion = [System.Version]::Parse($buildNumber); $ver = [Environment]::OSVersion.Version; $verNoPatch = [System.Version]::new($ver.Major, $ver.Minor, $ver.Build); if ($verNoPatch -lt $minVersion) { Write-Output "^""Skipping: Windows ($verNoPatch) is below minimum $minVersion ($versionName)"^""; Exit 0; }; $registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Server'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Server' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Server!DisabledByDefault"
:: This operation will not run on Windows versions earlier than Windows10-1607.
PowerShell -ExecutionPolicy Unrestricted -Command "$versionName = 'Windows10-1607'; $buildNumber = switch ($versionName) { 'Windows11-FirstRelease' { '10.0.22000' }; 'Windows11-22H2' { '10.0.22621' }; 'Windows11-21H2' { '10.0.22000' }; 'Windows10-22H2' { '10.0.19045' }; 'Windows10-21H2' { '10.0.19044' }; 'Windows10-20H2' { '10.0.19042' }; 'Windows10-1909' { '10.0.18363' }; 'Windows10-1607' { '10.0.14393' }; default { throw "^""Internal privacy$([char]0x002E)sexy error: No build for minimum Windows '$versionName'"^""; }; }; $minVersion = [System.Version]::Parse($buildNumber); $ver = [Environment]::OSVersion.Version; $verNoPatch = [System.Version]::new($ver.Major, $ver.Minor, $ver.Build); if ($verNoPatch -lt $minVersion) { Write-Output "^""Skipping: Windows ($verNoPatch) is below minimum $minVersion ($versionName)"^""; Exit 0; }; $registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Server'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Server' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Client!Enabled"
:: This operation will not run on Windows versions earlier than Windows10-1607.
PowerShell -ExecutionPolicy Unrestricted -Command "$versionName = 'Windows10-1607'; $buildNumber = switch ($versionName) { 'Windows11-FirstRelease' { '10.0.22000' }; 'Windows11-22H2' { '10.0.22621' }; 'Windows11-21H2' { '10.0.22000' }; 'Windows10-22H2' { '10.0.19045' }; 'Windows10-21H2' { '10.0.19044' }; 'Windows10-20H2' { '10.0.19042' }; 'Windows10-1909' { '10.0.18363' }; 'Windows10-1607' { '10.0.14393' }; default { throw "^""Internal privacy$([char]0x002E)sexy error: No build for minimum Windows '$versionName'"^""; }; }; $minVersion = [System.Version]::Parse($buildNumber); $ver = [Environment]::OSVersion.Version; $verNoPatch = [System.Version]::new($ver.Major, $ver.Minor, $ver.Build); if ($verNoPatch -lt $minVersion) { Write-Output "^""Skipping: Windows ($verNoPatch) is below minimum $minVersion ($versionName)"^""; Exit 0; }; $registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Client'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Client' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Client!DisabledByDefault"
:: This operation will not run on Windows versions earlier than Windows10-1607.
PowerShell -ExecutionPolicy Unrestricted -Command "$versionName = 'Windows10-1607'; $buildNumber = switch ($versionName) { 'Windows11-FirstRelease' { '10.0.22000' }; 'Windows11-22H2' { '10.0.22621' }; 'Windows11-21H2' { '10.0.22000' }; 'Windows10-22H2' { '10.0.19045' }; 'Windows10-21H2' { '10.0.19044' }; 'Windows10-20H2' { '10.0.19042' }; 'Windows10-1909' { '10.0.18363' }; 'Windows10-1607' { '10.0.14393' }; default { throw "^""Internal privacy$([char]0x002E)sexy error: No build for minimum Windows '$versionName'"^""; }; }; $minVersion = [System.Version]::Parse($buildNumber); $ver = [Environment]::OSVersion.Version; $verNoPatch = [System.Version]::new($ver.Major, $ver.Minor, $ver.Build); if ($verNoPatch -lt $minVersion) { Write-Output "^""Skipping: Windows ($verNoPatch) is below minimum $minVersion ($versionName)"^""; Exit 0; }; $registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Client'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Client' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Enable secure "TLS 1.3" protocol-------------
:: ----------------------------------------------------------
echo --- Enable secure "TLS 1.3" protocol
:: Enable "TLS 1.3" protocol as default for TLS/SSL connections
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server!Enabled"
:: This operation will not run on Windows versions earlier than Windows11-FirstRelease.
PowerShell -ExecutionPolicy Unrestricted -Command "$versionName = 'Windows11-FirstRelease'; $buildNumber = switch ($versionName) { 'Windows11-FirstRelease' { '10.0.22000' }; 'Windows11-22H2' { '10.0.22621' }; 'Windows11-21H2' { '10.0.22000' }; 'Windows10-22H2' { '10.0.19045' }; 'Windows10-21H2' { '10.0.19044' }; 'Windows10-20H2' { '10.0.19042' }; 'Windows10-1909' { '10.0.18363' }; 'Windows10-1607' { '10.0.14393' }; default { throw "^""Internal privacy$([char]0x002E)sexy error: No build for minimum Windows '$versionName'"^""; }; }; $minVersion = [System.Version]::Parse($buildNumber); $ver = [Environment]::OSVersion.Version; $verNoPatch = [System.Version]::new($ver.Major, $ver.Minor, $ver.Build); if ($verNoPatch -lt $minVersion) { Write-Output "^""Skipping: Windows ($verNoPatch) is below minimum $minVersion ($versionName)"^""; Exit 0; }; $registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server!DisabledByDefault"
:: This operation will not run on Windows versions earlier than Windows11-FirstRelease.
PowerShell -ExecutionPolicy Unrestricted -Command "$versionName = 'Windows11-FirstRelease'; $buildNumber = switch ($versionName) { 'Windows11-FirstRelease' { '10.0.22000' }; 'Windows11-22H2' { '10.0.22621' }; 'Windows11-21H2' { '10.0.22000' }; 'Windows10-22H2' { '10.0.19045' }; 'Windows10-21H2' { '10.0.19044' }; 'Windows10-20H2' { '10.0.19042' }; 'Windows10-1909' { '10.0.18363' }; 'Windows10-1607' { '10.0.14393' }; default { throw "^""Internal privacy$([char]0x002E)sexy error: No build for minimum Windows '$versionName'"^""; }; }; $minVersion = [System.Version]::Parse($buildNumber); $ver = [Environment]::OSVersion.Version; $verNoPatch = [System.Version]::new($ver.Major, $ver.Minor, $ver.Build); if ($verNoPatch -lt $minVersion) { Write-Output "^""Skipping: Windows ($verNoPatch) is below minimum $minVersion ($versionName)"^""; Exit 0; }; $registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client!Enabled"
:: This operation will not run on Windows versions earlier than Windows11-FirstRelease.
PowerShell -ExecutionPolicy Unrestricted -Command "$versionName = 'Windows11-FirstRelease'; $buildNumber = switch ($versionName) { 'Windows11-FirstRelease' { '10.0.22000' }; 'Windows11-22H2' { '10.0.22621' }; 'Windows11-21H2' { '10.0.22000' }; 'Windows10-22H2' { '10.0.19045' }; 'Windows10-21H2' { '10.0.19044' }; 'Windows10-20H2' { '10.0.19042' }; 'Windows10-1909' { '10.0.18363' }; 'Windows10-1607' { '10.0.14393' }; default { throw "^""Internal privacy$([char]0x002E)sexy error: No build for minimum Windows '$versionName'"^""; }; }; $minVersion = [System.Version]::Parse($buildNumber); $ver = [Environment]::OSVersion.Version; $verNoPatch = [System.Version]::new($ver.Major, $ver.Minor, $ver.Build); if ($verNoPatch -lt $minVersion) { Write-Output "^""Skipping: Windows ($verNoPatch) is below minimum $minVersion ($versionName)"^""; Exit 0; }; $registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' /v 'Enabled' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client!DisabledByDefault"
:: This operation will not run on Windows versions earlier than Windows11-FirstRelease.
PowerShell -ExecutionPolicy Unrestricted -Command "$versionName = 'Windows11-FirstRelease'; $buildNumber = switch ($versionName) { 'Windows11-FirstRelease' { '10.0.22000' }; 'Windows11-22H2' { '10.0.22621' }; 'Windows11-21H2' { '10.0.22000' }; 'Windows10-22H2' { '10.0.19045' }; 'Windows10-21H2' { '10.0.19044' }; 'Windows10-20H2' { '10.0.19042' }; 'Windows10-1909' { '10.0.18363' }; 'Windows10-1607' { '10.0.14393' }; default { throw "^""Internal privacy$([char]0x002E)sexy error: No build for minimum Windows '$versionName'"^""; }; }; $minVersion = [System.Version]::Parse($buildNumber); $ver = [Environment]::OSVersion.Version; $verNoPatch = [System.Version]::new($ver.Major, $ver.Minor, $ver.Build); if ($verNoPatch -lt $minVersion) { Write-Output "^""Skipping: Windows ($verNoPatch) is below minimum $minVersion ($versionName)"^""; Exit 0; }; $registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' /v 'DisabledByDefault' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Enable secure connections for legacy .NET apps------
:: ----------------------------------------------------------
echo --- Enable secure connections for legacy .NET apps
:: Configure "SystemDefaultTlsVersions" for .NET applications
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727!SystemDefaultTlsVersions"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727'; $data =  '1'; reg add 'HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' /v 'SystemDefaultTlsVersions' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727!SystemDefaultTlsVersions"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727'; $data =  '1'; reg add 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727' /v 'SystemDefaultTlsVersions' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319!SystemDefaultTlsVersions"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'; $data =  '1'; reg add 'HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' /v 'SystemDefaultTlsVersions' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319!SystemDefaultTlsVersions"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'; $data =  '1'; reg add 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' /v 'SystemDefaultTlsVersions' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable basic authentication in WinRM-----------
:: ----------------------------------------------------------
echo --- Disable basic authentication in WinRM
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client!AllowBasic"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' /v 'AllowBasic' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Disable unauthorized user account discovery (anonymous SAM enumeration)
echo --- Disable unauthorized user account discovery (anonymous SAM enumeration)
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\Lsa!restrictanonymoussam"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v 'restrictanonymoussam' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable anonymous access to named pipes and shares----
:: ----------------------------------------------------------
echo --- Disable anonymous access to named pipes and shares
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters!restrictnullsessaccess"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' /v 'restrictnullsessaccess' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: Disable hidden remote file access via administrative shares (breaks remote system management software)
echo --- Disable hidden remote file access via administrative shares (breaks remote system management software)
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters!AutoShareWks"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' /v 'AutoShareWks' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable anonymous enumeration of shares----------
:: ----------------------------------------------------------
echo --- Disable anonymous enumeration of shares
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\LSA!restrictanonymous"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\LSA'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\LSA' /v 'restrictanonymous' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable "Telnet Client" feature--------------
:: ----------------------------------------------------------
echo --- Disable "Telnet Client" feature
:: Disable the "TelnetClient" feature
PowerShell -ExecutionPolicy Unrestricted -Command "$featureName = 'TelnetClient'; $feature = Get-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -ErrorAction Stop; if (-Not $feature) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is not found. No action required."^""; Exit 0; }; if ($feature.State -eq [Microsoft.Dism.Commands.FeatureState]::Disabled) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is already disabled. No action required."^""; Exit 0; }; try { Write-Host "^""Disabling feature: `"^""$featureName`"^""."^""; Disable-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -NoRestart -LogLevel ([Microsoft.Dism.Commands.LogLevel]::Errors) -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null; } catch { Write-Error "^""Failed to disable the feature `"^""$featureName`"^"": $($_.Exception.Message)"^""; Exit 1; }; Write-Output "^""Successfully disabled the feature `"^""$featureName`"^""."^""; Exit 0"
:: ----------------------------------------------------------


:: Remove "RAS Connection Manager Administration Kit (CMAK)" capability
echo --- Remove "RAS Connection Manager Administration Kit (CMAK)" capability
PowerShell -ExecutionPolicy Unrestricted -Command "Get-WindowsCapability -Online -Name 'RasCMAK.Client*' | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Windows Remote Assistance feature---------
:: ----------------------------------------------------------
echo --- Disable Windows Remote Assistance feature
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance!fAllowToGetHelp"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance' /v 'fAllowToGetHelp' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance!fAllowFullControl"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance' /v 'fAllowFullControl' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services!AllowBasic"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' /v 'AllowBasic' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable "Net.TCP Port Sharing" feature----------
:: ----------------------------------------------------------
echo --- Disable "Net.TCP Port Sharing" feature
:: Disable the "WCF-TCP-PortSharing45" feature
PowerShell -ExecutionPolicy Unrestricted -Command "$featureName = 'WCF-TCP-PortSharing45'; $feature = Get-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -ErrorAction Stop; if (-Not $feature) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is not found. No action required."^""; Exit 0; }; if ($feature.State -eq [Microsoft.Dism.Commands.FeatureState]::Disabled) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is already disabled. No action required."^""; Exit 0; }; try { Write-Host "^""Disabling feature: `"^""$featureName`"^""."^""; Disable-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -NoRestart -LogLevel ([Microsoft.Dism.Commands.LogLevel]::Errors) -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null; } catch { Write-Error "^""Failed to disable the feature `"^""$featureName`"^"": $($_.Exception.Message)"^""; Exit 1; }; Write-Output "^""Successfully disabled the feature `"^""$featureName`"^""."^""; Exit 0"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable "SMB Direct" feature---------------
:: ----------------------------------------------------------
echo --- Disable "SMB Direct" feature
:: Disable the "SmbDirect" feature
PowerShell -ExecutionPolicy Unrestricted -Command "$featureName = 'SmbDirect'; $feature = Get-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -ErrorAction Stop; if (-Not $feature) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is not found. No action required."^""; Exit 0; }; if ($feature.State -eq [Microsoft.Dism.Commands.FeatureState]::Disabled) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is already disabled. No action required."^""; Exit 0; }; try { Write-Host "^""Disabling feature: `"^""$featureName`"^""."^""; Disable-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -NoRestart -LogLevel ([Microsoft.Dism.Commands.LogLevel]::Errors) -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null; } catch { Write-Error "^""Failed to disable the feature `"^""$featureName`"^"": $($_.Exception.Message)"^""; Exit 1; }; Write-Output "^""Successfully disabled the feature `"^""$featureName`"^""."^""; Exit 0"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable "TFTP Client" feature---------------
:: ----------------------------------------------------------
echo --- Disable "TFTP Client" feature
:: Disable the "TFTP" feature
PowerShell -ExecutionPolicy Unrestricted -Command "$featureName = 'TFTP'; $feature = Get-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -ErrorAction Stop; if (-Not $feature) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is not found. No action required."^""; Exit 0; }; if ($feature.State -eq [Microsoft.Dism.Commands.FeatureState]::Disabled) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is already disabled. No action required."^""; Exit 0; }; try { Write-Host "^""Disabling feature: `"^""$featureName`"^""."^""; Disable-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -NoRestart -LogLevel ([Microsoft.Dism.Commands.LogLevel]::Errors) -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null; } catch { Write-Error "^""Failed to disable the feature `"^""$featureName`"^"": $($_.Exception.Message)"^""; Exit 1; }; Write-Output "^""Successfully disabled the feature `"^""$featureName`"^""."^""; Exit 0"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Remove "RIP Listener" capability-------------
:: ----------------------------------------------------------
echo --- Remove "RIP Listener" capability
PowerShell -ExecutionPolicy Unrestricted -Command "Get-WindowsCapability -Online -Name 'RIP.Listener*' | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: Remove "Simple Network Management Protocol (SNMP)" capability
echo --- Remove "Simple Network Management Protocol (SNMP)" capability
PowerShell -ExecutionPolicy Unrestricted -Command "Get-WindowsCapability -Online -Name 'SNMP.Client*' | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Remove "SNMP WMI Provider" capability-----------
:: ----------------------------------------------------------
echo --- Remove "SNMP WMI Provider" capability
PowerShell -ExecutionPolicy Unrestricted -Command "Get-WindowsCapability -Online -Name 'WMI-SNMP-Provider.Client*' | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: Mitigate Spectre Variant 2 and Meltdown in host operating system
echo --- Mitigate Spectre Variant 2 and Meltdown in host operating system
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management!FeatureSettingsOverrideMask"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'; $data =  '3'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' /v 'FeatureSettingsOverrideMask' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management!FeatureSettingsOverride"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'; $data =  '0'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' /v 'FeatureSettingsOverride' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management!FeatureSettingsOverride"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'; $data =  '64'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' /v 'FeatureSettingsOverride' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Mitigate Spectre Variant 2 and Meltdown in Hyper-V----
:: ----------------------------------------------------------
echo --- Mitigate Spectre Variant 2 and Meltdown in Hyper-V
:: Set the registry value: "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization!MinVmVersionForCpuBasedMitigations"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization'; $data =  '1.0'; reg add 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization' /v 'MinVmVersionForCpuBasedMitigations' /t 'REG_SZ' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Enable Data Execution Prevention (DEP)----------
:: ----------------------------------------------------------
echo --- Enable Data Execution Prevention (DEP)
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer!NoDataExecutionPrevention"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v 'NoDataExecutionPrevention' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: Set the registry value: "HKLM\SOFTWARE\Policies\Microsoft\Windows\System!DisableHHDEP"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v 'DisableHHDEP' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable storage of the LAN Manager password hashes----
:: ----------------------------------------------------------
echo --- Disable storage of the LAN Manager password hashes
:: Set the registry value: "HKLM\SYSTEM\CurrentControlSet\Control\Lsa!NoLMHash"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; $data =  '1'; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v 'NoLMHash' /t 'REG_DWORD' /d "^""$data"^"" /f"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -Enable security against PowerShell 2.0 downgrade attacks-
:: ----------------------------------------------------------
echo --- Enable security against PowerShell 2.0 downgrade attacks
:: Disable the "MicrosoftWindowsPowerShellV2" feature
PowerShell -ExecutionPolicy Unrestricted -Command "$featureName = 'MicrosoftWindowsPowerShellV2'; $feature = Get-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -ErrorAction Stop; if (-Not $feature) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is not found. No action required."^""; Exit 0; }; if ($feature.State -eq [Microsoft.Dism.Commands.FeatureState]::Disabled) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is already disabled. No action required."^""; Exit 0; }; try { Write-Host "^""Disabling feature: `"^""$featureName`"^""."^""; Disable-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -NoRestart -LogLevel ([Microsoft.Dism.Commands.LogLevel]::Errors) -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null; } catch { Write-Error "^""Failed to disable the feature `"^""$featureName`"^"": $($_.Exception.Message)"^""; Exit 1; }; Write-Output "^""Successfully disabled the feature `"^""$featureName`"^""."^""; Exit 0"
:: Disable the "MicrosoftWindowsPowerShellV2Root" feature
PowerShell -ExecutionPolicy Unrestricted -Command "$featureName = 'MicrosoftWindowsPowerShellV2Root'; $feature = Get-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -ErrorAction Stop; if (-Not $feature) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is not found. No action required."^""; Exit 0; }; if ($feature.State -eq [Microsoft.Dism.Commands.FeatureState]::Disabled) { Write-Output "^""Skipping: The feature `"^""$featureName`"^"" is already disabled. No action required."^""; Exit 0; }; try { Write-Host "^""Disabling feature: `"^""$featureName`"^""."^""; Disable-WindowsOptionalFeature -FeatureName "^""$featureName"^"" -Online -NoRestart -LogLevel ([Microsoft.Dism.Commands.LogLevel]::Errors) -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null; } catch { Write-Error "^""Failed to disable the feature `"^""$featureName`"^"": $($_.Exception.Message)"^""; Exit 1; }; Write-Output "^""Successfully disabled the feature `"^""$featureName`"^""."^""; Exit 0"
:: ----------------------------------------------------------


:: Pause the script to view the final state
pause
:: Restore previous environment settings
endlocal
:: Exit the script successfully
exit /b 0