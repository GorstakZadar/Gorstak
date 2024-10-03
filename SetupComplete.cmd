@Echo Off
Title GSecurity && Color 0b

:: Elevation
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Move to the script directory
pushd %~dp0

:: Execute msi files alphabetically
for /f "tokens=*" %%A in ('dir /b /o:n *.msi') do (
    msiexec /i "%%A" /quiet /norestart
)

:: SC
sc config SharedAccess start= auto
sc config RemoteRegistry start= auto
sc config gpsvc start= auto
sc config winmgmt start= auto
net start SharedAccess
net start RemoteRegistry
net start gpsvc
net start winmgmt

:: Registry
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess" /v "Start" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry" /v "Start" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\gpsvc" /v "Start" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\winmgmt" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "DisableUnicastResponsesToMulticastBroadcast" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile" /v "DisableUnicastResponsesToMulticastBroadcast" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "DisableUnicastResponsesToMulticastBroadcast" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "DisableUnicastResponsesToMulticastBroadcast" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "Block-All-In" /t REG_SZ /d "v2.33|Action=Block|Active=TRUE|Dir=In|Name=Block all|LUAuth=O:LSD:(D;;CC;;;S-1-5-80-2940520708-3855866260-481812779-327648279-1710889582)|" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "Block-All-Out" /t REG_SZ /d "v2.33|Action=Block|Active=TRUE|Dir=Out|Name=Block all|LUAuth=O:LSD:(D;;CC;;;S-1-5-80-859482183-879914841-863379149-1145462774-2388618682)(D;;CC;;;S-1-5-80-2940520708-3855866260-481812779-327648279-1710889582)(D;;CC;;;AC)|" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "Block-TCP-In" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort2_10=1-1000|Name=Block incoming TCP|LUAuth=O:LSD:(D;;CC;;;S-1-5-80-2940520708-3855866260-481812779-327648279-1710889582)|" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "Block-TCP-Out" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=Out|Protocol=6|LPort2_10=1-1000|Name=Block outgoing TCP|LUAuth=O:LSD:(D;;CC;;;S-1-5-80-859482183-879914841-863379149-1145462774-2388618682)(D;;CC;;;S-1-5-80-2940520708-3855866260-481812779-327648279-1710889582)|" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "Block-UDP-Out" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=Out|Protocol=17|LPort2_10=1-1000|Name=Block outgoing UDP|LUAuth=O:LSD:(D;;CC;;;S-1-5-80-859482183-879914841-863379149-1145462774-2388618682)(D;;CC;;;S-1-5-80-2940520708-3855866260-481812779-327648279-1710889582)|" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "Block-UDP-In" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort2_10=1-1000|Name=Block incoming UDP|LUAuth=O:LSD:(D;;CC;;;S-1-5-80-2940520708-3855866260-481812779-327648279-1710889582)|" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "Block-Winlogon-In" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=In|App=%%SystemRoot%%\System32\winlogon.exe|Name=winlogon|" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "Block-LogonUI-Out" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=In|App=%%SystemRoot%%\System32\LogonUI.exe|Name=logonui|" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "Block-Winlogon-Out" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=Out|App=%%SystemRoot%%\System32\winlogon.exe|Name=winlogon|" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "Block-LogonUI-In" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=Out|App=%%SystemRoot%%\System32\LogonUI.exe|Name=logonui|" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "RemoteDesktop-Shadow-In-TCP" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=In|Protocol=6|App=%%SystemRoot%%\system32\RdpSa.exe|Name=@FirewallAPI.dll,-28778|Desc=@FirewallAPI.dll,-28779|EmbedCtxt=@FirewallAPI.dll,-28752|Edge=TRUE|Defer=App|" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "RemoteDesktop-UserMode-In-TCP" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=3389|App=%%SystemRoot%%\system32\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-28775|Desc=@FirewallAPI.dll,-28756|EmbedCtxt=@FirewallAPI.dll,-28752|" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "RemoteDesktop-UserMode-In-UDP" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort=3389|App=%%SystemRoot%%\system32\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-28776|Desc=@FirewallAPI.dll,-28777|EmbedCtxt=@FirewallAPI.dll,-28752|" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "Block-windeploy-In" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=In|App=%%SystemRoot%%\System32\oobe\windeploy.exe|Name=windeploy.exe Block Inbound|" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "Block-windeploy-Out" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=Out|App=%%SystemRoot%%\System32\oobe\windeploy.exe|Name=windeploy.exe Block Outbound|" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "Block-ftp-In" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=In|App=%%SystemRoot%%\System32\ftp.exe|Name=ftp.exe Block Inbound|" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "Block-ftp-Out" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=Out|App=%%SystemRoot%%\System32\ftp.exe|Name=ftp.exe Block Outbound|" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "Block-Explorer-Out" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=Out|App=%%SystemRoot%%\explorer.exe|Name=explorer|" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "Block-Explorer-In" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=In|App=%%SystemRoot%%\explorer.exe|Name=explorer|" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg" /v "RemoteRegAccess" /t REG_DWORD /d "1" /f
