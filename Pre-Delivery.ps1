
#PowerShell disabling Standby
    powercfg -change -standby-timeout-ac 0    
    $powercfgList = powercfg.exe /query;
    $sleepAfter = 'Disabled';for($i = 0; $i -lt $powercfgList.Count; $i++){if($powercfgList[$i] -match 'Sleep after'){Write-Host 'Found sleep after item';for($j = $i; $j -lt ($i + 20); $j++){if([String]::IsNullOrWhiteSpace($powercfgList[$j])){Write-Host 'Found blank line';break}if($powercfgList[$j] -match 'Current AC Power Setting Index:'){Write-Host 'Found Sleep AC Power Setting';$currentSetting = $($powercfgList[$j] -replace 'Current AC Power Setting Index: ','').Trim();Write-Host 'Current Setting: $currentSetting';if($currentSetting -ne '0x00000000'){$sleepAfter = 'Enabled'}break}}}};(Write-Host "SleepAfter is $sleepAfter")

#New Account Adding:
## $Clientcode = @EDF HERE@
    Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True'"| Where-Object {$_.Disabled -match 'False'} | Select-Object -ExpandProperty name
    net user wcsadmin "@clientcode@Wc5dAlly" /add /Y
    net user wcsadmin /fullname:"WCS Local System Admin" /comment:"Wallis Computer Solutions Local Computer Administrator Account"
    WMIC USERACCOUNT WHERE Name="wcsadmin" SET PasswordExpires=FALSE
    net localgroup administrators wcsadmin /add
    if ($null -eq (net localgroup administrators|select -skip 6|?{$_ -like '*wcsadmin*'})){0}else{1}

#Update Computer Description
##### Need Reg Key Name here
    Set-ItemProperty -Path "HKLM\System\CurrentControlSet\Services\lanmanserver\parameters\srvcomment" -Name "$RegKeyName" -Value @computerDescription@

#Setting TimeZone
###Global Variable here
    tzutil /g
    tzutil /s "@TimeZone@"

#Setting Time Server
    w32tm /config /computer:%computername% /manualpeerlist:"au.pool.ntp.org pool.ntp.org " /syncfromflags:manual /update
    w32tm /resync
    $TestingTimeServer = w32tm /query /peers | find "Peer:"

# Setting Windows Updates to receive other products with Microsoft updates
##### Need Reg Key Name here
    $ServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager"; $ServiceManager.ClientApplicationID = "My App"; $ServiceManager.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"")
    $ServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager"; $ServiceManager.ClientApplicationID = "My App"; $ServiceManager.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"")
    Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\EnableFeaturedSoftware" -Name "$RegKeyName" -Value '1'
    Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\IncludeRecommendedUpdates" -Name "$RegKeyName" -Value '1'

#Rename Windows Machine
    #WCS - Pre Delivery - Windows - Rename Machine
    #https://proval.itglue.com/5078775/docs/8175270

#Rename System Partition
    $Drivename =Get-WmiObject -Class win32_logicaldisk|?{$_.DeviceId -eq 'C:'}|select -ExpandProperty volumename
    Write-Host "$Drivename-OS"
    powershell.exe -ExecutionPolicy Bypass -Command "label C: $env:Computername-OS"
    IF ($Drivename -contains $env:Computername) {Write-host "Renamed System Partition successfully."}


# Getting Windows completely updated
    Set-ExecutionPolicy Unrestricted -Scope Process -Force
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
    Install-Package Nuget -Force | Out-Null
    Install-Module PSWindowsupdate -Force | Out-Null
    $obj = @{}
    $theseupdates = Get-WindowsUpdate 
    $missingcount = 0
    for ($i = 0; $i -le $theseupdates.Count; $i++){$thisupdate = ($theseupdates[$i].Title | Out-String)
        If ($thisupdate -match "^.*KB[0-9]{7}") {
            $missingcount = $missingcount + 1
            $Placeholder = "UpdateName$missingCount"
            $obj.$Placeholder = $thisupdate
        }else{
        Write-Host "There are no pending Microsoft Updates"
    }}
    $obj.Total = $missingcount
    #AutoReboots leave this enabled:
    If ($obj.Total -ne 0){Install-WindowsUpdate -AcceptAll -AutoReboot}
    #CONCAT all object variables to pull back into Automate:
    $Final = [string]::Join("|",($obj.GetEnumerator() | %{$_.Name + "=" + $_.Value}))
    Write-Output $Final
    <#
.SYNOPSIS
    New Laptop Setup
    Optionally Performs any or all of the following:
    -Removes Pre-installed AppXPackages that are generally unneeded
    -Installs commonly used software
    -Installs and configured Hyper-V Host for dev environment
    -Installs any binary placed in the CustomInstallers Directory, which should be located in the same directory as this script.
    -Configures Git, Posh Git, nuget
.PARAMETER -RemoveBloatware
    Removes the following pre-installed AppXPackages:
    ---Microsoft.3DBuilder
    ---skypeapp
    ---Microsoft.Getstarted
    ---Microsoft.MicrosoftSolitaireCollection
    ---Microsoft.BingFinance
    ---Microsoft.BingNews
    ---Microsoft.Office.OneNote
    ---Microsoft.BingSports
    ---Microsoft.BingTravel
    ---Microsoft.BingFoodAndDrink
    ---Microsoft.BingHealthAndFitness
    ---Microsoft.MicrosoftOfficeHub
.PARAMETER -InstallSoftware
    Installs the following software:
    ---Chrome
    ---adobereader
    ---obs-studio
    ---audacity
    ---dotpeek
    ---microsoft-windows-terminal
    ---vscode
    ---gsudo
    ---git
    ---zoom
    ---parsec
    ---treesizefree
    ---greenshot
    ---ditto
.PARAMETER -InstallCustomSoftware
    loops through any binaries in the custom directory "CustomInstallers", located in the root of the script directory, and runs them one by one. 
    The script will wait for each installation to complete before moving on to the next one. 
    This parameter requires attended setup.
.PARAMETER -EnableHyperV
    Enables HyperV on the workstation.
    Will invoke a reboot at the end of the script.
.PARAMETER -SetupGit
    Installs Nuget, configures package managers, configures powershell profile, configures git with user information
.PARAMETER -SetupPrefs
    Configures the following settings on the endpoint:
    ---Sets Timezone to EST
    ---Sets Power plan to high performance
    ---Removes Cortana, Search, news&interests from taskbar
    ---Enables small icons on taskbar
    ---Enables hidden files and file extensions in explorer
    ---Sets Dark Mode windows theme
    ---Clears desktop icons
    ---Empties recycle bin
    Will invoke a reboot at the end of the script.
.PARAMETER -All
    Performs all of the above functions, cleans up, and breaks before other params are checked.
    Adding -All to the script will overwrite any other choices and perform all tasks.
.EXAMPLE
    c:\>InvokeDevEnvSetup.ps1 -RemoveBloatware -InstallCustomSoftware
    C:\>InvokeDevEnvSetup.ps1 -All
.NOTES
    Dan's Laptop setup, preferences, and more 
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)][switch]$RemoveBloatware,
    [Parameter(Mandatory = $false)][switch]$InstallSoftware,
    [Parameter(Mandatory = $false)][switch]$InstallCustomSoftware,
    [Parameter(Mandatory = $false)][switch]$SetupPrefs,
    [Parameter(Mandatory = $false)][switch]$All
)
### Bootstrap ###
#The bootstrap loads Logging, Chocolatey, environment paths, common variables, powershell updates. It should be included on ALL ProVal powershell scripts developed.
if (-not $bootstrapLoaded) {
    [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
    Invoke-Expression (New-Object System.Net.WebClient).DownloadString("https://file.provaltech.com/repo/script/Bootstrap.ps1")
    Set-Environment
    Update-PowerShell
    if ($powershellUpgraded) { return }
    if ($powershellOutdated) { return }
}
else {
    Write-Log -Text "Bootstrap already loaded." -Type INIT
}
function Set-ExplorerAdvancedOption {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][object]$Value
    )
    Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name $Name -Value $Value -Type DWORD -Force
    Write-Log -Text "$Name set to $Value" -Type LOG
}
function Invoke-BloatwareCleanup {
    Write-Log -Text 'Bloatware removal selected. Processing...' -Type DATA
    Get-AppxPackage -name "Microsoft.3DBuilder" | Remove-AppxPackage
    Write-Log -Text 'Removed Microsoft.3DBuilder' -Type LOG
    Get-AppxPackage -name "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
    Write-Log -Text 'Removed Office Hub' -Type LOG
    Get-AppxPackage *skypeapp* | Remove-AppxPackage
    Write-Log -Text 'Removed Skype' -Type LOG
    Get-AppxPackage -name "Microsoft.Getstarted" | Remove-AppxPackage
    Write-Log -Text 'Removed Get Started' -Type LOG
    Get-AppxPackage -name "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
    Write-Log -Text 'Removed Solitaire' -Type LOG
    Get-AppxPackage -name "Microsoft.BingFinance" | Remove-AppxPackage
    Write-Log -Text 'Removed Finance' -Type LOG
    Get-AppxPackage -name "Microsoft.BingNews" | Remove-AppxPackage
    Write-Log -Text 'Removed News' -Type LOG
    Get-AppxPackage -name "Microsoft.Office.OneNote" | Remove-AppxPackage
    Write-Log -Text 'Removed OneNote for Windows 10' -Type LOG
    Get-AppxPackage -name "Microsoft.BingSports" | Remove-AppxPackage
    Write-Log -Text 'Removed Sports' -Type LOG
    Get-AppxPackage -name "Microsoft.BingTravel" | Remove-AppxPackage
    Write-Log -Text 'Removed Travel' -Type LOG
    Get-AppxPackage -name "Microsoft.BingFoodAndDrink" | Remove-AppxPackage
    Write-Log -Text 'Removed Dining' -Type LOG
    Get-AppxPackage -name "Microsoft.BingHealthAndFitness" | Remove-AppxPackage
    Write-Log -Text 'Removed Health' -Type LOG
    Write-Log -Text 'Bloatware removal complete.' -Type DATA
}
function Install-GeneralSoftware {
    Write-Log -Text 'General software installation selected. Processing...' -Type DATA
    choco install `
        googlechrome `
        adobereader `
        zoom `
        greenshot `
        $env:path += 'C:\Program Files\Git\cmd'
    Write-Log -Text 'General Software Installation complete. Git env:path updated for the session.' -Type DATA
}
function Install-CustomSoftware {
    Write-Log -Text 'Custom software installation selected. Processing items in CustomInstalls directory.' -Type DATA
    Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vs_Community.exe" -OutFile ./CustomInstallers/vs.exe
    Write-Log -Text 'Visual Studio 2022 Community Installer downloaded.' -Type LOG
    foreach ($installers in (Get-ChildItem ./CustomInstallers)) {
        Start-Process $installer.Name -Wait
        Write-Log -Text "$installer.Name Installed." -Type LOG
    }
    Write-Log -Text 'Custom software installation complete.' -Type DATA
}
function Set-UserPrefs {
    Write-Log -Text 'User Preference settings selected. Processing.' -Type DATA
    Write-Log -Text 'Setting Time zone to Eastern' -Type LOG
    Set-TimeZone "Eastern Standard Time"
    Write-Log -Text 'Setting Power profile to "High performance"' -Type LOG
    powercfg.exe -SETACTIVE 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
    Write-Log -Text 'Disabling Taskbar Search' -Type LOG
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name SearchBoxTaskbarMode -Value 0 -Type DWord -Force
    Write-Log -Text 'Disabling "News & Interests" toolbar' -Type LOG
    Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds -Name ShellFeedsTaskbarViewMode -Value 2 -Type DWord -Force
    Write-Log -Text 'Setting Windows Dark Theme' -Type LOG
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Value 0 -Type DWORD -Force
    Write-Log -Text 'Disabling Fast Boot' -Type LOG
    Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power -Name HiberbootEnabled -Value 0 -Type DWORD -Force
    Write-Log -Text 'Disabling Taskbar Task View button' -Type LOG
    Set-ExplorerAdvancedOption -Name 'ShowTaskViewButton' -Value 0
    Write-Log -Text 'Disabling Taskbar Cortana Button' -Type LOG
    Set-ExplorerAdvancedOption -Name 'ShowCortanaButton' -Value 0
    Write-Log -Text 'Setting Taskbar to "Small Icons"' -Type LOG
    Set-ExplorerAdvancedOption -Name 'TaskbarSmallIcons' -Value 1
    #Write-Log -Text 'Enabling Explorer: View Hidden Items' -Type LOG
    #Set-ExplorerAdvancedOption -Name 'Hidden' -Value 1
    #Write-Log -Text 'Disabling Explorer: Hide extensions for known file types' -Type LOG
    #Set-ExplorerAdvancedOption -Name 'HideFileExt' -Value 0
    Write-Log -Text 'Setting all current networks to Private' -Type LOG
    Set-AllNetworksPrivate
    Write-Log -Text 'Clearing Desktop Icons' -Type LOG
    Remove-Item $env:USERPROFILE\Desktop\* -Force -Confirm:$false
    Write-Log -Text 'Emptying Recycle Bin' -Type LOG
    Clear-RecycleBin -Force -Confirm:$false
    $rebootNeeded = 1
    return $rebootNeeded
    Write-Log -Text 'User Preference settings complete.' -Type DATA
}
function Set-AllNetworksPrivate {
    $netProfiles = Get-NetConnectionProfile
    foreach ($profile in $netProfiles) {
        Set-NetConnectionProfile -Name $profile.Name -networkCategory Private
    }
}
function Test-RegistryValue {
    param (
        [parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]$Path,
        [parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()]$Value
    )
    try {
        Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}
function Get-PendingReboots {
    [bool]$PendingReboot = $false
    #Check for Keys
    If ((Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") -eq $true) {
        $PendingReboot = $true
    }
    If ((Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting") -eq $true) {
        $PendingReboot = $true
    }
    If ((Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") -eq $true) {
        $PendingReboot = $true
    }
    If ((Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") -eq $true) {
        $PendingReboot = $true
    }
    If ((Test-Path -Path "HKLM:\SOFTWARE\Microsoft\ServerManager\CurrentRebootAttempts") -eq $true) {
        $PendingReboot = $true
    }
    #Check for Values
    If ((Test-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing" -Value "RebootInProgress") -eq $true) {
        $PendingReboot = $true
    }
    If ((Test-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing" -Value "PackagesPending") -eq $true) {
        $PendingReboot = $true
    }
    If ((Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Value "PendingFileRenameOperations") -eq $true) {
        $PendingReboot = $true
    }
    If ((Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Value "PendingFileRenameOperations2") -eq $true) {
        $PendingReboot = $true
    }
    If ((Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Value "DVDRebootSignal") -eq $true) {
        $PendingReboot = $true
    }
    If ((Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon" -Value "JoinDomain") -eq $true) {
        $PendingReboot = $true
    }
    If ((Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon" -Value "AvoidSpnSet") -eq $true) {
        $PendingReboot = $true
    }
    return $PendingReboot
}
function Invoke-Cleanup {
    Write-Log -Text 'The selected Modules have been completed.' -TYPE LOG
    Get-PendingReboots
    if ($PendingReboot) {
        Write-Log -Text 'A reboot is pending on this machine after setup. This machine will now be restarted. Press enter to continue.' -TYPE LOG
        Read-Host
        Restart-Computer
    }
}
#logic
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
if ($All) {
    Invoke-BloatwareCleanup
    Install-GeneralSoftware
    Install-CustomSoftware
    Set-UserPrefs
    Write-Log -Text 'All done, cleaning up and rebooting.' -Type LOG
    Invoke-Cleanup
    break
}
else {
    if ($RemoveBloatware) { Invoke-BloatwareCleanup }
    if ($InstallSoftware) { Install-GeneralSoftware }
    if ($InstallCustomSoftware) { Install-CustomSoftware }
    if ($SetupPrefs) { Set-UserPrefs }
    Write-Log -Text 'All done, cleaning up and checking to see if a reboot is required.' -TypeLOG
    Invoke-Cleanup
}