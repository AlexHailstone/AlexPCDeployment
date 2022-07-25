[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)][switch]$RemoveBloatware,
    [Parameter(Mandatory = $false)][switch]$InstallSoftware,
    [Parameter(Mandatory = $false)][switch]$InstallCustomSoftware,
    [Parameter(Mandatory = $false)][switch]$SetupPrefs,
    [Parameter(Mandatory = $false)][switch]$All
)

$logPath = $null
$dataPath = $null
$errorPath = $null
$workingPath = $null
$scriptTitle = $null
$powershellTargetVersion = 5
$powershellOutdated = $false
$powershellUpgraded = $false
#$provalScriptBasePath = "https://file.provaltech.com/repo/script"
$bootstrapLoaded = $true
$isElevated = $false

function Set-Environment {
    <#
    .SYNOPSIS
        Sets ProVal standard variables for logging and error handling.
    .EXAMPLE
        PS C:\> Set-Environment
    #>
    $scriptObject = Get-Item -Path $script:PSCommandPath
    $script:workingPath = $($scriptObject.DirectoryName)
    $script:logPath = "$($scriptObject.DirectoryName)\$($scriptObject.BaseName)-log.txt"
    $script:dataPath = "$($scriptObject.DirectoryName)\$($scriptObject.BaseName)-data.txt"
    $script:errorPath = "$($scriptObject.DirectoryName)\$($scriptObject.BaseName)-error.txt"
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    $script:isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    Remove-Item -Path $script:dataPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $script:errorPath -Force -ErrorAction SilentlyContinue
    $script:scriptTitle = $scriptObject.BaseName
    Write-Log -Text "-----------------------------------------------" -Type INIT
    Write-Log -Text $scriptTitle -Type INIT
    Write-Log -Text "System: $($env:COMPUTERNAME)" -Type INIT
    Write-Log -Text "User: $($env:USERNAME)" -Type INIT
    Write-Log -Text "OS Bitness: $($env:PROCESSOR_ARCHITECTURE)" -Type INIT
    Write-Log -Text "PowerShell Bitness: $(if([Environment]::Is64BitProcess) {64} else {32})" -Type INIT
    Write-Log -Text "PowerShell Version: $(Get-Host | Select-Object -ExpandProperty Version | Select-Object -ExpandProperty Major)" -Type INIT
    Write-Log -Text "-----------------------------------------------" -Type INIT
}

function Write-LogHelper {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ParameterSetName="String")]
        [AllowEmptyString()]
        [string]$Text,
        [Parameter(Mandatory=$true, ParameterSetName="String")]
        [string]$Type
    )
    $formattedLog = "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))  $($Type.PadRight(8)) $Text"
    switch ($Type) {
        "LOG" { 
            Write-Host -Object $formattedLog
            Add-Content -Path $script:logPath -Value $formattedLog
        }
        "INIT" {
            Write-Host -Object $formattedLog -ForegroundColor White -BackgroundColor DarkBlue
            Add-Content -Path $script:logPath -Value $formattedLog
        }
        "WARN" {
            Write-Host -Object $formattedLog -ForegroundColor Black -BackgroundColor DarkYellow
            Add-Content -Path $script:logPath -Value $formattedLog
        }
        "ERROR" {
            Write-Host -Object $formattedLog -ForegroundColor White -BackgroundColor DarkRed
            Add-Content -Path $script:logPath -Value $formattedLog
            Add-Content -Path $script:errorPath -Value $formattedLog
        }
        "SUCCESS" {
            Write-Host -Object $formattedLog -ForegroundColor White -BackgroundColor DarkGreen
            Add-Content -Path $script:logPath -Value $formattedLog
        }
        "DATA" {
            Write-Host -Object $formattedLog -ForegroundColor White -BackgroundColor Blue
            Add-Content -Path $script:logPath -Value $formattedLog
            Add-Content -Path $script:dataPath -Value $Text
        }
        Default {
            Write-Host -Object $formattedLog
            Add-Content -Path $script:logPath -Value $formattedLog
        }
    }
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a message to a log file, the console, or both.
    .EXAMPLE
        PS C:\> Write-Log -Text "An error occurred." -Type ERROR
        This will write an error to the console, the log file, and the error log file.
    .PARAMETER Text
        The message to pass to the log.
    .PARAMETER Type
        The type of log message to pass in. The options are:
        LOG     - Outputs to the log file and console.
        WARN    - Outputs to the log file and console.
        ERROR   - Outputs to the log file, error file, and console.
        SUCCESS - Outputs to the log file and console.
        DATA    - Outputs to the log file, data file, and console.
        INIT    - Outputs to the log file and console.
    .NOTES
        This function is dependant on being run within a script. This will not work run directly from the console.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position = 0, ParameterSetName="String")]
        [AllowEmptyString()][Alias("Message")]
        [string]$Text,
        [Parameter(Mandatory=$true, Position = 0, ParameterSetName="StringArray")]
        [AllowEmptyString()]
        [string[]]$StringArray,
        [Parameter(Mandatory=$false, Position = 1, ParameterSetName="String")]
        [Parameter(Mandatory=$false, Position = 1, ParameterSetName="StringArray")]
        [string]$Type = "LOG"
    )
    if($script:PSCommandPath -eq '') {
        Write-Error -Message "This function cannot be run directly from a terminal." -Category InvalidOperation
        return
    }
    if($null -eq $script:logPath) {
        Set-Environment
    }

    if($StringArray) {
        foreach($logItem in $StringArray) {
            Write-LogHelper -Text $logItem -Type $Type
        }
    } elseif($Text) {
        Write-LogHelper -Text $Text -Type $Type
    }
}

Register-ArgumentCompleter -CommandName Write-Log -ParameterName Type -ScriptBlock {"LOG","WARN","ERROR","SUCCESS","DATA","INIT"}

function Install-Chocolatey {
    if($env:Path -notlike "*C:\ProgramData\chocolatey\bin*") {
        $env:Path = $env:Path + ';C:\ProgramData\chocolatey\bin'
    }
    [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    if(Test-Path -Path "C:\ProgramData\chocolatey\bin\choco.exe") {
        Write-Log -Text "Chocolatey installation detected." -Type LOG
        choco upgrade chocolatey -y | Out-Null
        choco feature enable -n=allowGlobalConfirmation -confirm | Out-Null
        choco feature disable -n=showNonElevatedWarnings -confirm | Out-Null
        return 0
    } else {
        Write-Log -Text "Chocolatey installation failed." -Type ERROR
        return 1
    }
}

function Update-PowerShell {
    if(-not $isElevated) {
        Write-Log -Text "The current PowerShell session is not elevated. PowerShell will not be upgraded." -Type FAIL
        return
    }
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Force
    $powershellMajorVersion = Get-Host | Select-Object -ExpandProperty Version | Select-Object -ExpandProperty Major
    if($powershellMajorVersion -lt $script:powershellTargetVersion) {
        $script:powershellOutdated = $true
        Write-Log -Text "The version of PowerShell ($powershellMajorVersion) will be upgraded to version $($script:powershellTargetVersion)." -Type LOG
        if($(Install-Chocolatey) -ne 0) {
            Write-Log -Text "Unable to install Chocolatey." -Type ERROR
            return
        }
        try {$powerShellInstalled = $(choco list -le "PowerShell") -like "PowerShell*"} catch {}
        if($powerShellInstalled) {
            Write-Log -Text "PowerShell has already been updated to $powerShellInstalled but is running under version $powershellMajorVersion. Ensure that the machine has rebooted after the update." -Type ERROR
            $script:powershellUpgraded = $true
            return
        }
        Write-Log -Text "Starting PowerShell upgrade." -Type LOG
        cup powershell -y -Force
        Start-Sleep -Seconds 5
        $powerShellInstalled = $(choco list -le "PowerShell") -like "PowerShell*"
        if($powerShellInstalled) {
            Write-Log -Text "Updated to $powerShellInstalled. A reboot is required for this process to continue." -Type LOG
            $script:powershellUpgraded = $true
            return
        } else {
            Write-Log -Text "Something went wrong with the PowerShell upgrade. The process is unable to continue." -Type ERROR
            return
        }
    } else {
        Write-Log -Text "PowerShell is already at or above version $($script:powershellTargetVersion)." -Type LOG
    }
}

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
    winget install `
    Valve.Steam `
    Microsoft.VisualStudioCode `
    Google.Chrome `
    Greenshot.Greenshot `
    # choco install `
    #     googlechrome `
    #     greenshot `
    #     unity `
    #     vscode `
    #     steam-client `
    #     $env:path += 'C:\Program Files\Git\cmd'
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
    #Write-Log -Text 'Setting Taskbar to "Small Icons"' -Type LOG
    #Set-ExplorerAdvancedOption -Name 'TaskbarSmallIcons' -Value 1
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
