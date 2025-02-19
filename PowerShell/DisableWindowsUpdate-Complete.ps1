###running this script that save in networks share may not work###
#make sure the script is running with full admin privileges
#### START ELEVATE TO ADMIN #####
param(
    [Parameter(Mandatory=$false)]
    [switch]$shouldAssumeToBeElevated,
 
    [Parameter(Mandatory=$false)]
    [String]$workingDirOverride
)
 
# If parameter is not set, we are propably in non-admin execution. We set it to the current working directory so that
#  the working directory of the elevated execution of this script is the current working directory
if(-not($PSBoundParameters.ContainsKey('workingDirOverride')))
{
    $workingDirOverride = (Get-Location).Path
}
 
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
 
# If we are in a non-admin execution. Execute this script as admin
if ((Test-Admin) -eq $false)  {
    if ($shouldAssumeToBeElevated) {
        Write-Output "Elevating did not work :("
 
    } else {
        #                                                         vvvvv add `-noexit` here for better debugging vvvvv 
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -shouldAssumeToBeElevated -workingDirOverride "{1}"' -f ($myinvocation.MyCommand.Definition, "$workingDirOverride"))
    }
    exit
}
 
Set-Location "$workingDirOverride"
##### END ELEVATE TO ADMIN #####
 
# Add actual commands to be executed in elevated mode here:
Write-Output "Admin in PowerShell elevation successful"
 
 
###-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------###
 
 
 
 
 
 
# Check for administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script with administrative privileges."
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit
}
 
###==================================================================================================###


# Define file paths and registry paths
$files = @{
    "qmgr.dll" = "$env:WINDIR\System32\qmgr.dll"
    "wuaueng.dll" = "$env:WINDIR\System32\wuaueng.dll"
    "wuauclt.exe" = "$env:WINDIR\System32\wuauclt.exe"
}

$registryPaths = @{
    "wuauserv" = "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv"
    "WaaSMedicSvc" = "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc"
}

# Backup directory
$backupDir = "C:\RegeditBackupDIR"

# Function to change file owner to Administrators and grant full control
function Set-FilePermissions {
    param (
        [string]$filePath
    )
    $acl = Get-Acl $filePath
    $admins = New-Object System.Security.Principal.NTAccount("Administrators")
    $acl.SetOwner($admins)
    Set-Acl $filePath $acl

    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "Allow")
    $acl.SetAccessRule($accessRule)
    Set-Acl $filePath $acl
}

# Function to stop Windows Update service
function Stop-WindowsUpdateService {
    Write-Host "Stopping Windows Update service..."
    Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
    Write-Host "Windows Update service stopped."
}

# Function to disable Windows Update service
function Disable-WindowsUpdateService {
    Write-Host "Disabling Windows Update service..."
    Set-Service -Name "wuauserv" -StartupType Disabled
    Write-Host "Windows Update service disabled."
}

# Function to check if files have already been renamed
function Check-FilesAlreadyDisabled {
    foreach ($file in $files.GetEnumerator()) {
        if (Test-Path "$($file.Value).disable") {
            return $true
        }
    }
    return $false
}

# Function to rename files by adding ".disable" suffix
function Disable-Files {
    if (Check-FilesAlreadyDisabled) {
        Write-Host "Files have already been renamed. Aborting."
        return
    }

    Stop-WindowsUpdateService
    Disable-WindowsUpdateService

    foreach ($file in $files.GetEnumerator()) {
        $filePath = $file.Value
        $newFilePath = "$filePath.disable"

        if (Test-Path $filePath) {
            Set-FilePermissions -filePath $filePath
            Rename-Item -Path $filePath -NewName $newFilePath
            Write-Host "Renamed $filePath to $newFilePath"
        } else {
            Write-Host "File $filePath not found"
        }
    }
}

# Function to revert the renaming of files
function Enable-Files {
    foreach ($file in $files.GetEnumerator()) {
        $filePath = "$($file.Value).disable"
        $originalFilePath = $file.Value

        if (Test-Path $filePath) {
            Set-FilePermissions -filePath $filePath
            Rename-Item -Path $filePath -NewName $originalFilePath
            Write-Host "Renamed $filePath to $originalFilePath"
        } else {
            Write-Host "File $filePath not found"
        }
    }

    Write-Host "Reverting changes..."
    Set-Service -Name "wuauserv" -StartupType Manual
    Start-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    Write-Host "Windows Update service reverted to manual startup."
}

# Function to check if registry keys have already been renamed
function Check-RegistryAlreadyDisabled {
    foreach ($key in $registryPaths.GetEnumerator()) {
        if (Test-Path "$($key.Value)-BLOCKED") {
            return $true
        }
    }
    return $false
}

# Function to backup registry keys
function Backup-RegistryKey {
    param (
        [string]$keyPath,
        [string]$backupPath
    )
    $backupFilePath = Join-Path -Path $backupDir -ChildPath ($backupPath + ".reg")
    if (-Not (Test-Path -Path $backupDir)) {
        New-Item -Path $backupDir -ItemType Directory -Force
    }
    & reg export $keyPath $backupFilePath /y
    Write-Host "Backed up $keyPath to $backupFilePath"
}

# Function to rename registry keys to disable services
function Disable-Registry {
    if (Check-RegistryAlreadyDisabled) {
        Write-Host "Registry keys have already been renamed. Aborting."
        return
    }

    Stop-WindowsUpdateService
    Disable-WindowsUpdateService

    foreach ($key in $registryPaths.GetEnumerator()) {
        Backup-RegistryKey -keyPath $key.Value -backupPath $key.Key
    }

    Rename-Item -Path "Registry::$($registryPaths["wuauserv"])" -NewName "wuauserv-BLOCKED" -Force
    Rename-Item -Path "Registry::$($registryPaths["WaaSMedicSvc"])" -NewName "WaaSMedicSvc-BLOCKED" -Force
    Write-Host "Renamed registry keys to disable services."
}

# Function to rename registry keys to enable services
function Enable-Registry {
    Rename-Item -Path "Registry::$($registryPaths["wuauserv"])-BLOCKED" -NewName "wuauserv" -Force
    Rename-Item -Path "Registry::$($registryPaths["WaaSMedicSvc"])-BLOCKED" -NewName "WaaSMedicSvc" -Force

    Write-Host "Reverting changes..."
    Set-Service -Name "wuauserv" -StartupType Manual
    Start-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    Write-Host "Windows Update service reverted to manual startup."
}

# Main script execution
$choice = Read-Host "Enter 'disable' to disable Windows update service or 'enable' to revert changes"
$method = Read-Host "Enter '1' for file renaming method (recommended) or '2' for registry method"

if ($choice -eq "disable") {
    if ($method -eq "1") {
        Disable-Files
    } elseif ($method -eq "2") {
        Disable-Registry
    } else {
        Write-Host "Invalid method choice. Please enter '1' or '2'."
    }
} elseif ($choice -eq "enable") {
    if ($method -eq "1") {
        Enable-Files
    } elseif ($method -eq "2") {
        Enable-Registry
    } else {
        Write-Host "Invalid method choice. Please enter '1' or '2'."
    }
} else {
    Write-Host "Invalid choice. Please enter 'disable' or 'enable'."
}
