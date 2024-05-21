##### START ELEVATE TO ADMIN #####
param(
    [Parameter(Mandatory=$false)]
    [switch]$shouldAssumeToBeElevated,

    [Parameter(Mandatory=$false)]
    [String]$workingDirOverride,

    [Parameter(Mandatory=$false)]
    [String]$scriptUrl
)

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

# Determine the script source (local or remote)
$localScript = $false
if ($myinvocation.MyCommand.Path) {
    $localScript = $true
}

# If the working directory is not set, use the current location
if (-not($PSBoundParameters.ContainsKey('workingDirOverride'))) {
    $workingDirOverride = (Get-Location).Path
}

# If not running as admin, restart the script with admin privileges
if (-not(Test-Admin)) {
    if ($shouldAssumeToBeElevated) {
        Write-Output "Elevating did not work :("
    } else {
        if ($localScript) {
            Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -file "{0}" -shouldAssumeToBeElevated -workingDirOverride "{1}"' -f ($myinvocation.MyCommand.Definition, "$workingDirOverride"))
        } else {
            Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -command "iex (irm ''{0}'')" -shouldAssumeToBeElevated -workingDirOverride "{1}" -scriptUrl ''{0}'' ' -f ($scriptUrl, "$workingDirOverride"))
        }
    }
    exit
}

# If running as admin, continue
Set-Location "$workingDirOverride"
if (-not $localScript -and $scriptUrl) {
    iex (irm $scriptUrl)
}
##### END ELEVATE TO ADMIN #####


# Detect PowerShell version and warn if using PowerShell Core
if ($PSVersionTable.PSVersion.Major -ge 6) {
    Write-Output "Warning: This script is designed for Windows PowerShell and may not work correctly in PowerShell Core (version 6.0 or newer)."
    $confirmation = Read-Host "Do you want to proceed? (Y/N)"
    if ($confirmation -ne "Y") {
        Write-Output "Operation cancelled."
        Exit
    }
} else {
    $confirmation = Read-Host "This script will patch the termsrv.dll file to allow multiple RDP connections. Do you want to proceed? (Y/N)"
    if ($confirmation -ne "Y") {
        Write-Output "Operation cancelled."
        Exit
    }
}

# Prompt user for custom backup location
$backupLocationPrompt = Read-Host "Enter the backup folder path for termsrv.dll or press Enter to use default (C:\Windows\System32\termsrv.dll.backup)"
$backupLocation = if ($backupLocationPrompt -eq '') { "C:\Windows\System32\termsrv.dll.backup" } else { "$backupLocationPrompt\termsrv.dll.backup" }

# Stop RDP services
Stop-Service UmRdpService -Force
Stop-Service TermService -Force

# Backup original termsrv.dll file
try {
    Copy-Item "C:\Windows\System32\termsrv.dll" $backupLocation -Force
    Write-Output "Backup created at $backupLocation"
} catch {
    Write-Output "Failed to create backup. Exiting."
    Read-Host "Press any key to exit"
    Exit
}

# Change permissions for termsrv.dll
$termsrv_dll_acl = Get-Acl "C:\Windows\System32\termsrv.dll"
takeown /f "C:\Windows\System32\termsrv.dll"
$new_termsrv_dll_owner = (Get-Acl "C:\Windows\System32\termsrv.dll").owner
cmd /c "icacls C:\Windows\System32\termsrv.dll /Grant $($new_termsrv_dll_owner):F /C"

# Read termsrv.dll as bytes
$dll_as_bytes = Get-Content "C:\Windows\System32\termsrv.dll" -Raw -Encoding byte
$dll_as_text = $dll_as_bytes.forEach('ToString', 'X2') -join ' '

# Define patterns and patch
# Patterns reference:
# Windows 11 22H2    39 81 3C 06 00 00 0F 84 75 7A 01 00
# Windows 10 22H2    39 81 3C 06 00 00 0F 84 85 45 01 00
# Windows 11 21H2 (RTM)  39 81 3C 06 00 00 0F 84 4F 68 01 00
# Windows 10 x64 21H2    39 81 3C 06 00 00 0F 84 DB 61 01 00
# Windows 10 x64 21H1    39 81 3C 06 00 00 0F 84 2B 5F 01 00
# Windows 10 x64 20H2    39 81 3C 06 00 00 0F 84 21 68 01 00
# Windows 10 x64 2004    39 81 3C 06 00 00 0F 84 D9 51 01 00
# Windows 10 x64 1909    39 81 3C 06 00 00 0F 84 5D 61 01 00
# Windows 10 x64 1903    39 81 3C 06 00 00 0F 84 5D 61 01 00
# Windows 10 x64 1809    39 81 3C 06 00 00 0F 84 3B 2B 01 00
# Windows 10 x64 1803    8B 99 3C 06 00 00 8B B9 38 06 00 00
# Windows 10 x64 1709    39 81 3C 06 00 00 0F 84 B1 7D 02 00
$patterns = @(
    [regex]'39 81 3C 06 00 00(\s\S\S){6}',
    [regex]'8B 99 3C 06 00 00 8B B9 38 06 00 00',
    [regex]'39 81 3C 06 00 00 0F 84 B1 7D 02 00'
)
$patch = 'B8 00 01 00 00 89 81 38 06 00 00 90'

# Check if any pattern exists
$patternFound = $false
foreach ($pattern in $patterns) {
    $checkPattern = Select-String -Pattern $pattern -InputObject $dll_as_text
    if ($checkPattern -ne $null) {
        # Replace pattern with patch
        $dll_as_text_replaced = $dll_as_text -replace $pattern, $patch
        $patternFound = $true
        break
    }
}

if (-not $patternFound) {
    if (Select-String -Pattern $patch -InputObject $dll_as_text) {
        Write-Output 'The termsrv.dll file is already patched, exiting'
    } else {
        Write-Output "Pattern not found."
    }
    
    # Ensure services are started even if patch is not needed
    Start-Service UmRdpService
    Start-Service TermService

    Read-Host "Press any key to exit"
    Exit
}

# Write patched bytes to new file
[byte[]] $dll_as_bytes_replaced = -split $dll_as_text_replaced -replace '^', '0x'
Set-Content "C:\Windows\System32\termsrv.dll.patched" -Encoding Byte -Value $dll_as_bytes_replaced

# Compare original and patched files
fc.exe /b "C:\Windows\System32\termsrv.dll.patched" "C:\Windows\System32\termsrv.dll"

# Replace original termsrv.dll file
Copy-Item "C:\Windows\System32\termsrv.dll.patched" "C:\Windows\System32\termsrv.dll" -Force

# Restore original ACL
Set-Acl "C:\Windows\System32\termsrv.dll" $termsrv_dll_acl

# Start RDP services
Start-Service UmRdpService
Start-Service TermService

# Output success message and prompt to exit
Write-Output "RDP patching complete."
Read-Host "Press any key to exit"
