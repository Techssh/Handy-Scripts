####Note####
#Open PowerShell as an Administrator
#Type: Set-ExecutionPolicy Unrestricted
#Once the entire script has finished running, type: Set-ExecutionPolicy Restricted

##Tested on Windows 10/11###

#This is based on whatever window SMB version is running, if you require SMBv1 (not recommended), be sure to enable it


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

# Set the log file path
$logFileBaseName = "creating-user-share_LOGs"
$logFileExtension = ".txt"
$logFileIndex = 0
$logFilePath = Join-Path -Path $Env:USERPROFILE -ChildPath ($logFileBaseName + $logFileExtension)

# Check if log file exists, if yes, create additional log files with sequential numbers
while (Test-Path $logFilePath) {
    $logFileIndex++
    $logFilePath = Join-Path -Path $Env:USERPROFILE -ChildPath ($logFileBaseName + "_$logFileIndex" + $logFileExtension)
}

# Redirect all output to the log file
Start-Transcript -Path $logFilePath


###-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------###

## Default values， not USE!!!
#$folderPath = Join-Path -Path $Env:USERPROFILE -ChildPath "Scans-Folder"
#$userName = "scansonly"
#$fullName = "Scans Only"
#$password = "P@ssw0rd"
#$shareName = "Scans-Share"


# Function to validate folder path
function Validate-FolderPath {
    param([string]$folderPath)
    if (-not ($folderPath -match "^([A-Za-z]:\\[^/:*?""<>|]+)$")) {
        Write-Warning "Invalid folder path. Folder path must be a valid Windows path (e.g., C:\folder)."
        return $false
    }
    return $true
}

# Function to validate username
function Validate-Username {
    param([string]$username)
    if (-not ($username -match "^[a-zA-Z0-9_]+$")) {
        Write-Warning "Invalid username. Username must contain only letters, numbers, and underscores."
        return $false
    }
    return $true
}

# Function to validate full name
function Validate-FullName {
    param([string]$fullName)
    if (-not ($fullName -match "^[\w\s'-]+$")) {
        Write-Warning "Invalid full name. Full name must contain only letters, numbers, spaces, hyphens, and apostrophes."
        return $false
    }
    return $true
}




# Function to validate password
function Validate-Password {
    param([string]$password)
    if (-not ([string]::IsNullOrEmpty($password) -or $password.Length -ge 8)) {
        Write-Warning "Invalid password. Password must be at least eight characters long."
        return $false
    }
    return $true
}




# Function to validate share name
function Validate-ShareName {
    param([string]$shareName)
    if (-not ($shareName -match "^[a-zA-Z0-9_]+$")) {
        Write-Warning "Invalid share name. Share name must contain only letters, numbers, and underscores; your computer policy may require you to have a more complex password too."
        return $false
    }
    return $true
}

# Default values prompting for custom input
$folderPathDefault = Join-Path -Path $Env:USERPROFILE -ChildPath "Scans-Folder"
$userNameDefault = "scansonly"
$fullNameDefault = "Scans Only"
$passwordDefault = "P@ssw0rd"
$shareNameDefault = "ScansShare"

do {
    $folderPathInput = Read-Host "Enter folder path (default: $folderPathDefault)"
    if ([string]::IsNullOrEmpty($folderPathInput)) {
        $folderPath = $folderPathDefault
        break
    }
} until (Validate-FolderPath $folderPathInput)

if (-not [string]::IsNullOrEmpty($folderPathInput)) {
    $folderPath = $folderPathInput
}

do {
    $userNameInput = Read-Host "Enter username (default: $userNameDefault)"
    if ([string]::IsNullOrEmpty($userNameInput)) {
        $userName = $userNameDefault
        break
    }
} until (Validate-Username $userNameInput)

if (-not [string]::IsNullOrEmpty($userNameInput)) {
    $userName = $userNameInput
}

do {
    $fullNameInput = Read-Host "Enter full name (default: $fullNameDefault)"
    if ([string]::IsNullOrEmpty($fullNameInput)) {
        $fullName = $fullNameDefault
        break
    }
} until (Validate-FullName $fullNameInput)

if (-not [string]::IsNullOrEmpty($fullNameInput)) {
    $fullName = $fullNameInput
}





do {
    $passwordInput = Read-Host "Enter password (default: $passwordDefault)"
    if ([string]::IsNullOrEmpty($passwordInput)) {
        $password = $passwordDefault
        break
    }
} until (Validate-Password $passwordInput)

if (-not [string]::IsNullOrEmpty($passwordInput)) {
    $password = $passwordInput
}



do {
    $shareNameInput = Read-Host "Enter share name (default: $shareNameDefault)"
    if ([string]::IsNullOrEmpty($shareNameInput)) {
        $shareName = $shareNameDefault
        break
    }
} until (Validate-ShareName $shareNameInput)

if (-not [string]::IsNullOrEmpty($shareNameInput)) {
    $shareName = $shareNameInput
}

# Displaying info message
Write-Host "Congratulations! You've successfully completed all inputs."
Write-Host "Folder Path: $folderPath"
Write-Host "Username: $userName"
Write-Host "Full Name: $fullName"
Write-Host "Password: $password"
Write-Host "Share Name: $shareName"




###-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------###


# Function to create user
function Create-LocalUser {
    param(
        [string]$userName,
        [string]$password,
        [string]$fullName
    )

    $userExists = $false
    $user = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue
    if ($user) {
        Write-Host "User '$userName' already exists."
        $userExists = $true
    } else {
        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        $userParams = @{
            Name = $userName
            Password = $securePassword
            FullName = $fullName
            PasswordNeverExpires = $true
            UserMayNotChangePassword = $true
        }
        New-LocalUser @userParams
        Write-Host "User '$userName' created."
    }
    return $userExists
}

# Function to create share
function Create-Share {
    param(
        [string]$shareName,
        [string]$folderPath
    )

    if (-not (Get-SmbShare | Where-Object { $_.Name -eq $shareName })) {
        New-SmbShare -Name $shareName -Path $folderPath -FullAccess "Everyone"
        Write-Host "Share '$shareName' created."
    } else {
        Write-Host "Share '$shareName' already exists."
    }
}

# Function to create folder and set permissions recursively
function Create-Folder {
    param(
        [string]$folderPath,
        [string]$userName
    )

    if (-not (Test-Path $folderPath -PathType Container)) {
        New-Item -ItemType Directory -Path $folderPath
        Write-Host "Folder '$folderPath' created."
    } else {
        Write-Host "Folder '$folderPath' already exists."
    }

    if (-not [string]::IsNullOrEmpty($userName)) {
        $acl = Get-Acl $folderPath
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$userName", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($rule)
        Set-Acl $folderPath $acl
        Write-Host "Permissions granted to user '$userName' on folder '$folderPath' and propagated to all child items."
    } else {
        Write-Host "User name is null or empty. No permissions were granted."
    }
}

# Function to grant permissions to share
function Grant-Permissions {
    param(
        [string]$userName,
        [string]$shareName
    )

    $share = Get-SmbShare | Where-Object { $_.Name -eq $shareName }
    if ($share) {
        Grant-SmbShareAccess -Name $shareName -AccountName $userName -AccessRight Full
        Write-Host "Permissions granted to user '$userName' on share '$shareName'."
    } else {
        Write-Host "Share '$shareName' not found. Permissions not granted."
    }
}

# Step 0: Enable file and printer sharing firewall rules
$firewallRule = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*File and Printer Sharing*" }
if ($firewallRule -ne $null) {
    # Ensure rule is in the "Allow" connection state
    if ($firewallRule.Action -ne "Allow") {
        Set-NetFirewallRule -Name $firewallRule.Name -Action Allow
    }
    # Allow connections from any remote subnet
    Set-NetFirewallRule -Name $firewallRule.Name -RemoteAddress Any
    # Enable the rule if it's not already enabled
    if (-not $firewallRule.Enabled) {
        Set-NetFirewallRule -Name $firewallRule.Name -Enabled True
    }
} else {
    Write-Host "File and Printer Sharing firewall rule not found."
}



Write-Host "Your Wi-Fi or Ethernet has a connection (LAN connection it's good enough) to complete it successfully for the following step 1! Otherwise, having an error is normal behavior."
# Step 1: Check network profile and set if needed
$networkProfile = Get-NetConnectionProfile
if ($networkProfile.NetworkCategory -ne "Private") {
    Set-NetConnectionProfile -Name $networkProfile.Name -NetworkCategory Private
}

# Step 2: Create user
$userExists = Create-LocalUser -userName $userName -password $password -fullName $fullName

# Step 3: Create folder
Create-Folder -folderPath $folderPath -userName $userName

# Step 4: Create share
Create-Share -shareName $shareName -folderPath $folderPath

# Step 5: Grant permissions
if (-not $userExists) {
    Grant-Permissions -userName $userName -shareName $shareName
}

# Print share information if all steps were successful
if ((Test-Path $folderPath) -and (Get-SmbShare | Where-Object { $_.Name -eq $shareName }) -and (Get-LocalUser | Where-Object { $_.Name -eq $userName })) {
    $hostname = hostname
    $ipv4 = (Get-NetIPAddress -AddressFamily IPv4).IPAddress
    $ipv6 = (Get-NetIPAddress -AddressFamily IPv6).IPAddress

    Write-Host "All steps completed successfully!"
    Write-Host "---------------------------------------o(*￣▽￣*)ブ"
    Write-Host "Share Information:"
    Write-Host "  Hostname: $hostname"
    Write-Host "  IPv4 Addresses: $ipv4"
    Write-Host "  IPv6 Addresses: $ipv6"
    Write-Host "  Share Name: $shareName"
    Write-Host "  Share Path: \\$hostname\$shareName"
    Write-Host "  Username: $userName"
    Write-Host "  Password: $password" # Displaying password for convenience, make sure to change this in a production environment
    Write-Host "完---------------------------------------o(*￣▽￣*)ブ"

    Write-Host "Press 'q' to exit PowerShell..."
    $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    if ($key.Character -eq "q") {
        exit
    }
} else {
    Write-Host "An error occurred during the process. Please check and try again."
}

# End transcript and close log file
Stop-Transcript
