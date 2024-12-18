#--------------------------------------------------------------------------
#- Created by:             Adrian Johnson                                -
#- Version:                2.1 (Refactored with Advanced Logging)         -
#--------------------------------------------------------------------------

#-------------
#- Variables -
#-------------

# Network Variables
$NetworkConfig = @{ 
    IPAddress        = '192.168.1.222'
    PrefixLength     = '24'
    DefaultGateway   = '192.168.1.1'
    DNS              = '8.8.8.8'
    GlobalSubnet     = '192.168.1.0/24'
    SubnetLocation   = 'Sydney'
    SiteName         = 'Sydney-Site'
}

# Active Directory Variables
$ADConfig = @{ 
    DomainName   = 'vlab.local'
    RestorePwd   = $null
}

# Remote Desktop Variable
$EnableRDP = $true

# IE Enhanced Security Configuration Variable
$DisableIESec = $true

# Hostname Variable
$Hostname = 'SERVERDC1'

# NTP Servers
$NTPServers = @( '0.au.pool.ntp.org', '1.au.pool.ntp.org' )

# DNS Variables
$DNSConfig = @{ 
    ReverseZone = '1.168.192.in-addr.arpa'
}

# Log File Path
$LogFile = "C:\SysadminTutorialsScript\Windows-2022-AD-Deployment-log.txt"

# Notification Email Address
$NotificationEmail = "admin@example.com"

#-------------
#- Functions -
#-------------

function Write-Log {
    param (
        [string]$Message,
        [switch]$Error
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $FormattedMessage = "$Timestamp - $Message"
    if ($Error) {
        Write-Warning $FormattedMessage
        Send-Notification -Message $FormattedMessage -Critical
    } else {
        Write-Host $FormattedMessage -ForegroundColor Green
    }
    Add-Content -Path $LogFile -Value $FormattedMessage
}

function Send-Notification {
    param (
        [string]$Message,
        [switch]$Critical
    )
    try {
        $Subject = "Script Notification"
        if ($Critical) {
            $Subject = "CRITICAL: Script Failure Notification"
        }
        Send-MailMessage -To $NotificationEmail -From "script-notify@example.com" -Subject $Subject -Body $Message -SmtpServer "smtp.example.com"
        Write-Host "Notification sent: $Message" -ForegroundColor Yellow
    } catch {
        Write-Warning "Failed to send notification: $_"
    }
}

function Configure-Network {
    param (
        [hashtable]$Config
    )
    Write-Log "Starting network configuration..."
    Write-Log "Configuration details: IP=$($Config.IPAddress), PrefixLength=$($Config.PrefixLength), Gateway=$($Config.DefaultGateway), DNS=$($Config.DNS)"
    try {
        New-NetIPAddress -IPAddress $Config.IPAddress -PrefixLength $Config.PrefixLength -DefaultGateway $Config.DefaultGateway -InterfaceIndex (Get-NetAdapter).InterfaceIndex -ErrorAction Stop
        Set-DNSClientServerAddress -ServerAddresses $Config.DNS -InterfaceIndex (Get-NetAdapter).InterfaceIndex -ErrorAction Stop
        Write-Log "Network configured successfully"
    } catch {
        Write-Log "Failed to configure network: $_" -Error
        throw
    }
}

function Configure-RDP {
    param (
        [bool]$Enable
    )
    Write-Log "Configuring RDP (Enable=$Enable)..."
    try {
        if ($Enable) {
            Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0 -ErrorAction Stop
            Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction Stop
            Write-Log "RDP enabled successfully"
        } else {
            Write-Log "RDP configuration skipped"
        }
    } catch {
        Write-Log "Failed to configure RDP: $_" -Error
        throw
    }
}

function Configure-IESec {
    param (
        [bool]$Disable
    )
    Write-Log "Configuring IE Enhanced Security (Disable=$Disable)..."
    try {
        if ($Disable) {
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name IsInstalled -Value 0 -ErrorAction Stop
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -Name IsInstalled -Value 0 -ErrorAction Stop
            Write-Log "IE Enhanced Security Configuration disabled successfully"
        } else {
            Write-Log "IE Enhanced Security Configuration remains enabled"
        }
    } catch {
        Write-Log "Failed to configure IE Enhanced Security: $_" -Error
        throw
    }
}

function Rename-Server {
    param (
        [string]$NewName
    )
    Write-Log "Renaming server to $NewName..."
    try {
        Rename-Computer -ComputerName $env:COMPUTERNAME -NewName $NewName -ErrorAction Stop
        Write-Log "Server renamed to $NewName successfully"
    } catch {
        Write-Log "Failed to rename server: $_" -Error
        throw
    }
}

function Install-ActiveDirectory {
    param (
        [hashtable]$Config
    )
    Write-Log "Installing Active Directory with Domain=$($Config.DomainName)..."
    try {
        Write-Log "Installing Active Directory Domain Services..."
        Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
        Install-ADDSForest -DomainName $Config.DomainName -InstallDNS -SafeModeAdministratorPassword $Config.RestorePwd -Confirm:$false
        Write-Log "Active Directory installed and configured successfully"
    } catch {
        Write-Log "Failed to install Active Directory: $_" -Error
        throw
    }
}

#-------------
#- Main Logic -
#-------------

if (-Not (Test-Path $LogFile)) {
    New-Item -Path (Split-Path $LogFile) -ItemType Directory -Force | Out-Null
    New-Item -Path $LogFile -ItemType File -Force | Out-Null
    Write-Log "Log file created at $LogFile"
}

Write-Log "Starting Active Directory Deployment Script"

# Configure Network
Configure-Network -Config $NetworkConfig

# Configure RDP
Configure-RDP -Enable $EnableRDP

# Disable IE Enhanced Security
Configure-IESec -Disable $DisableIESec

# Rename Server
Rename-Server -NewName $Hostname

# Install Active Directory
$ADConfig.RestorePwd = Read-Host "Enter Directory Services Restore Mode Password" -AsSecureString
Install-ActiveDirectory -Config $ADConfig

Write-Log "Script execution completed successfully"
