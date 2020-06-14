<#
.SYNOPSIS
An active directory & windows server audit script. Compatible with Windows 7, Windows Server 2008 or newer. Powershell version 2.0+
.DESCRIPTION
Version 2.0 - 20-JUNE-2019
.EXAMPLE
.\Invoke-Audit.ps1 -Verbose
.\Invoke-Audit.ps1 -AD -Verbose
.PARAMETER AD
If you use the -AD Switch, the script will include Active Directory specific commands
#>
[CmdletBinding()]
param
(
	[switch]$AD,
	[switch]$SecurityUpdates
)
$Computername = $env:COMPUTERNAME;
$ADSI = [ADSI]"WinNT://$Computername";
$Path = "Audit-" + $Computername;

#Current User must have administrator privileges, or run an elevated Powershell Session
$isAdmin = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if(!$isAdmin)
{
	throw "Commands require administrator privileges to execute!";
}

if($PSVersionTable.PSVersion.Major -lt 2)
{
	throw "This script is only compatible with Powershell Version 2.0+";
}


if(!(Test-Path -Path $Path))
{
	New-Item -Path "." -Name $Path -ItemType Directory | Out-Null
	if(!(Test-Path -Path $Path))
	{
		throw "Cannot create folder to contain script output";
	}
}
else
{
	$r = Read-Host -Prompt "Audit Folder already exists in the current folder, Continue & Overwrite? [Y/N]";
	if(!($r -Match "[Yy]")) 
	{
		Write-Verbose "Exiting script";
		exit; 
	}
}
Set-Location -Path $Path;
# ------------------------------------

<#
$GMWSUPath = (Resolve-Path -Path $Path).Path + "MissingUpdates.txt"
Try
{
	Start-Job -Name GMWSU -FilePath Get-MissingSecurityUpdates.ps1 -ArgumentList $GMWSUPath | Out-Null
}
Catch
{
	"Could not start job to get missing security updates"
	Get-Job -Name GMWSU | Remove-Job
}#>

#Table of valid Computer Roles
$SystemRoles = @{
0    =    "Standalone Workstation   ";
1    =    "Member Workstation       ";
2    =    "Standalone Server        ";
3    =    "Member Server            ";
4    =    "Backup  Domain Controller";
5    =    "Primary Domain Controller"       
}
$ComputerRole = $SystemRoles[[int]((Get-WMIObject -Class Win32_ComputerSystem).DomainRole)]

[string[]]$SysInfo = @()
$SysInfo += "Date: "+([string](Get-Date -UFormat "%d-%m-%y"))
$SysInfo += "Current User: "+($env:UserName)
$SysInfo += "Current Domain: "+($env:UserDomain)
$SysInfo += "Hostname: "+($env:ComputerName)
$OS = Get-WMIObject -class Win32_OperatingSystem
$SysInfo += "OS: "+($OS.Caption)
$SysInfo += "Service Pack: "+($OS.ServicePackMajorVersion)
$SysInfo += "PSVersion: "+([string]$PSVersionTable.PSVersion.Major)
$SysInfo += "Computer/Domain Role: "+($ComputerRole)
Foreach($v in $SysInfo)
{
	Write-Verbose $v
}

$SysInfoPath = "Sysinfo.txt";
Foreach($v in $SysInfo)
{
	$v | Out-File -FilePath $SysInfoPath -Append
}

Write-Verbose "Getting Local System & User Information"
$SecEditPath = "SecPolicy.txt"
Invoke-Expression -Command ("SecEdit.exe /export /cfg " + $SecEditPath + " /quiet")
Invoke-Expression -Command ("w32tm /query /status") | Out-File -FilePath "NTPConfig.txt"
Invoke-Expression -Command "auditpol.exe /get /category:*" | Out-File -FilePath "AuditPolicy.txt"
#Invoke-Expression -Command "net user" | Out-File -FilePath "Local users.txt"
#Invoke-Expression -Command "net localgroup" | Out-File -FilePath "Local groups.txt"
#Invoke-Expression -Command "net localgroup administrators" | Out-File -FilePath "Local admins.txt"
[System.IO.DriveInfo]::GetDrives() | Export-CSV -Path "LocalDrives.csv" -Delimiter ';' -NoTypeInformation
Invoke-Expression -Command "netsh advfirewall show allprofiles" | Out-File -FilePath "Firewall_Profiles.txt"
Invoke-Expression -Command "netsh advfirewall firewall show rule all verbose" | Out-File -FilePath "Firewall_Rules.txt"


#region Active Directory
if($DC -And ($ComputerRole -ge 3)) 
{
	if ((Get-Module -Name ActiveDirectory) -eq $null)
	{
		Import-Module ActiveDirectory

		if ((Get-Module -Name ActiveDirectory) -eq $null)
		{
			throw "Cannot import Active Directory PS Module"
		}
	}
	if($ComputerRole -lt 4) { Write-Warning "Running AD Commands on a Member Server / Workstation instead of Domain Controller" }
	[string[]]$UserProperties = @("SamAccountName","adminCount","AccountExpirationDate","CannotChangePassword","Created",
							"DisplayName","DistinguishedName","Enabled","Description","LastLogonDate","PasswordExpired",
							"UserPrincipalName", "GivenName","BadLogonCount", "PasswordNeverExpires","PasswordLastSet",
							"PasswordNotRequired","whenCreated","whenChanged","createTimeStamp","SID");
	[string[]]$GrpProperties = @("SamAccountName","DisplayName","DistinguishedName","Created","GroupCategory","GroupScope","SID");

	Write-Verbose "Getting Domain User & Group Information"
	Get-ADUser -Filter * -Properties $UserProperties | Export-CSV -Path ($Path+"ADAllUsers.csv") -Delimiter ';' -NoTypeInformation
	Get-ADGroup -Filter * -Properties $GrpProperties | Export-CSV -Path ($Path+"ADAllGroups.csv") -Delimiter ';' -NoTypeInformation
	Get-ADGroupMember "Domain Admins" | Export-CSV -Path ($Path+"ADDomainAdmins.csv") -Delimiter ';' -NoTypeInformation
	Get-ADGroupMember "Enterprise Admins" | Export-CSV -Path ($Path+"ADEnterpriseAdmins.csv") -Delimiter ';' -NoTypeInformation
	Get-ADGroupMember "Schema Admins" | Export-CSV -Path ($Path+"ADSchemaAdmins.csv") -Delimiter ';' -NoTypeInformation
	Get-ADDefaultDomainPasswordPolicy $env:UserDomain | Export-CSV -Path ($Path+"DefaultDomainPasswordPolicy.csv") -Delimiter ';' -NoTypeInformation
	
	if ((Get-Module -Name GroupPolicy) -eq $null)
	{
		Import-Module GroupPolicy

		if ((Get-Module -Name GroupPolicy) -eq $null)
		{
			throw "Cannot import Group Policy PS Module"
		}
	}
	Write-Verbose "Getting all Group Policy Object Reports"
	Invoke-Expression -Command ("GPResult /H " + $Path + "GPResult.htm") | Out-Null
	Get-GPO -All | % {$_.GenerateReport('html') | Out-File ($Path+ "$($_.DisplayName).gpo.htm")}
}
#endregion


<#
Write-Verbose "Waiting for parallel job(s) to complete"
# Wait for missing updates job to complete
Get-Job -Name GMWSU | Wait-Job | Out-Null
Receive-Job GMWSU | Out-Null
Get-Job -Name GMWSU | Remove-Job | Out-Null
Write-Verbose "Script Complete"#>

#>