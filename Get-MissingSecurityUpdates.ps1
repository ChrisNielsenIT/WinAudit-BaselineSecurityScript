<#
.SYNOPSIS
Displays which Microsoft Security Updates are missing from the current machine.
.DESCRIPTION
Version 1.0 - 30-10-2018
This script displays which Microsoft Security Updates are missing from the current machine, and can output, semi-colon separated results, to a file.
.EXAMPLE
.\Get-MissingSecurityUpdates.ps1
.EXAMPLE
.\Get-MissingSecurityUpdates.ps1 -FilePath MissingUpdates.txt
#>
[Cmdletbinding()]
param
(
	[string]$FilePath
)
$Reporting = New-Object -Type System.Collections.ArrayList
$UpdateSession = New-Object -ComObject Microsoft.Update.Session 
$UpdateSearcher = $UpdateSession.CreateUpdateSearcher() 
$UpdateSearcher.ServerSelection = 2 # ssWindowsUpdate

#Test Info
Write-Host "30-10-2018 | THIS IS NOT RELEASED FOR USE IN CLIENT ENVIRONMENTS!" -Fore Red
Write-Host "$(Get-Date)" -Fore Green
Write-Host "$($env:USERNAME)@$($env:COMPUTERNAME)" -Fore Green

Write-Host "Searching for updates, this could take several minutes...`n" -Fore Green

Try
{
	$SearchResult = $UpdateSearcher.Search("IsInstalled=0 and IsHidden=0")
}
Catch
{
	Write-Host "The script is either not allowed or not able to contact Microsoft's WUA Server!" -Fore Red
	Write-Host "Specific Error Message: $($_.Exception.Message)"
	return $null
}

$Updates = $SearchResult.Updates 
if($Updates.Count -eq 0)
{ 
    Write-Host "There are no applicable updates." -Fore Green
	$Reporting.Add("There are no applicable updates") | Out-Null
	if($FilePath) { $Reporting | Out-File -FilePath $FilePath }
    return $null
} 
 
Write-Host "List of applicable items on this machine:`n" 
 
$i = 1 
foreach($Update in $Updates)
{
	if($Update.MsrcSeverity)
	{
		Write-Host "Update: $i" 
		Write-Host "$($Update.Title)" 
		Write-Host "Severity: $($Update.MsrcSeverity) `n" -Fore Red
		$Reporting.Add("Update: $($i);Title: $($Update.Title);Severity: $($Update.MsrcSeverity)") | Out-Null
		$i++ 
	}
}
if($FilePath) { $Reporting | Out-File -FilePath $FilePath -Append }


<#
ServerSelection:
	ssDefault = 0
	ssManagedServer = 1
	ssWindowsUpdate = 2
	ssOthers = 3
	
#$SearchResult = $UpdateSearcher.Search("IsInstalled=1 or IsInstalled=0")
#$SearchResult = $UpdateSearcher.Search("IsInstalled=1 or IsInstalled=0 or IsHidden=0")
#>