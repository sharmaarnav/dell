<#

	.EXAMPLE
		Set a new admin password
		Manage-DellBiosPasswords-PSModule.ps1 -AdminSet -AdminPassword <String>
	
		Set or change a admin password
		Manage-DellBiosPasswords-PSModule.ps1 -AdminSet -AdminPassword <String> -OldAdminPassword <String1>,<String2>,<String3>

		Clear existing admin password(s)
		Manage-DellBiosPasswords-PSModule.ps1 -AdminClear -OldAdminPassword <String1>,<String2>,<String3>

		Set a new admin password and set a new system password
		Manage-DellBiosPasswords-PSModule.ps1 -AdminSet -SystemSet -AdminPassword <String> -SystemPassword <String>
#>

#Parameters ===================================================================================================================

param(
	[Parameter(Mandatory=$false)][Switch]$AdminSet,
	[Parameter(Mandatory=$false)][Switch]$AdminClear,
	[Parameter(Mandatory=$false)][Switch]$SystemSet,
	[Parameter(Mandatory=$false)][Switch]$SystemClear,
	[Parameter(Mandatory=$false)][ValidateNotNullOrEmpty()][String]$AdminPassword,
	[Parameter(Mandatory=$false)][ValidateNotNullOrEmpty()][String[]]$OldAdminPassword,
	[Parameter(Mandatory=$false)][ValidateNotNullOrEmpty()][String]$SystemPassword,
	[Parameter(Mandatory=$false)][ValidateNotNullOrEmpty()][String[]]$OldSystemPassword,
	[Parameter(Mandatory=$false)][Switch]$NoUserPrompt,
	[Parameter(Mandatory=$false)][Switch]$ContinueOnError,
	[Parameter(Mandatory=$false)][Switch]$SMSTSPasswordRetry,
	[Parameter(Mandatory=$false)][ValidateScript({
		if($_ -notmatch "(\.log)")
		{
			throw "The file specified in the LogFile paramter must be a .log file"
		}
		return $true
	})]
	[System.IO.FileInfo]$LogFile = "$ENV:ProgramData\ConfigJonScripts\Dell\Manage-DellBiosPasswords-PSModule.log"
)

#Functions ====================================================================================================================



Function New-DellBiosPassword
{
	param(
		[Parameter(Mandatory=$true)][ValidateSet('Admin','System')]$PasswordType,
		[Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][String]$Password,
		[Parameter(Mandatory=$false)][ValidateNotNullOrEmpty()][String]$AdminPW
	)
	#Attempt to set the system password when the admin password is already set
	if($AdminPW)
	{
        $Error.Clear()
		try
		{
			Set-Item -Path "DellSmbios:\Security\$($PasswordType)Password" $Password -Password $AdminPW -ErrorAction Stop
		}
		catch
		{
			Set-Variable -Name "$($PasswordType)PWExists" -Value "Failed" -Scope Script
			Write-Host "Failed to set the $PasswordType password"
		}
		if(!($Error))
		{
			Write-Host "The $PasswordType password has been successfully set"
		}
    }
    #Attempt to set the admin or system password
    else
    {
        $Error.Clear()
        try
        {
            Set-Item -Path "DellSmbios:\Security\$($PasswordType)Password" $Password -ErrorAction Stop
        }
        catch
        {
            Set-Variable -Name "$($PasswordType)PWExists" -Value "Failed" -Scope Script
            Write-Host "Failed to set the $PasswordType password"
        }
        if(!($Error))
        {
            Write-Host "The $PasswordType password has been successfully set"
        }
    }
}

Function Set-DellBiosPassword
{
	param(
		[Parameter(Mandatory=$true)][ValidateSet('Admin','System')]$PasswordType,
		[Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][String]$Password,
		[Parameter(Mandatory=$false)][ValidateNotNullOrEmpty()][String[]]$OldPassword
	)
	Write-Host "Attempt to change the existing $PasswordType password"
	Set-Variable -Name "$($PasswordType)PWSet" -Value "Failed" -Scope Script
}

Function Clear-DellBiosPassword
{
	param(
		[Parameter(Mandatory=$true)][ValidateSet('Admin','System')]$PasswordType,
		[Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][String[]]$OldPassword	
	)
	Write-Host "Attempt to clear the existing $PasswordType password"
	Set-Variable -Name "$($PasswordType)PWClear" -Value "Failed" -Scope Script
}

Function Start-UserPrompt
{
	#Create a user prompt with custom body and title text if the NoUserPrompt variable is not set

	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][String[]]$BodyText,
		[Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][String[]]$TitleText
	)
	if(!($NoUserPrompt))
	{
		(New-Object -ComObject Wscript.Shell).Popup("$BodyText",0,"$TitleText",0x0 + 0x30) | Out-Null
	}
}

#Main program =================================================================================================================

#Configure Logging and task sequence variables
	$LogsDirectory = ($LogFile | Split-Path)
	if([string]::IsNullOrEmpty($LogsDirectory))
	{
		$LogsDirectory = $PSScriptRoot
	}
	else
	{
		if(!(Test-Path -PathType Container $LogsDirectory))
		{
			try
			{
				New-Item -Path $LogsDirectory -ItemType "Directory" -Force -ErrorAction Stop | Out-Null
			}
			catch
			{
				throw "Failed to create the log file directory: $LogsDirectory. Exception Message: $($PSItem.Exception.Message)"
			}
		}
	}



#Check if 32 or 64 bit architecture
if([System.Environment]::Is64BitOperatingSystem)
{
    $ModuleInstallPath = $env:ProgramFiles
}
else
{
    $ModuleInstallPath = ${env:ProgramFiles(x86)}    
}

#Verify the DellBIOSProvider module is installed

try
{
    $LocalVersion = Get-Package DellBIOSProvider -ErrorAction Stop | Select-Object -ExpandProperty Version
}
catch
{
    $Local = $true
    if(Test-Path "$ModuleInstallPath\WindowsPowerShell\Modules\DellBIOSProvider")
    {
        $LocalVersion = Get-Content "$ModuleInstallPath\WindowsPowerShell\Modules\DellBIOSProvider\DellBIOSProvider.psd1" | Select-String "ModuleVersion ="
        $LocalVersion = (([regex]".*'(.*)'").Matches($LocalVersion))[0].Groups[1].Value
    }
    else
    {
		Write-Host -ErrorMessage "DellBIOSProvider module not found on the local machine"
    }
}
if(($NULL -ne $LocalVersion) -and (!($Local)))
{
     Write-Host "Error"
}

#Verify the DellBIOSProvider module is imported

$ModuleCheck = Get-Module DellBIOSProvider
if($ModuleCheck)
{
    Write-Host "The DellBIOSProvider module is already imported"
   
}
else
{
    Write-Host "Importing the DellBIOSProvider module"
    $Error.Clear()
    try
    {
        Import-Module DellBIOSProvider -Force -ErrorAction Stop
    }
    catch 
    {
		Write-Host -ErrorMessage "Failed to import the DellBIOSProvider module" -Exception $PSItem.Exception.Message
    }
    if(!($Error))
    {
        Write-Host "Successfully imported the DellBIOSProvider module"
    }
}