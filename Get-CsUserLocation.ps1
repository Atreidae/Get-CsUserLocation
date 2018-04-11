<#  
.SYNOPSIS  
	Returns the user location as an object.
	Uses a UCMA call to query a Skype4B FrontEnd for a user's location based on information present in the LIS
	Requires the LIS to be correctly defined.


.DESCRIPTION  
	Created by James Arber. www.skype4badmin.com
	Built with PoshTools www.poshtools.com
    
	
.NOTES  
    Version      	   	: 0.3 (Devel)
	Date			    : 11/04/2018
	Lync Version		: Tested against Skype4B 2015
    Author    			: James Arber
	Header stolen from  : Greig Sheridan who stole it from Pat Richard's amazing "Get-CsConnections.ps1"

	## Update History

	:v0.3:	Verbose Build
			- Additional logging. Verbose logging support

	:v0.2:	Security Build
			- Added External config file and credential encryption
			
	:v0.11:	Debugging Build
			- Added additional OAuth Debugging

	:v0.1:	Internal Build
	
.LINK  
    https://www.skype4badmin.com

.KNOWN ISSUES
   None at this stage, this is however in development code and bugs are expected

.EXAMPLE Locates and returns the LIS entry for the user with the sip address james.arber@skype4badmin.com
    PS C:\> .\Get-CsUserLocation.ps1 james.arber@Skype4badmin.com


.PARAMETER SipAddress
SIP address of user to perform the lookup against.

.PARAMETER -DisableScriptUpdate
Stops the script from checking online for an update and prompting the user to download. Ideal for scheduled tasks


.INPUT
Get-CsUserLocation accepts pipeline input of single objects with named properties matching parameters.

.Output
Custom.PsObject. Get-CsUserLocation returns a the results of a migration as a custom object on the pipeline.

	Acknowledgements 	: Testing and Advice
  								Greig Sheriden https://greiginsydney.com/about/ @greiginsydney

						: Auto Update Code
								Pat Richard https://ucunleashed.com @patrichard

						: Proxy Detection
								Michel de Rooij	http://eightwone.com

						: UCWA Application code
								Darren (DOC) Robinson https://blog.kloud.com.au/2016/09/07/querying-skype-for-business-online-using-ucwa-and-powershell/
#>

[CmdletBinding(DefaultParametersetName="Common")]
param(
	[Parameter(Mandatory=$true, Position=1)] [string]$SipAddress,
	[Parameter(Mandatory=$false, Position=2)] [switch]$DisableScriptUpdate,
	[Parameter(Mandatory=$false, Position=3)] [string]$LogFileLocation
	)

 #############################
 #### UPDATE THESE SETTINGS### 
 #############################

 #This should NOT be your admin account, if you have a service account etc, use that instead. Otherwise create an AD account and enable it for S4B

 $username = "example\user" #username (in UPN or NetBios format) of a user authorised to use UCMA
 $password = "#####"  #Their password (We wont log it, promise)
 $s4bAutodiscover = "https://lyncdiscover.skype4badmin.com" #This should by "Lyncdiscover.(yoursipdomain)"

 ### END UPDATE THESE SETTINGS ###

 

 
#############################
# Script Specific Variables #
#############################
	[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
	[single]$ScriptVersion = "0.3"
	[string]$GithubRepo = "Get-CsUserLocation"
	[string]$GithubBranch = "master"
	[string]$BlogPost = "http://www.skype4badmin.com/australian-holiday-rulesets-for-response-group-service/" #todo
	

	
#endregion config
#region bootstrap
	$pwd = $password | convertto-securestring -AsPlainText -Force #Move the user password in to secure ram
	$StartTime = Get-Date
	Write-Host "Info: Get-CsUserLocation.ps1 Version $ScriptVersion started at $StartTime" -ForegroundColor Green
	If (!$LogFileLocation) {$LogFileLocation = $PSCommandPath -replace ".ps1",".log"} #Where do we store the log files? (In the same folder by default)
	$DefaultLogComponent = "Unknown" 
	Write-Host "Info: Loading Functions" -ForegroundColor Green
#endregion bootstrap



#region Functions

 ##################
  # Function Block #
  ##################
Function Write-Log {
    PARAM(
         [String]$Message,
         [String]$Path = $LogFileLocation,
         [int]$severity = 1,
         [string]$component = "Default"
         )

         $TimeZoneBias = Get-WmiObject -Query "Select Bias from Win32_TimeZone"
         $Date= Get-Date -Format "HH:mm:ss"
         $Date2= Get-Date -Format "MM-dd-yyyy"

         $MaxLogFileSizeMB = 10
         If(Test-Path $Path)
         {
            if(((gci $Path).length/1MB) -gt $MaxLogFileSizeMB) # Check the size of the log file and archive if over the limit.
            {
                $ArchLogfile = $Path.replace(".log", "_$(Get-Date -Format dd-MM-yyy_hh-mm-ss).lo_")
                ren $Path $ArchLogfile
            }
         }
         
		 "$env:ComputerName date=$([char]34)$date2$([char]34) time=$([char]34)$date$([char]34) component=$([char]34)$component$([char]34) type=$([char]34)$severity$([char]34) Message=$([char]34)$Message$([char]34)"| Out-File -FilePath $Path -Append -NoClobber -Encoding default
		 #If the log entry is verbose (1), output it to write verbose
		 if ($severity -eq 1) {"$date $Message"| Write-verbose}
         #If the log entry is just informational (eq 2), output it to write host
		 if ($severity -eq 2) {"Info: $date $Message"| Write-Host -ForegroundColor Green}
		 #If the log entry has a severity of 3 assume its a warning and write it to write-warning
		 if ($severity -eq 3) {"$date $Message"| Write-Warning}
		 #If the log entry has a severity of 4 or higher, assume its an error and display an error message (Note, critical errors are caught by throw statements so may not appear here)
		 if ($severity -ge 4) {"$date $Message"| Write-Error}
} 

Function Get-IEProxy {
	Write-Log "Checking for proxy settings" -severity 1
        If ( (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyEnable -ne 0) {
            $proxies = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').proxyServer
            if ($proxies) {
                if ($proxies -ilike "*=*") {
                    return $proxies -replace "=", "://" -split (';') | Select-Object -First 1
                }
                Else {
                    return ('http://{0}' -f $proxies)
                }
            }
            Else {
                return $null
            }
        }
        Else {
            return $null
        }
    }

Function Get-ScriptUpdate {
	if ($DisableScriptUpdate -eq $false) {
		Write-Log -component "Self Update" -Message "Checking for Script Update" -severity 1
		Write-Log -component "Self Update" -Message "Checking for Proxy" -severity 1
			$ProxyURL = Get-IEProxy
		If ( $ProxyURL) {
			Write-Log -component "Self Update" -Message "Using proxy address $ProxyURL" -severity 1
		   }
		Else {
			Write-Log -component "Self Update" -Message "No proxy setting detected, using direct connection" -severity 1
				}
	  }
	  $GitHubScriptVersion = Invoke-WebRequest "https://raw.githubusercontent.com/atreidae/$GitHubRepo/$GitHubBranch/version" -TimeoutSec 10 -Proxy $ProxyURL
        If ($GitHubScriptVersion.Content.length -eq 0) {
			Write-Log -component "Self Update" -Message "Error checking for new version. You can check manualy here" -severity 3
			Write-Log -component "Self Update" -Message $BlogPost -severity 1
			Write-Log -component "Self Update" -Message "Pausing for 5 seconds" -severity 1
            start-sleep 5
            }
        else { 
                if ([single]$GitHubScriptVersion.Content -gt [single]$ScriptVersion) {
				Write-Log -component "Self Update" -Message "New Version Available" -severity 3
                   #New Version available

                    #Prompt user to download
				$title = "Update Available"
				$message = "an update to this script is available, did you want to download it?"

				$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
					"Launches a browser window with the update"

				$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
					"No thanks."

				$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

				$result = $host.ui.PromptForChoice($title, $message, $options, 0) 

				switch ($result)
					{
						0 {
							Write-Log -component "Self Update" -Message "User opted to download update" -severity 1
							start $BlogPost #todo F
							Write-Log -component "Self Update" -Message "Exiting Script" -severity 3
							Exit
						}
						1 {Write-Log -component "Self Update" -Message "User opted to skip update" -severity 1
									
							}
							
					}
                 }   
                 Else{
                 Write-Log -component "Self Update" -Message "Script is up to date on $GithubBranch branch" -severity 1
                 }
        
	       }

	}

function Connect-CsUCWAAPI{

#Not implemented

}

Function Test-CsAutoDiscover {
	PARAM ([String]$s4bAutoDiscover)
	
	 Write-Log -component "Config" -Message "Testing Autodiscover" -severity 2
	 Write-Log -component "Config" -Message "User defined url is $s4bAutodiscover" -severity 1
	try{
		Write-Log -component "Config" -Message "Invoking webrequest" -severity 1
		$data = Invoke-WebRequest -Uri $s4bAutodiscover -Method GET -ContentType "application/json" -UseBasicParsing
		 Write-Log -component "Config" -Message "got data, parsing" -severity 1
 		$baseurl = (($data.content | ConvertFrom-JSON)._links.user.href).split("/")[0..2] -join "/"
		 Write-Log -component "Config" -Message "Found BaseURL $baseurl" -severity 1
 		$oauthurl = ($data.content | convertfrom-json)._links.user.href
		 Write-Log -component "Config" -Message "Found OauthURL $oauthurl" -severity 1
		 Write-Log -component "Config" -Message "AutoDiscover test passed, Found UCWA details" -severity 2
	}catch{
		Write-Log -component "Config" -Message "Something went wrong getting to the AutoDiscover URL or the data was bad" -severity 3
	}

}



Function Read-ConfigFile {
	Write-Log -component "Read-ConfigFile" -Message "Writing Config file" -severity 2
    If(!(Test-Path $Script:ConfigPath)) {
			Write-Log -component "Config" -Message "Could not locate config file!" -severity 5
			Throw "No Config File!"
			}
			Else {
			Write-Log -component "Config" -Message "Found Config file in the specified folder" -severity 1
				}

	Write-Log -component "Read-ConfigFile" -Message "Pulling JSON File" -severity 1
	[Void](Remove-Variable -Name Config -Scope Script )
    Try{
		$Script:Config=@{}
		$Script:Config.AESKey = New-Object Byte[] 32
		$Script:Config = (ConvertFrom-Json (Get-Content -raw $Script:ConfigPath))
		Write-Log -component "Read-ConfigFile" -Message "Config File Read OK" -severity 2
		Write-Log -component "Read-ConfigFile" -Message "Reading Key File" -severity 1
		$Script:Config.AESKey = New-Object Byte[] 32
		$AESKeyFilePath = $Script:ConfigPath -replace ".json",".key" #The Key should be in the same folder as the config 
		$Script:Config.AESKey = Get-Content $AESKeyFilePath  
		}
	Catch {
		Write-Log -component "Read-ConfigFile" -Message "Error reading Config or Key file, Loading Defaults" -severity 3
		Load-DefaultConfig
		}

	Write-Log -component "Read-ConfigFile" -Message "Decrpyting Bot Password" -severity 2
	#Grab the Variable from the Config file, stuff it into a SecureString, Then decrypt it with BSTR
	$SecurePassword = (ConvertTo-SecureString -string $Script:Config.BotPassword  -key $Script:Config.AESKey)
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    $Txt_BotPassword.text = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

	
    Write-Log -component "Read-ConfigFile" -Message "Importing Objects" -severity 1


}

Function Write-ConfigFile {
	Write-Log -component "Write-ConfigFile" -Message "Writing Config file" -severity 2
	Write-Log -component "Write-ConfigFile" -Message "Writing AES Key to File" -severity 1
	# Store the AESKey into a file. 
	Try{
		$AESKeyFilePath = $Script:ConfigPath -replace ".json",".key" #Store the Key in the same folder as the config 
		Set-Content $AESKeyFilePath $Script:Config.AESKey   # Any existing AES Key file will be overwritten		
		Write-Log -component "Write-ConfigFile" -Message "Key File Saved" -severity 2
		}
	Catch {
		Write-Log -component "Write-ConfigFile" -Message "Error writing Key file" -severity 3
		}
	
	#Pull Data from GUI to store in array
	Write-Log -component "Write-ConfigFile" -Message "Encrpyting Bot Password" -severity 2
	$SecurePassword = (ConvertTo-SecureString -string $Txt_BotPassword.text -asplaintext -force) # is this needed if we are using get-credential?
	$Script:Config.BotPassword = (ConvertFrom-SecureString -securestring $SecurePassword -key $Script:Config.AESKey)
	Write-Log -component "Write-ConfigFile" -Message "Importing Objects" -severity 1
    #Config Page
	$Script:Config.BotAddress = $Txt_BotSipAddr.Text 
	$Script:Config.AutoDiscover = $tbx_Autodiscover.text

	#Remove the AES Key from the Config array, this stops it being stored in the json file
	$Script:Config.AesKey = $null
	
	#Write the Json File
	Try{
		(ConvertTo-Json $Script:Config) | Out-File -FilePath $Script:ConfigPath -Encoding default
		Write-Log -component "Write-ConfigFile" -Message "Config File Saved" -severity 2
		}
	Catch {
		Write-Log -component "Write-ConfigFile" -Message "Error writing Config file" -severity 3
		}
}

Function Load-DefaultConfig {
	#Set Variables to Defaults
	#Remove and re-create the Config Array
		[Void](Remove-Variable -Name Config -Scope Script )
		$Script:Config=@{}
	#Populate with Defaults
			[Float]$Script:Config.ConfigFileVersion = "0.1"
			[string]$Script:Config.Description = "Get-CsUserLocation Configuration file. See Skype4BAdmin.com for more information"
			[string]$Script:Config.Warning = "whilst passwords are encrpyted in this file, the Keys are also stored here! Please dont treat it as secure"
			[string]$Script:Config.BotPassword = "#####"
			[string]$Script:Config.BotAddress = "GetCsUserLocation@Skype4bAdmin.com"
			[string]$Script:Config.AutoDiscover = "LyncDiscover@Skype4BAdmin.com"

	#Generate an AES Key for password protection
	
			$Script:Config.AESKey = New-Object Byte[] 32
			[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Script:Config.AESKey)

}
#endregion Functions

#Check to see if the script has actually been configured

if ($password -eq "#####") {
		Write-Log "Script Not Configured, Password set to default. Aborting" -severity 3
		Write-log "You need to configure this scrip before using it. Please edit this script file and add edit the config region"
		exit
}
Get-ScriptUpdate #Check for an update

#Import the Skype for Business / Lync Modules and error if not found
	Write-Log -component "Script Block" -Message "Checking for Lync/Skype management tools" -severity 2
	$ManagementTools = $false
	if(!(Get-Module "SkypeForBusiness")) {Import-Module SkypeForBusiness -Verbose:$false}
	if(!(Get-Module "Lync")) {Import-Module Lync -Verbose:$false}
	if(Get-Module "SkypeForBusiness") {$ManagementTools = $true}
	if(Get-Module "Lync") {$ManagementTools = $true}
	if(!$ManagementTools) {
		Write-Log 
		Write-Log -component "Script Block" -Message "Could not locate Lync/Skype4B Management tools. Script Exiting" -severity 5 
		$AllGood=$false
		Throw "Unable to load Skype4B/Lync management tools"
		}




 Test-CsAutoDiscover
 Write-log "Attempting to download S4B Autodiscover Information" -severity 2
try{
	write-log "Requesting URL $s4bAutodiscover" -severity 1
	$data = Invoke-WebRequest -Uri $s4bAutodiscover -Method GET -ContentType "application/json" -UseBasicParsing
	write-log "Raw data $data" -severity 1
 	$baseurl = (($data.content | ConvertFrom-JSON)._links.user.href).split("/")[0..2] -join "/"
	write-log "Found base url $baseurl" -severity 1
 	$oauthurl = ($data.content | convertfrom-json)._links.user.href
	write-log "Found oauth url $oauthurl" -severity 1
}catch{
	 write-log "Could not retrieve S4B Autodiscover information on" $s4bAutodiscover "Update the S4B Autodiscover URL and try again" -severity 4
	exit 1
}

write-log "Authenticating to Webservices to get oAuth Token" -severity 2
try{
	$postParams = @{grant_type="password";username=$username;password=$password}
	write-log "Requesting URL $baseurl/WebTicket/oauthtoken" -severity 1
 	$data = Invoke-WebRequest -Uri "$baseurl/WebTicket/oauthtoken" -Method POST -Body $postParams -UseBasicParsing
	write-log "Oauth Returned" -severity 1
	write-log "$data.content" -severity 1
 	$authcwt = ($data.content | ConvertFrom-JSON).access_token
	write-log "Oauth Token $authcwt" -severity 1
}catch{
	write-log "We couldn't Authenticate with the username & password provided. Update and try again." -severity 4
	exit 1
}

write-log  "Downloading application URLs" -severity 2
try{
	write-log "Requesting URL $oauthurl witha access token $authcwt" -severity 1
	$data = Invoke-WebRequest -Uri "$oauthurl" -Method GET -Headers @{"Authorization"="Bearer $authcwt"} -UseBasicParsing
	write-log "Raw data $data" -severity 1
	$rootappurl = ($data.content | ConvertFrom-JSON)._links.applications.href
	write-log "Rootapp url returned $rootappurl" -severity 1
}catch{
	write-log "Unable to get Application URLs" -severity 4
	exit 1
}

<# Create the UCWA Application

The following script will create an application on the UCWA endpoint. The Endpoint ID you can make up yourself. Same for the Application name.#>

write-log -message "Creating App Instance" -severity 2
$userAgent = "Get-CsUserLocation Version $Scriptversion"
$EndpointID = "d90347cd-31b9-4cd7-9abe-7814fe52c43b"

 
try{
	$postparams = @{UserAgent=$userAgent;EndpointId=$EndpointID;Culture="en-US"} | ConvertTo-JSON

	write-log "Requesting URL $oauthurl witha application details $postparams" -severity 1
    $data = Invoke-WebRequest -Uri "$rootappurl" -Method POST -Body "$postparams" -Headers @{"Authorization"="Bearer $authcwt"} -ContentType "application/json" -UseBasicParsing
	write-log "Raw data $data" -severity 1
    $script:appurl = $(($data.content | ConvertFrom-JSON)._links.self.href)
	$script:appurl = "$($rootappurl.split("/")[0..2] -join "/")$(($data.content | ConvertFrom-JSON)._links.self.href)"
	write-log "Appurl $script:appurl" -severity 1
    $meurl = $(($data.Content | ConvertFrom-JSON)._embedded.me._links)   
    $peopleurl = $(($data.Content | ConvertFrom-JSON)._embedded.people._links)   
	$appid = $appurl.split("/")[-1]
	write-log "meurl $meurl" -severity 1
	write-log "peopleurl $peopleurl" -severity 1
	write-log "appid $appid" -severity 1

	$operationID = (($data.content | ConvertFrom-JSON)._embedded.communication | GM -Type Noteproperty)[0].name
	write-log "appid $opperationid" -severity 1
}

catch{
	write-log "Unable to create application instance" -severity 4
	exit 1
}

Write-Log "Downloading user location from ($appurl + /people/ + $sipAddress + /Location)" -severity 1
$location = (Invoke-WebRequest -Uri ($script:appurl + "/people/" + $SipAddress + "/Location") -method GET -Headers @{"Authorization"="Bearer $authcwt"} -ContentType "application/json" -UseBasicParsing | ConvertFrom-Json)

if ($location.location -eq $null) {
	Write-Log "Users location is not in the LIS database and user has not input a location. Cannot locate" -severity 3
}
else {
	Write-Log "Users location is: $($location.location)" -severity 2
	Write-Log "Outputting object" -severity 1
	}

	Write-Output $location.location
