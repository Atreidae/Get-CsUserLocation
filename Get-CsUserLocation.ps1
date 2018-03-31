<#  
.SYNOPSIS  
	Returns the user location as an object.
	Uses a UCMA call to query a Skype4B FrontEnd for a user's location based on information present in the LIS
	Requires the LIS to be correctly defined.


.DESCRIPTION  
	Created by James Arber. www.skype4badmin.com
	Built with PoshTools www.poshtools.com
    
	
.NOTES  
    Version      	   	: 0.1 (Devel)
	Date			    : 31/03/2018
	Lync Version		: Tested against Skype4B 2015
    Author    			: James Arber
	Header stolen from  : Greig Sheridan who stole it from Pat Richard's amazing "Get-CsConnections.ps1"
							
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
								Pat Richard http://www.ehloworld.com @patrichard

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
	[single]$ScriptVersion = "0.10"
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
         #If the log entry is just informational (less than 2), output it to write verbose
		 if ($severity -le 2) {"Info: $date $Message"| Write-Host -ForegroundColor Green}
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

#endregion Functions

#Check to see if the script has actually been configured

if ($password -eq "#####") {
		Write-Log "Script Not Configured, Password set to default. Aborting" -severity 3
		Write-log "You need to configure this scrip before using it. Please edit this script file and add edit the config region"
		exit
}
Get-ScriptUpdate #Check for an update

#Import the Skype for Business / Lync Modules and error if not found
	Write-Log -component "Script Block" -Message "Checking for Lync/Skype management tools"
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


 write-log "Attempting to download S4B Autodiscover Information" -severity 1
try{
	$data = Invoke-WebRequest -Uri $s4bAutodiscover -Method GET -ContentType "application/json" -UseBasicParsing
 	$baseurl = (($data.content | ConvertFrom-JSON)._links.user.href).split("/")[0..2] -join "/"
 	$oauthurl = ($data.content | convertfrom-json)._links.user.href
}catch{
	 write-log "Could not retrieve S4B Autodiscover information on" $s4bAutodiscover "Update the S4B Autodiscover URL and try again" -severity 4
	exit 1
}

write-log "AuthN to S4B to get oAuth Token" -severity 1
try{
	$postParams = @{grant_type="password";username=$username;password=$password}
 	$data = Invoke-WebRequest -Uri "$baseurl/WebTicket/oauthtoken" -Method POST -Body $postParams -UseBasicParsing
 	$authcwt = ($data.content | ConvertFrom-JSON).access_token
}catch{
	write-log "We couldn't AuthN with the username & password provided. Update and try again." -severity 4
	exit 1
}

write-log  "Downloading application URLs" -severity 1
try{
	$data = Invoke-WebRequest -Uri "$oauthurl" -Method GET -Headers @{"Authorization"="Bearer $authcwt"} -UseBasicParsing
	$rootappurl = ($data.content | ConvertFrom-JSON)._links.applications.href
}catch{
	write-log "Unable to get Application URLs" -severity 4
	exit 1
}

<# Create the UCWA Application

The following script will create an application on the UCWA endpoint. The Endpoint ID you can make up yourself. Same for the Application name.#>

write-log -message "Creating App Instance" -severity 1
$userAgent = "Get-CsUserLocation Version $Scriptversion"
$EndpointID = "d90347cd-31b9-4cd7-9abe-7814fe52c43b"

 
try{
	$postparams = @{UserAgent=$userAgent;EndpointId=$EndpointID;Culture="en-US"} | ConvertTo-JSON
    $data = Invoke-WebRequest -Uri "$rootappurl" -Method POST -Body "$postparams" -Headers @{"Authorization"="Bearer $authcwt"} -ContentType "application/json" -UseBasicParsing

    $script:appurl = $(($data.content | ConvertFrom-JSON)._links.self.href)
	$script:appurl = "$($rootappurl.split("/")[0..2] -join "/")$(($data.content | ConvertFrom-JSON)._links.self.href)"

    $meurl = $(($data.Content | ConvertFrom-JSON)._embedded.me._links)   
    $peopleurl = $(($data.Content | ConvertFrom-JSON)._embedded.people._links)   

	$appid = $appurl.split("/")[-1]
	$operationID = (($data.content | ConvertFrom-JSON)._embedded.communication | GM -Type Noteproperty)[0].name

}

catch{
	 write-log "Unable to create application instance" -severity 4
	exit 1
}

Write-Log "Downloading user presence from ($appurl + /people/ + $sipAddress + /Location)"
$location = (Invoke-WebRequest -Uri ($script:appurl + "/people/" + $SipAddress + "/Location") -method GET -Headers @{"Authorization"="Bearer $authcwt"} -ContentType "application/json" -UseBasicParsing | ConvertFrom-Json)

if ($location.location -eq $null) {
	Write-Log "Users location is not in the LIS database and user has not input a location. Cannot locate" -severity 3
}
else {
	Write-Log "Users location is: $($location.location)"
	Write-Log "Outputting object"
	}

	Write-Output $location.location
