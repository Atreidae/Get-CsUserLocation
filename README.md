# Get-CsUserLocation
Returns the user location as an object.
Uses a UCMA call to query a Skype4B FrontEnd for a user's location based on information present in the LIS
Requires the LIS to be correctly defined.

## DESCRIPTION  
Created by James Arber. [www.skype4badmin.com](http://www.skype4badmin.com)
Built using Visual Studio and Poshtools Pro

    
	
## NOTES 

Version			: 0.1

Date			: 31/03/2018

Lync Version	: Tested against Skype4B 2015

Author    		: James Arber

Header stolen from  	: Greig Sheridan who stole it from Pat Richard's amazing "Get-CsConnections.ps1"

## Update History

**:v0.10: Internal Build**
	
## LINK  
TODO

## KNOWN ISSUES
   None at this stage, this is however in development code and bugs are expected

## Script Specifics
**EXAMPLE** Locates and returns the LIS entry for the user with the sip address james.arber@skype4badmin.com
`PS C:\> .\Get-CsUserLocation.ps1 james.arber@Skype4badmin.com

**PARAMETER SipAddress**
SIP address of user to perform the lookup against.

**PARAMETER -DisableScriptUpdate**
Stops the script from checking online for an update and prompting the user to download. Ideal for scheduled tasks

**INPUT**
Get-CsUserLocation accepts pipeline input of single objects with named properties matching parameters.

**Output**
Custom.PsObject. Get-CsUserLocation returns a the results of a migration as a custom object on the pipeline.

