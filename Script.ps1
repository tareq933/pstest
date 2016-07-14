#
# Script.ps1
#
<#  
Generate a report page about Lab Configuration with  details and give feedback output in html 
---------------------------------------------------------------------------------- 
 Configuring Users, Group and Permissions (lab7 )
 Active Directory & Group Policy (lab8-9 )
 ----------------------------------------------------------------------------------
In order to deploy the proposed system, I’m going to start with lab 7 as an example. 
In that example,  I’m going to retrieve information about a remote computer, and format it all in to a dynamic HTML report. 
Hopefully, we’ll be able to extend these techniques, and adapt those to our INFT2031 specific tasks.
I want the report to have ﬁve sections, each with the following information:
 
•  Part 1: VM image configuration (IPv4 address, MAC address, Subnet mask, Default Gateway)

• Part 2: Active Directory & Group Policy
1. Domain Configuration Information
2. Organizational Units 
3. Global Groups and Users 
4. Domain Local Groups 
5. Group Policy 

• Part 3: Install and configure DHCP
o    DHCP Scopes 
o    Exclusion Ranges
o    Reservations

•  Part 4: Installation of Active Directory
•  Part 5: Exploring Active Directory Domains: Users, Groups, OUs and Clients
o  Creating OUs 
o   Creating Users and Groups 

•  Part 6: Group Policy
o   Configure Log on Locally configuration setting
o   Delegate Control over OUs
o   Display a logon message for all users
o   Explore the password policy for the domain:
o   Remove Control Panel from all student user’s using GPOs  
o   Creating Home Folders
#>

# HTML Output Formatting
$a = "<style>"
$a = $a + "BODY{background-color:whit ;}"
$a = $a + "TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}"
$a = $a + "TH{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:thistle}"
$a = $a + "TD{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:PaleGoldenrod}"
$a = $a + "</style>"

# Global variables
$vUserName = (Get-Item env:\username).Value 			# This will get username using environment variable
# $vUserName= Get-VM -Name Serv2016-TP5

$vComputerName = (Get-Item env:\Computername).Value     # this is computer name using environment variable
$filepath = (Get-ChildItem env:\userprofile).value		# this is user profile  using environment variable
$filepath = (Get-ChildItem env:\userprofile).value		# this is user profile  using environment variable
#$filepath = Out-File D:\Demo\labReportTest1.html		# this is user profile  using environment variable

$title = “INFT 2031 – Systems and Network Administration”
$heading = “<CENTER><H2><FONT Color=black>INFT 2031 – Systems and Network Administration </FONT></H2></CENTER>”
ConvertTo-Html -Title $title -Head $heading  -Body "<h1>  </h1>" >  "$filepath\$vComputerName.html" 

#-----------------------------------------------

 <#   
PC Name: DESKTOP-BCRJIHT
  VMs:   INFT2031-PC1
         INFT2031-PC2     
         Serv2016-TP5  
#>

ConvertTo-Html -Body "<H1> Lab (7-9)  </H1>" >> "$filepath\$vComputerName.html"
ConvertTo-Html -Body "<H2> Part 1: VM image configuration </H2>" >> "$filepath\$vComputerName.html"

Get-NetIPConfiguration -Detailed -ComputerName $vComputerName | Select-Object ComputerName, DNSServer,IPv4Address `
                                          | ConvertTo-html  >>  "$filepath\$vComputerName.html"

Get-WmiObject win32_operatingsystem -ComputerName $vComputerName | select Caption,InstallDate,OSArchitecture,Version `
                                          | ConvertTo-html -Body "<H2>  </H2>" >>  "$filepath\$vComputerName.html"
										  
Get-WmiObject win32_logicalDisk -ComputerName $vComputerName | select DeviceID,VolumeName,@{Expression={$_.Size /1Gb -as [int]};Label="Total Size(GB)"},@{Expression={$_.Freespace / 1Gb -as [int]};Label="Free Size (GB)"} `
                                         | ConvertTo-html -Body "<H2>  </H2>" >>  "$filepath\$vComputerName.html"
										 
Get-WmiObject Win32_NetworkAdapterConfiguration |
Where-Object { $_.IPEnabled -eq $true }| select IPAddress,DefaultIPGateway,AddressFamily,DHCPEnabled,Description `
                                            | ConvertTo-html -Body "<H2> </H2>" >>  "$filepath\$vComputerName.html" 
                                                                                      
Get-NetIPConfiguration | Select-Object InterfaceAlias, InterfaceDescription,IPv4Address,IPv4DefaultGateway,DNSServer  `
                                          | ConvertTo-html -Body "<H2>  </H2>" >>  "$filepath\$vComputerName.html"
         
 Get-NetIPAddress | Select-Object IPv4Address `
                                          | ConvertTo-html -Body "<H2>  </H2>" >>  "$filepath\$vComputerName.html"       
                                            	
<#   
Output:
  OS: Windows Server 2012 R2
  IPv4 Address: 10.211.55.7 
  Subnet mask: 255.255.255.0 
  Default gateway: 10.211.55.1 
  Preferred DNS: 10.211.55.7 
 ------------------------------------------------------
#>
								 
ConvertTo-Html -Body "<H2> Part 2: Active Directory & Group Policy </H2>" >> "$filepath\$vComputerName.html" 

# Finding a domain controller
Get-ADDomainController -Discover -DomainName Warabrook.edu.au  |  Select Name,StartMode,State | 
ConvertTo-html  -Head $a -Body "<H2> Domain controller </H2>" >>  "$filepath\$vComputerName.html"										 
Get-ADDomainController | Select-Object ComputerObjectDN, DefaultPartition, Domain, Enabled, Forest `
                                          | ConvertTo-html -Body "<H2> Domain Configuration </H2>" >>  "$filepath\$vComputerName.html"
Get-ADOrganizationalUnit -Filter * | select Name `
                                          | ConvertTo-html -Body "<H2> Organizational Units: </H2>" >>  "$filepath\$vComputerName.html"
Get-ADGroup -Filter * | Select-Object DistinguishedName, Name, ObjectClass `
                                          | ConvertTo-html -Body "<H2> Domain Local Groups: </H2>" >>  "$filepath\$vComputerName.html"
Get-ADUser -Filter * | Select-Object DistinguishedName, Enabled,GivenName,Surname, Name, ObjectClass, SamAccountName, UserPrincipalName `
                                          | ConvertTo-html -Body "<H2> Global Groups and Users: </H2>" >>  "$filepath\$vComputerName.html"

<#   
Output:

  IPv4 Address: ____________________________________ 
  Subnet Mask: ____________________________________ 
  Default Gateway: ______________________________ 
  DNS Server: ____________________________________ 
  DHCP Server: ____________________________________ 
  Lease Obtained: ______________________________ 
  Lease Expires: ____________________________________
  ------------------------------------------------------
#>	

ConvertTo-Html -Body "<H2> Part 3:Install and configure DHCP </H2>" >> "$filepath\$vComputerName.html" 

Get-DhcpServerv4Scope -ComputerName $vComputerName | select ScopeId,SubnetMask,Name,State,StartRange,EndRange,LeaseDuration `
                                          | ConvertTo-html -Body "<H2> DHCP Server Scope </H2>" >>  "$filepath\$vComputerName.html"

Get-DhcpServerv4ExclusionRange -ComputerName $vComputerName | select ScopeId,StartRange,EndRange `
                                          | ConvertTo-html -Body "<H2> DHCP Server Scope </H2>" >>  "$filepath\$vComputerName.html"

#------------------------------------------------------
ConvertTo-Html -Body "<H2> Part 4: Installation of Active Directory </H2>" >> "$filepath\$vComputerName.html" 

Get-WindowsFeature | Where { $_.Installed} | Select-Object Name,Display `
                                          | ConvertTo-html -Body "<H2> Features & Roles installation: </H2>" >>  "$filepath\$vComputerName.html"

<#   
Output:

  ------------------------------------------------------
#>	


ConvertTo-Html -Body "<H2> Part 5: Active Directory Domains: Users, Groups, OUs and Clients </H2>" >> "$filepath\$vComputerName.html"


# Search for accounts with non-expiring passwords
Search-ADAccount –PasswordNeverExpires | Select-Object Name `
                                          | ConvertTo-html -Body "<H2> Search for accounts with non-expiring passwords </H2>" >>  "$filepath\$vComputerName.html"

# Search for accounts that haven’t signed-on for 90 days
Search-AdAccount –accountinactive –timespan 90.00:00:00 | Select-Object Name `
                                          | ConvertTo-html -Body "<H2>  Search for accounts that haven’t signed-on for 90 days </H2>" >>  "$filepath\$vComputerName.html"
# Search for locked out accounts
Search-AdAccount –Lockedout | Select-Object Name `
                                          | ConvertTo-html -Body "<H2> Search for locked out accounts </H2>" >>  "$filepath\$vComputerName.html"
# Search for disabled accounts
Search-AdAccount –AccountDisabled | Select-Object Name `
                                          | ConvertTo-html -Body "<H2> Search for disabled accounts </H2>" >>  "$filepath\$vComputerName.html"				 

<#   
Output:

  ------------------------------------------------------
#>	

ConvertTo-Html -Body "<H1>  </H1>" >> "$filepath\$vComputerName.html"
function Get-ADObjectsCount {
[CmdletBinding()]
param(
)
$Users = Get-ADUser -Filter *
$Groups = Get-ADGroup -Filter *
$Computers = Get-ADComputer -Filter *
$DomainName = (Get-ADDomain).Name
"{0} Users, {1} Computers and {2} Groups found in {3} Domain" -f
$Users.Count,$Computers.Count,$Groups.Count,$DomainName
}
$count= Get-ADObjectsCount | ConvertTo-html -Body "<H2>$count </H2>" >>  "$filepath\$vComputerName.html"

#Results
ConvertTo-Html -Body "<H2> -------------------- </H2>" >> "$filepath\$vComputerName.html"
ConvertTo-Html -Body "<H1> Check your results : </H1>" >> "$filepath\$vComputerName.html"

# check the computer neame
if($vComputerName -eq "INFT2031-SERVER") {

ConvertTo-html -Body "<H3> $vComputerName is Done </H3>" >>  "$filepath\$vComputerName.html" 
} else {
ConvertTo-html -Body "<H3> Not completed </H3>" >>  "$filepath\$vComputerName.html" 
}	


# Check for Windows Feature installation
Get-WindowsFeature | Where { $_.Installed} |
Sort-Object status -descending |
foreach {
if ( $_.Name -eq "AD-Domain-Services")
{ConvertTo-html -Body "<H3> <FONT Color=Green> AD-Domain-Services is installed</FONT> </H3>" >>  "$filepath\$vComputerName.html"}
}

# DHCP
Get-WindowsFeature | Where { $_.Installed} |
Sort-Object status -descending |
foreach {
if ( $_.Name -eq "DHCP")
{ConvertTo-html -Body "<H3> <FONT Color=Green> DHCP is installed </FONT></H3>" >>  "$filepath\$vComputerName.html"}
}
# DNS
Get-WindowsFeature | Where { $_.Installed} |
Sort-Object status -descending |
foreach {
if ( $_.Name -eq "DNS")
{ConvertTo-html -Body "<H3> <FONT Color=Green> DNS is installed </FONT></H3>" >>  "$filepath\$vComputerName.html"}
}
                                         
#Import the CSV file into a variable
$user = Import-CSV C:\GroupMembership.csv
#Loop through each entry in CSV file
foreach($entry in $user) {
#Read the group Name
$userName = $entry.GroupName
#if Object type is Computer, then suffix it with $ sign
if($entry.ObjectClass -eq "user") {
ConvertTo-html -Body "<H3> <FONT Color=Green>$entry.DistinguishedName Done</FONT> </H3>" >>  "$filepath\$vComputerName.html"
} else {
ConvertTo-html -Body "<H3> <FONT Color=red> $entry.DistinguishedName Not completed </FONT> </H3>" >>  "$filepath\$vComputerName.html"

}}






#Import the CSV file into a variable
$UOs = Import-CSV C:\AD_UOs.csv
#Loop through each entry in CSV file
foreach($entry in $UOs) {
#Read the group Name
$UOsName = $entry.Name
#if Object type is Computer, then suffix it with $ sign
if($entry.Name -eq "Staff") {
ConvertTo-html -Body "<H3><FONT Color=Green>$entry Done</FONT> </H3>" >>  "$filepath\$vComputerName.html" 
} else {
ConvertTo-html -Body "<H3> <FONT Color=red>$entry Not completed </FONT>  </H3>" >>  "$filepath\$vComputerName.html"  
}}

#------------------------------------------------------
										 
$Report = "The Report is generated On  $(get-date) by $((Get-Item env:\username).Value) on computer $((Get-Item env:\Computername).Value)"
$Report  >> "$filepath\$vComputerName.html" 

invoke-Expression "$filepath\$vComputerName.html"  

#--------------END of SCRIPT ------------------------
