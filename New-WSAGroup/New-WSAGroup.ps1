<#
.Synopsis
   Name: Add-NewWSAGroup.1.0.ps1
   Version: 1.3
   Author: Konstantin Atanassov (FG-811), DXC
   Company Name: BMW Group

   Short Description: The Script 'Add-NewWSAGroup.x.x.ps1' is designed to automatically create WSA Groups and set their membership in the proper Admin Role Group.


.DESCRIPTION

   Author: Konstantin Atanassov (FG-810/811), DXC
   Company Name: BMW Group

   Requirements: 
   - requires account privileges for all 10 domains, because of Domain switching mechanism without credentials prompt;
   - requires Read/Write Access to the path "OU=WSA,OU=TPG-Pgroups,OU=SCAPPLICATION,OU=Resources,$domain_DN", where the variable $domain_DN is the derived Domain DistinguishedName
   - must be able to become a member of the Admin Roles (Security Groups), located under (example): "OU=ParentOU-AdministrationRoles,OU=ParentOU,OU=Resources,$domain_DN"

   The Script 'Add-NewWSAGroup.x.x.ps1' performs the following actions:
    - Checks the Script Folder for files, sorted by name and age, and starts with the oldest one.
    - Reads and interpretes the Input Data.
        () Those are the Columns and their content:
            () Name - the Name of the new WSA Group to be created
            () ExtAttr1 - extension Attribute 1, contains at least two OU responsibles in q-account format
            () ExtAttr5 - extension Attribute 5, a four-digit coding on: allowing auto e-mails (default: ON), allowing Groups as members (default: OFF), max age of the WSA Group (default: 12 months);
            () TargetRole - the DistinguishedName of the Admin Roles Group, where the WSA Group should become a Member Of;
        () The Input File can be created manually, in emergency situaitons only
        () The Input File can be created automatically by the ADRM.Client Script, which is the intended way of doing it, for prevention of syntax issues;
    - Asks for a Decision, to confirm with actions or exit script.
    - Performs a Main Loop against each Line in the Input Line, which does the following Steps:
        () Checks the required Domain as per Input Line
        () Sets the current Domain to match the required one;
            () No Credentials are asked, assuming that the current account has read/write access to the WSA Group OU in all 10 Domains;
        () Checks the input line parameters: ExtAttr1,ExtAttr5
            () Checks the existence of the User Accounts: EUROPE and EMEADECENTRAL only
        () {switchable} Checks, if the asked WSA Group doesn't already exist.
            () Checks the content of the WSA Groups OU: "OU=WSA,OU=TPG-Pgroups,OU=SCAPPLICATION,OU=Resources,$domain_DN", where the variable $domain_DN is the derived Domain DistinguishedName
        () Creates a new WSA Groups, with the given Parameters, if the previous checks are all OK.
            () the Name of the WSA Group is resulting from the 'Name' column of the current line
            () Properties and Attributes handled: ExtAttr1,ExtAttr5,Description,Notes
            () ProtectfromAccidentalDeletion is TRUE
            () Creation Path - WSA Groups OU:  "OU=WSA,OU=TPG-Pgroups,OU=SCAPPLICATION,OU=Resources,$domain_DN", where the variable $domain_DN is the derived Domain DistinguishedName
        () Double checks the WSA Group creation
        () {switchable} Sets Membership of the WSA Group, against the AdminRole, defined in the field 'TargetRole'
        () The Script creates an After-action Log, containing Outcome and Error Informaiton about the just completed acitons;
    - after all actions are completed, the Input File is renamed, with the phrase "DONE_" attached at its front.
        () This way, when the script is ran the next time, it will surely skipp the already completed task (previously renamed Input File), if there are more than one;
        () in case a task has to be reran, simply rename the Input file back, deleting the "DONE_" part at its front.

    The Script has the following operation modes:
    - Standard Mode of Operation - will do everything menioned above, exept double-checking 
    - skipWSAgroupmembership - Switch - for skipping the part, where WSA Groups are set as members of the Admin Role Groups;
    - DoubleCheck_OUResponsibles - Switch - for double checking the provided User Q-Accounts in 'ExtAttr1'
    - DEBUG: in Script only, not a parameter; Setting the Variable $Testing to $true will activate an isolated testing mode against the AD/GPO Testing enivronment.

    The Script has extensive Built-In Error handling mechanics
    - in some circumstances, the script will completely halt, leaving no Output file.
    - in some circumstances, the script will skip the line, leaving notes in the Output file.
    - in some circumstances, the script will default values (like ExtAttr5 - handling); Notes will be left in the Output file.
    - in some circumstances, the script will handle errors and leave error logs in the output file.

.EXAMPLE
        Add-NewWSAGroup.x.x.ps1 
        -> for the Standard Mode. OUResponsibles ('ExtAttr1') double-check is disabled by default;

.EXAMPLE
        Add-NewWSAGroup.x.x.ps1 -skipWSAgroupmembership
        -> for skipping the part, where WSA Groups are set as members of the Admin Role Groups

.EXAMPLE
        Add-NewWSAGroup.x.x.ps1 -DoubleCheck_OUResponsibles
        -> for double checking the provided User q-accounts in 'ExtAttr1'

.OUTPUTS
    .\WSACreationLog-yyyymmdd-hhmmss.csv

.NOTES
    # CHANGE HISTORY:
    # V 1.3 - another few glitches resolved
    # V 1.2 - Description-glitch for WSA_P Groupsfixed 
    # V 1.1 - ExtAttr1 semicolon delimitation (formerly: comma)
    # V 1.0 - Initial Release

.COMPONENT
   See .DESCRIPTION

.ROLE
   See .DESCRIPTION

.FUNCTIONALITY
   See .DESCRIPTION
#>

Param(
    [Parameter(Mandatory=$false)][switch]$skipWSAgroupmembership,
    [Parameter(Mandatory=$false)][switch]$DoubleCheck_OUResponsibles,
    [Parameter(Mandatory=$false)][switch]$DeleteListed
     )
## DEBUG ONLY:
## $Testing = $true
## if not needed, just comment out
##
Clear-Host
#region Current Domain Determination:
    $myForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $DomainName = $DomainName.Name
    if ($DomainName -like "*.*" -and $DomainName -ne $Null) {
        ## Deriving the Distinguished Name from the Domain Name (FQDN) for any scenario faced so far within BMW AG:
        if ( ($DomainName.split(".") | Measure-Object | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty 'Count') -eq 3 ) {
        $domain_DN = "DC=$($DomainName.split(".")[0]),DC=$($DomainName.split(".")[1]),DC=$($DomainName.split(".")[2])"
        }
        elseif ( ($DomainName.split(".") | Measure-Object | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty 'Count') -eq 2) {
        $domain_DN = "DC=$($DomainName.split(".")[0]),DC=$($DomainName.split(".")[1])"
        }
        elseif ( ($DomainName.split(".") | Measure-Object | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty 'Count') -eq 4) {
        $domain_DN = "DC=$($DomainName.split(".")[0]),DC=$($DomainName.split(".")[1]),DC=$($DomainName.split(".")[2]),DC=$($DomainName.split(".")[3])"
        }
    }
$domainsuffix = "*."+$DomainName
$DomainPrefix = $DomainName.split(".")[0]
## V 1.5.0.0 - converting to capital letters:
[string]$DomainPrefix = $DomainPrefix.ToUpper()
#endregion
#region Domain Controller determination
try {
#error handling test only: $DC = Get-ADDomainController -Server "HEU0MUC2558"
$DC = Get-ADDomainController -DomainName $DomainName -Discover -Service PrimaryDC -Erroraction Stop
}
catch {
$DC = Get-ADDomainController -DomainName $DomainName -Discover -Writable -Erroraction Stop
}
## added Europe - hardcoded Domain Controller, for Q-Account check
try {
$DC_Europe = Get-ADDomainController -DomainName "europe.bmw.corp" -Discover -Service PrimaryDC -Erroraction Stop
}
catch {
try {$DC_Europe = Get-ADDomainController -DomainName "europe.bmw.corp" -Discover -Writable -Erroraction Stop
}
catch {
    Write-Warning "      EUROPE DOMAIN CONTROLLER Query Issues"
    Break Script
}
}
<## OBSOLETE: added Emeadecentral - hardcoded Domain Controller, for Q-Account check, as there are two outliers residing there;
try {
$DC_Emeadecentral = Get-ADDomainController -DomainName "emeadecentral.bmw.corp" -Discover -Service PrimaryDC -Erroraction Stop
}
catch {
try {$DC_Emeadecentral = Get-ADDomainController -DomainName "emeadecentral.bmw.corp" -Discover -Writable -Erroraction Stop
}
catch {
    if ($DoubleCheck_OUResponsibles) {
    Write-Warning "      EMEADECENTRAL DOMAIN CONTROLLER Query issues"
    Break Script
    }
} 
}#>
##
#endregion
#region Some Default Values
$time = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
$date = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
$context = Get-Location
$currentuser = join-path (join-path "$env:userdomain" "\") "$env:username"
                if (-not $Testing) {
                [string]$WSA_GroupsOU = "OU=WSA,OU=TPG-Pgroups,OU=SCAPPLICATION,OU=Resources,$domain_DN"
                }
                else {
                [string]$WSA_GroupsOU = "OU=WSA_TEST,OU=TPG-Bgroups-TEST,OU=SCAAPPLICATION_TEST,OU=Resources-TEST,OU=SCECT,OU=Resources,DC=europe,DC=bmw,DC=corp"
                }
#endregion
"

      PROGRESS: Script Started!      
      
      SCRIPT VERSION: 1.3

      START TIME: $time

      TIMESTAMP: $date

         (...) current Domain: $DomainName
         (...) current Domain Controller: $DC
         (...) current User: $currentuser               
"
if ($Testing) {
"`n      TESTING MODE: ON`n"
}
#region Selecting Input File Phase
    ## Only the oldest input file is being used (its timestamp determines the sorting):
    try {
    # V 1.3: -First 1, instead of -Last 1
    $InputFile = Get-ChildItem -Path ".\WSARequest_*.csv" -ErrorAction Stop | select -First 1
    ## V 1.3 - Input File Display
    Write-Host "
         (...) current Input File: $($InputFile.Name)
    " -ForegroundColor Cyan
    ##
    }
    catch {
Write-Host "
       (x) Csv Input File - Get-ChildItem Error
       $($error[0])
       Breaking Script
" -ForegroundColor Red
    Break Script
    }
if ($InputFile -eq  $null) {
Write-Warning "
       (-) Csv Input File - No Input Files Found
       Search for: WSARequest_*.csv
       Place it directly within the Script Folder
       Ending Script

"
    Break Script
}
#endregion
#region Expanding Input Data 
    try {
        $InputLineS = Import-Csv -Path $InputFile -Delimiter "`t" -ErrorAction Stop
        $InputLineS_Count = $InputLineS.Count
    }
    catch {
Write-Host "
       (x) Csv Input File - Import-CSV Error
       $($error[0])
       Breaking Script
" -ForegroundColor Red
    Break Script
    }
#endregion
#region Displaying Input Data on Screen
"       PROGRESS: current Input Data:`n"
$InputLineS | ft  Name,ExtAttr1,ExtAttr5,TargetRole
    ## V 1.3 - Input File Display
    Write-Host "
         (...) current Input File: $($InputFile.Name)
    " -ForegroundColor Cyan
    ##
#endregion
#region Decision Phase
do {
$decision = Read-Host "[INPUT REQUIRED] Please enter your confirmation for proceeding with WSA Group Creation (Do!/exit)"
} while ($decision -notlike "Do!" -and $decision -notlike "exit")
if ($decision -like "exit") {
Break Script
}
#endregion
#region Output File
$LogFile = ".\WSACreationLog-$date.csv"
Out-File -FilePath $LogFile -InputObject "WSAGroupName`tDomainPrefix`tTargetRole`tInputFile`tSTATUS`tERROR" -Append
#endregion
#region Main Loop
    ## MAIN LOOP START
    foreach ($InputLine in $InputLineS) {

    $i++
    Write-Output "

  ------------------------------------------------
  ACTION: PROCESSING LINE $i of $InputLineS_Count

"
$InputLine | ft Name,ExtAttr1,ExtAttr5,TargetRole -Wrap

        $WSA_Group = $null
        $ExtAttr1 = $null
        $ExtAttr5 = $null
        $TargetRole = $null
Write-Output "`n         (...) Interpreting Input Data`n"
        try {$WSA_Group = $InputLine | select -expand Name -ErrorAction Stop
        }
        catch {
        Write-Warning "     ERROR: Couldn't expand 'Name' Column - verify input file /formatting"
        Out-File -FilePath $LogFile -InputObject "`t`t`t$($InputFile.Name)`tINPUT-FAULT`tError-Name-Column:$($error[0])" -Append
        Break Script
        }
        try {$ExtAttr1 = $InputLine | select -expand ExtAttr1 -ErrorAction Stop
        }
        catch {
        Write-Warning "     ERROR: Couldn't expand 'ExtAttr1' Column - verify input file /formatting"
        Out-File -FilePath $LogFile -InputObject "$WSA_Group`t`t`t$($InputFile.Name)`tINPUT-FAULT`tError-ExtAttr1-Column:$($error[0])" -Append
        Break Script
        }
        try {$ExtAttr5 = $InputLine | select -expand ExtAttr5 -ErrorAction Stop
        }
        catch {
        Write-Warning "     ERROR: Couldn't expand 'ExtAttr5' Column  - verify input file /formatting"
        Out-File -FilePath $LogFile -InputObject "$WSA_Group`t`t`t$($InputFile.Name)`tINPUT-FAULT`tError-ExtAttr5-Column:$($error[0])" -Append
        Break Script
        }
       try {$TargetRole = $InputLine | select -expand TargetRole -ErrorAction Stop
        }
        catch {
        Write-Warning "     ERROR: Couldn't expand 'TargetRole' Column - verify input file /formatting"
        Out-File -FilePath $LogFile -InputObject "$WSA_Group`t`t`t$($InputFile.Name)`tINPUT-FAULT`tError-TargetRole-Column:$($error[0])" -Append
        Break Script
        }

        [array]$ExistingWSAGroups = $null
        $Error_OUResponsibles = $false
        $Error_GroupCreation = $false
        $Error_SetGroupMembership = $false
        [string]$Status = $null
        [string]$ERROR_LOG = $null

                                    #region [PART 0] Domain Correction
                                    Write-Output "         (...) Current - Domain: '$DomainName'`n"
                                    ## As the current Admin Role Domain might vary within the same Input File, a domain change might need to be performed in script:
                                        ## This part - extract of the Domain Name and Domain distinguished name from the DistinguishedName of the Container
                                        [array]$Domain_DN_of_Member_Of = $null
                                        [array]$Domain_Name_of_Member_Of = $null
                                        [array]$Domain_DN_of_Member_Of = [array]($TargetRole.split(",")) | where {[string]$_ -like "DC=*"}
                                        [array]$Domain_Name_of_Member_Of = [array]$Domain_DN_of_Member_Of.replace("DC=","")
                                        [string]$Domain_Name_of_Member_Of = [array]$Domain_Name_of_Member_Of -join (".")
                                        [string]$Domain_DN_of_Member_Of = [array]$Domain_DN_of_Member_Of -join (",")
                                    Write-Output "         (...) Input Line - Domain: '$Domain_Name_of_Member_Of'`n"
                                    ## If not, domain and credentials are asked:
                                    if ([string]$Domain_DN_of_Member_Of -notlike [string]$domain_DN) {
                                        try {
                                        Write-Output "         (...) Getting Domain Controller for Input Line - Domain: '$Domain_Name_of_Member_Of'`n"
                                        $DC = Get-ADDomainController -DomainName $Domain_Name_of_Member_Of -Discover -Writable -ErrorAction Stop
                                        ## below will be skipped in case of error:
                                        $domain_DN = [string]$Domain_DN_of_Member_Of
                                        $DomainName  = [string]$Domain_Name_of_Member_Of
                                        $domainsuffix = "*."+$DomainName
                                        $DomainPrefix = $DomainName.split(".")[0]
                                            if (-not $Testing) {
                                            [string]$WSA_GroupsOU = "OU=WSA,OU=TPG-Pgroups,OU=SCAPPLICATION,OU=Resources,$domain_DN"
                                            }
                                            else {
                                            [string]$WSA_GroupsOU = "OU=WSA_TEST,OU=TPG-Bgroups-TEST,OU=SCAAPPLICATION_TEST,OU=Resources-TEST,OU=SCECT,OU=Resources,DC=europe,DC=bmw,DC=corp"
                                            }
                                        }
                                        catch {
                                        ## Will skip to the next line, without doing any changes:
                                        Write-Warning "      (x) Error during Get-ADDomainController Query for the Domain '$([string]$Domain_Name_of_Member_Of)'"
                                        [string]$ERROR_LOG+= "DomainChange-Failure:$($error[0])"
                                        #Continue
                                        $Error_OUResponsibles = $true
                                        }
                                    }
                                    ##                                    
                                    #endregion
                                    ## Group Creation Requirements (FWP1-3228):
                                    #region [PART 1] ExtensionAttribute1
                                    Write-Output "         (...) Interpreting and checking the 'ExtAttr1'`n"
                                            $OUResponsibles = [string]$ExtAttr1
                                            ## V 1.1 - Comma replaced with semicolon, as ADGR Requires Semicolon Delimitation;
                                            $OUResponsibles_Split = $OUResponsibles.split(";")
                                            $OUResponsibles_Count = $OUResponsibles.split(";").count
                                            ## V 1.1:
                                            if ($OUResponsibles_Count -lt 2 -or $OUResponsibles_Split[1] -eq "" -or $OUResponsibles_Split[0] -eq "" -and -not $DeleteListed) {
                                            $Error_OUResponsibles = $true
                                            Write-Host "       (x) OUResponsibles Input Field: MINIMUM COUNT NOT MET ($($OUResponsibles_Count - 1))
                Result: ERROR
    " -ForegroundColor Red
                                            
                                            }
                                     ## 
                                     if ($DoubleCheck_OUResponsibles -and -not $DeleteListed) {
                                     Write-Output "         (...) Double Checking OUResponsibles User Accounts from 'ExtAttr1'`n"
                                         foreach ($OUResponsible_ in $OUResponsibles_Split) {
                                         $mask = $null
                                         ## replaced "-Server $DC" with "-Server $DC_Europe", as Q-accounts are only in Europe.
                                         ## NOTE: there are exceptions to thus rule, though:
                                         ### Bjorn: EMEADECENTRAL\AXZ0SYA
                                         ### Leon: EMEADECENTRAL\AT10032
                                         ## Q-USER CHECK:
                                         try {$mask = Get-ADuser -Server $DC_Europe -Identity "$OUResponsible_" -ErrorAction Stop
                                         }
                                         ## Q-USER FAILURE - 1
                                         catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                                            <# OBSOLETE: try {$mask = Get-ADuser -Server $DC_Emeadecentral -Identity "$OUResponsible_" -ErrorAction Stop
                                            }
                                            catch#>
                                           [array]$DomainList = "emeadecentral.bmw.corp","africa.bmw.corp","americas.bmw.corp","asiapacific.bmw.corp","china.bmw.corp","sfeu.bmw.corp","sfchina.bmw.corp","sfam.americas.bmw.corp","sfap.asiapacific.bmw.corp"
                                           $k = 0
                                           do {
                                               try {$DC_Current = Get-ADDomainController -DomainName $DomainList[$k] -Discover -Service PrimaryDC -Erroraction Stop
                                               }
                                               catch {
                                               $DC_Current = Get-ADDomainController -DomainName $DomainList[$k] -Discover -Writable -Erroraction Stop
                                               }
                                               Start-Sleep 1
                                               try {
                                               #DEBUG:"$($DomainList[$k])"
                                               #DEBUG:"$DC_Current"
                                               $mask = Get-ADuser -Server $DC_Current -Identity "$OUResponsible_" -ErrorAction Stop
                                               }
                                               catch {
                                               $mask = $null
                                               }                                            
                                            $k++
                                            } 
                                            while ($mask -eq $null -and $k -lt $DomainList.Count)
                                            ##                                            
                                            if ($mask -eq $null) {
                                            Write-Host "            (x) Verficiation Failed - Not Found - '$OUResponsible_'
" -ForegroundColor Red
                                            [string]$ERROR_LOG += "OUResponsibles-NotFound:'$OUResponsible_';"
                                            $Error_OUResponsibles = $true
                                            }
                                         }
                                         ## Q-USER FAILURE - 2:
                                         catch {
                                         Write-Host "            (x) Verficiation Failed - Exception - '$OUResponsible_'`n      $($error[0])
                          " -ForegroundColor Red
                                         [string]$ERROR_LOG += "OUResponsibles-Exception:'$OUResponsible_',$($error[0]);"
                                         $Error_OUResponsibles = $true
                                         }                                         
                                         ## Q-USER SUCCESS - 1
                                         if ($mask -ne $null) {
                                     Write-Host "            (v) OUResponsibles Input Field: User Verfied
                                         $($mask.DistinguishedName)
                                         Result: SUCCESS
                             " -ForegroundColor DarkGreen
                                         }
                                         ##
                                         }
                                     }

                                    #endregion
                                    #region [PART 2] ExtensionAttribute2
                                    ## Remains Empty, which is the default state - no actions
                                    #endregion
                                    #region [PART 3] ExtensionAttribute5
                                    ## Checking, if the provided input data is in the proper format (digits only, empty field unacceptable)
                                    Write-Output "         (...) Interpreting and checking the 'ExtAttr5'`n"
                                    if ([string]$ExtAttr5 -eq "" -or ([string]$ExtAttr5 -match '\d\d\d\d') -eq $false) {
                                    [string]$ExtAttr5 = "1012"
                                    }
                                    ## making sure, that the first two fields are binary only (0 or 1), else getting defaulted
                                    elseif ([string]$ExtAttr5 -match '\d\d\d\d') {                                        
                                        if ([string]$ExtAttr5[0] -notlike '0' -and [string]$ExtAttr5[0] -notlike '1') {
                                            [string]$ERROR_LOG += "ExtAttr5-Pos1-Fault:$([string]$ExtAttr5[0]),ExtAttr5-defaults-applied;"
                                            [string]$ExtAttr5 = "1012"
                                        }
                                        if ([string]$ExtAttr5[1] -notlike '0' -and [string]$ExtAttr5[1] -notlike '1') {
                                            [string]$ERROR_LOG += "ExtAttr5-Pos2-Fault:$([string]$ExtAttr5[1]),ExtAttr5-defaults-applied;"
                                            [string]$ExtAttr5 = "1012"
                                        }
                                        if ([int]( ([string]$ExtAttr5[2],[string]$ExtAttr5[3]) -join ("")) -gt 24) {
                                            [string]$ERROR_LOG += "ExtAttr5-Pos3,4-Fault:$([int]( ([string]$ExtAttr5[2],[string]$ExtAttr5[3]) -join (''))),ExtAttr5-defaults-applied;"
                                            [string]$ExtAttr5 = "1012"
                                        }
                                    }
                                    #endregion                                                                            
                                    #region [PART 4] Specific Entries in the Notes Attribute
                                    [string]$Notes = "Administrated by https://clicktime.symantec.com/a/1/3esCKtonICCF-rrs7xQKVLId02gZJ9a9AeDuvKdt8Fk=?d=wUoxAvRabIhx8KgGUdxwS8PiI8kOfKHFC7DFlH2Qg7_TPGOAZ9_reD4580YONYA7fBldo71LCtOqPnB4Fbw8HLmU8zEpA70X1JOw6FNkQOFlZl2EITDEYpLQyXXSnkx5UDAnvuG1pr4ufIOaODg-IBEGVvbBsUebIQMme-M8pLojbXfSPJL7nimIP2r33wdBPMIN1zgXSTEnyVgxFGat3_H9CGwzYDVtjAinFhlrzYCFW46LORLanXbA3RJ7lcXRbjnSdQnKGF3EkRr9_VDf7CidQkFzAVrqL5w5rIBQPytxHBCqciytMt7HqBphzDImlmnhGltXgTt67hVIVmtMi7hSFZ06xFf7aJ0Fywz9IIq_lHyB6yQi1jbRZAm2yhZaBd9RCdzbzRT-igkQIvDXapMpJKuJOtp2BwXTp0H6ZRZ7NiY00vsIEU4xgv9-JzNvIuFYptdWnKfTbGVDaYRSajwD6wIUyGC9npmCsqwi1Hh_ClLCUJVCNi0%3D&u=http%3A%2F%2Fadgr.bmwgroup.net%2F
Administrators (as defined in ExtensionAttribute1)
$OUResponsibles"
                                    #endregion
                                    #region [PART 5] Specific Entries in the Description Attribute
                                    ## Directly implemented through the below command
                                    #endregion
                                    #region [PREP] The Group Check Phase
                                    Write-Output "         (...) Checking for pre-existing WSA Groups, named '$WSA_Group'`n"
                                    try {
                                      if (-not $Testing) {
                                      # V 1.2
                                      # V 1.3
                                      [array]$ExistingWSAGroups = Get-ADGroup -SearchBase "$WSA_GroupsOU" -Server $DC -SearchScope OneLevel -Filter "Name -like 'WSA_I-C*' -or Name -like 'WSA_I-A*' -or Name -like 'WSA_P-C*' -or Name -like 'WSA_P-A*'" -ErrorAction Stop
                                      }
                                      # V 1.2
                                      # V 1.3
                                      else {
                                      [array]$ExistingWSAGroups = Get-ADGroup -SearchBase "$WSA_GroupsOU" -Server $DC -SearchScope OneLevel -Filter "Name -like 'WWSA_I-C*' -or Name -like 'WWSA_I-A*' -or Name -like 'WWSA_P-C*' -or Name -like 'WWSA_P-A*'" -ErrorAction Stop
                                      }
                                    } 
                                    catch {
                                      Write-Host "            (x) Error querying the WSA Group OU '$($WSA_GroupsOU.split(",")[0]) - Exception`n       $($error[0])`n" -ForegroundColor Red
                                      [string]$ERROR_LOG += "WSA-GroupsOU-Query-Error:$($error[0])"
                                      $Error_OUResponsibles = $true
                                    }
                                    Start-Sleep 1
                                    if ($WSA_Group -in $ExistingWSAGroups.Name) {
                                        Write-Host "            (v) Verified - ALREADY EXISTS - '$WSA_Group'`n" -ForegroundColor DarkGreen

                                        if ($DeleteListed) {
                                            Write-Output "         (...) Removing AD Group '$WSA_Group'`n"
                                            try {Set-ADObject -Identity "CN=$WSA_Group,$WSA_GroupsOU" -ProtectedFromAccidentalDeletion $false -Confirm:$False -Server $DC -Verbose
                                            }
                                            catch {
                                            Write-Host "            (x) Removing AD Group Proection '$WSA_Group' - FAILURE
" -ForegroundColor Red
                                            }
                                            Start-Sleep 1
                                            try {Remove-ADGroup -Identity "CN=$WSA_Group,$WSA_GroupsOU" -Confirm:$false -Server $DC -ErrorAction Stop -Verbose
                                            }
                                            catch {
                                            Write-Host "            (x) Removing AD Group '$WSA_Group' - FAILURE
" -ForegroundColor Red
                                            $Error_GroupCreation = $true
                                            }                                            
                                        }
                                    }
                                    if ($WSA_Group -notin $ExistingWSAGroups.Name -and $DeleteListed) {
                                        Write-Host "            (v) Verified - DOES NOT EXISTS - '$WSA_Group'`n" -ForegroundColor DarkGreen
                                    }
                                    #endregion
                                    #region [MAIN] The Group Creation Phase
                                    ## V 1.1. - won't happen, if the switch "DeleteListed" is used:
                                    if ($Error_OUResponsibles -ne $true -and $WSA_Group -notin $ExistingWSAGroups.Name -and -not $DeleteListed) {
                                        Write-Output "         (...) Creating WSA Group, named '$WSA_Group'`n"
                                        try {        
                                        
                                            if ($WSA_Group -like "WSA_I-A*" -or $WSA_Group -like "WWSA_I-A*") {
                                            ## added customized WSA Group Description
                                            [string]$WSA_Description = "Install and Change Computer Accounts"
                                            }
                                            elseif ($WSA_Group -like "WSA_I-C*" -or $WSA_Group -like "WWSA_I-C*") {
                                            ## added customized WSA Group Description
                                            [string]$WSA_Description = "Local Admin rights for Computers"                                        
                                            }
                                            ## V 1.2 - glitch fixed
                                            elseif ($WSA_Group -like "WSA_P-A*" -or $WSA_Group -like "WWSA_P-A*") {
                                            ## added customized WSA Group Description
                                            [string]$WSA_Description = "Install and Change Computer Accounts"
                                            }
                                            elseif ($WSA_Group -like "WSA_P-C*" -or $WSA_Group -like "WWSA_P-C*") {
                                            ## added customized WSA Group Description
                                            [string]$WSA_Description = "Local Admin rights for Computers"                                        
                                            }    
                                                     
                                            New-ADGroup -Name $WSA_Group -Path "$WSA_GroupsOU" -Server $DC -GroupScope Global -GroupCategory Security -Description $WSA_Description -OtherAttributes @{'ExtensionAttribute1'=$ExtAttr1;'ExtensionAttribute5'=$ExtAttr5;'Info'=$Notes}
                                            Start-Sleep 2
                                        }
                                        catch [System.UnauthorizedAccessException] {
                                            Write-Host "            (x) Did not create the WSA Group '$WSA_Group' - Missing 'Create all Child Objects' Permissions on Parent OU Level`n" -ForegroundColor Red
                                            [string]$ERROR_LOG += "WSACreation-System.UnauthorizedAccessException;"
                                            $Error_GroupCreation = $true
                                            $error.clear()
                                        }
                                        catch {
                                            Write-Host "           (x) Did not create the WSA Group '$WSA_Group' - Exception`n      $($error[0])`n" -ForegroundColor Red
                                            [string]$ERROR_LOG += "WSACreation-Exception:$($error[0]);"
                                            Start-Sleep 1
                                            $Error_GroupCreation = $true
                                            $error.clear()
                                        }
                                        Start-Sleep 3
                                    }
                                    #endregion
                                    #region [DOUBLE-CHECK] Group Creation Verification
                                    ## V 1.1. - won't happen, if the switch "DeleteListed" is used:
                                    if ($Error_OUResponsibles -ne $true -and $Error_GroupCreation -ne $true -and $WSA_Group -notin $ExistingWSAGroups.Name -and -not $DeleteListed) {
                                    Write-Output "         (...) Double-checking the WSA Group creation, named '$WSA_Group'`n"
                                        try {$mask = Get-ADGroup -SearchBase $WSA_GroupsOU -SearchScope Subtree -Filter * -Server $DC -Properties Name,DistinguishedName | where Name -like $WSA_Group
                                            if ($mask.DistinguishedName -eq "CN=$WSA_Group,$WSA_GroupsOU") {
                                            Write-Host "            (v) Verified - OK - '$WSA_Group'`n" -ForegroundColor DarkGreen
                                            }
                                            elseif ("CN=$WSA_Group,$WSA_GroupsOU" -notin $mask.DistinguishedName) {
                                            Write-Host "            (x) Verficiation Failed - Not Found - '$WSA_Group'`n" -ForegroundColor Red
                                            [string]$ERROR_LOG += "WSACreation-Verificaiton-NotFound;"
                                            $Error_GroupCreation = $true
                                            }

                                        } 
                                        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                                            Write-Host "            (x) Verficiation Failed - Not Found - '$WSA_Group'`n" -ForegroundColor Red
                                            [string]$ERROR_LOG += "WSACreation-Verificaiton-ADIdentityNotFoundException:$($error[0]);"
                                            $Error_GroupCreation = $true
                                            $error.clear()
                                        }
                                        catch {
                                            Write-Host "            (x) Verficiation Failed - unspecified - '$WSA_Group' - Exception`n      $($error[0])`n" -ForegroundColor Red
                                            Start-Sleep 1
                                            [string]$ERROR_LOG += "WSACreation-Verificaiton-unspecifiedexception:$($error[0]);"
                                            $Error_GroupCreation = $true
                                            $error.clear()
                                        }
                                    }
                                    ## V 1.1: Deletion phase:
                                    elseif ($DeleteListed -and $WSA_Group -in $ExistingWSAGroups.Name -and $Error_GroupCreation -ne $true ) {
                                    Write-Output "         (...) Double-checking the WSA Group deletion, named '$WSA_Group'`n"

                                        try {$mask = Get-ADGroup -SearchBase $WSA_GroupsOU -SearchScope Subtree -Filter * -Server $DC -Properties Name,DistinguishedName | where Name -like $WSA_Group
                                            
                                            if ($mask.DistinguishedName -eq "CN=$WSA_Group,$WSA_GroupsOU") {
                                            Write-Host "            (x) Verficiation Failed - Not Deleted - '$WSA_Group'`n" -ForegroundColor Red
                                            [string]$ERROR_LOG += "WSACreation-Verificaiton-NotDeleted;"
                                            $Error_GroupCreation = $true
                                            $error.clear()
                                            }
                                            elseif ("CN=$WSA_Group,$WSA_GroupsOU" -in $mask.DistinguishedName) {
                                            Write-Host "            (x) Verficiation Failed - Not Deleted - '$WSA_Group'`n" -ForegroundColor Red
                                            [string]$ERROR_LOG += "WSACreation-Verificaiton-NotDeleted;"
                                            $Error_GroupCreation = $true
                                            }
                                            elseif ($mask -eq $null) {
                                            Write-Host "            (v) Verified - OK - Deleted - '$WSA_Group'`n" -ForegroundColor DarkGreen
                                            }

                                        } 
                                        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                                             Write-Host "            (v) Verified - OK - Deleted - '$WSA_Group'`n" -ForegroundColor DarkGreen
                                        }
                                        catch {
                                            Write-Host "            (x) Verficiation Failed - unspecified - '$WSA_Group' - Exception`n      $($error[0])`n" -ForegroundColor Red
                                            Start-Sleep 1
                                            [string]$ERROR_LOG += "WSACreation-Verificaiton-unspecifiedexception:$($error[0]);"
                                            $Error_GroupCreation = $true
                                            $error.clear()
                                        }                                    
                                    }                                              
                                    #endregion                                   
                                    #region [MEMBERSHIP]     
                                    ## Addding WSA Group as MemberOf the proper Admin Role - re-enabled when switch Force_WSACreate is used
                                    ## Former location of region Setting WSA Membership
                                    ## V 1.1. - won't happen, if the switch "DeleteListed" is used:
                                    if ($Error_OUResponsibles -ne $true -and $Error_GroupCreation -ne $true -and -not $skipWSAgroupmembership -and -not $DeleteListed) {
                                        try {
                                            Write-Output "         (...) Setting Membership for the WSA Group '$WSA_Group' in '$($TargetRole.split(",")[0])'"
                                            # Add-ADGroupMember -Server $DC -Identity "CN=$Group,$AdminRolesOU" -Members $MemberOf_Identity_forGroupS -Confirm:$false
                                            # https://clicktime.symantec.com/a/1/rv7Oaske1E9jyvYK5JgJO_qvt6VBEGU5ptgxUTgPx44=?d=wUoxAvRabIhx8KgGUdxwS8PiI8kOfKHFC7DFlH2Qg7_TPGOAZ9_reD4580YONYA7fBldo71LCtOqPnB4Fbw8HLmU8zEpA70X1JOw6FNkQOFlZl2EITDEYpLQyXXSnkx5UDAnvuG1pr4ufIOaODg-IBEGVvbBsUebIQMme-M8pLojbXfSPJL7nimIP2r33wdBPMIN1zgXSTEnyVgxFGat3_H9CGwzYDVtjAinFhlrzYCFW46LORLanXbA3RJ7lcXRbjnSdQnKGF3EkRr9_VDf7CidQkFzAVrqL5w5rIBQPytxHBCqciytMt7HqBphzDImlmnhGltXgTt67hVIVmtMi7hSFZ06xFf7aJ0Fywz9IIq_lHyB6yQi1jbRZAm2yhZaBd9RCdzbzRT-igkQIvDXapMpJKuJOtp2BwXTp0H6ZRZ7NiY00vsIEU4xgv9-JzNvIuFYptdWnKfTbGVDaYRSajwD6wIUyGC9npmCsqwi1Hh_ClLCUJVCNi0%3D&u=https%3A%2F%2Fsocial.technet.microsoft.com%2FForums%2Fie%2Fen-US%2Faee5327f-43fe-4cc7-a0ca-6f45f06489d9%2Fremoveadgroupmember-where-member-is-in-parent-domain-and-group-is-in-child-domain%3Fforum%3Dwinserverpowershell 
                                            Set-ADObject -Identity "$($TargetRole)" -Add @{member="$("CN=$WSA_Group,$WSA_GroupsOU")"} -Server $DC -ErrorAction Stop
                                            ## also the following can be used, as it is not zeroed: -Add @{member="$($mask.DistinguishedName)"
                                            Write-Host "            (v) Membership for the WSA Group '$WSA_Group' in '$($TargetRole.split(",")[0]) set - SUCCESS`n" -ForegroundColor DarkGreen
                                        }
                                        catch [System.UnauthorizedAccessException] {
                                            Write-Host "            (x) Did not Set Membership for the WSA Group '$WSA_Group' in '$($TargetRole.split(",")[0]) - Missing 'Create all Child Objects' Permissions on Parent OU Level`n" -ForegroundColor Red
                                            [string]$ERROR_LOG += "WSA_Membership-SystemUnauthorizedAccessException;"
                                            $Error_SetGroupMembership = $true
                                            $error.clear()
                                        }
                                        catch {
                                            [string]$exception = $Error[0] | Microsoft.PowerShell.Utility\select-object -Property *
                                            Write-Host "            (x) Did not Set Membership for the WSA Group '$WSA_Group' in '$($TargetRole.split(",")[0]) - Unexpected Exception`n" -ForegroundColor Red
                                            Start-Sleep 1
                                            [string]$ERROR_LOG += "WSA_Membership-UnexpectedException;"
                                            $Error_SetGroupMembership = $true
                                            $error.clear()
                                        }
                                    }
                                    #endregion

                                    #region [LOGGING]
                                    if ($Error_OUResponsibles -eq $true) {
                                        [string]$Status = "PREPARATION-FAILURE"
                                    }
                                    ## V 1.1
                                    elseif ($Error_GroupCreation -eq $true -and -not $DeleteListed) {
                                        [string]$Status = "CREATION-FAILURE"
                                    }
                                    elseif ($Error_SetGroupMembership -eq $true) {
                                        [string]$Status = "CREATION-WARNING"
                                    }
                                    elseif ($WSA_Group -in $ExistingWSAGroups.Name -and -not $DeleteListed) {
                                        [string]$Status = "ALREADY-EXISTS"
                                    }
                                    ## V 1.1
                                    elseif ($WSA_Group -in $ExistingWSAGroups.Name -and $DeleteListed -and $Error_GroupCreation -eq $false) {
                                        [string]$Status = "EXISTS-REMOVED-SUCCESS"
                                    }
                                    ## V 1.1
                                    elseif ($WSA_Group -in $ExistingWSAGroups.Name -and $DeleteListed -and $Error_GroupCreation -eq $true) {
                                        [string]$Status = "EXISTS-REMOVAL-FAILED"
                                    }
                                    elseif ($WSA_Group -notin $ExistingWSAGroups.Name -and $DeleteListed) {
                                        [string]$Status = "DOES-NOT-EXIST-NOACTION"
                                        [string]$TargetRole = $null
                                    }
                                    else {
                                        [string]$Status = "SUCCESS"
                                    }
                                    Out-File -FilePath $LogFile -InputObject "$WSA_Group`t$DomainPrefix`t$($TargetRole.split(",")[0])`t$($InputFile.Name)`t$Status`t$ERROR_LOG" -Append
                                    #endregion
    }
    ## MAIN LOOP END
#endregion
#region InputFile Renaming
# This way, the Input File won't appear for selection for the next run
# The Script will select the next oldest input file in line
[string]$NewName = "DONE_" + $([string]$InputFile.Name)
Rename-Item -Path $InputFile.PSPath -NewName $NewName
#endregion
