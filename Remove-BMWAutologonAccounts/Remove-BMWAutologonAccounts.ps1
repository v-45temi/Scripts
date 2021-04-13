<#PSScriptInfo

.VERSION 1.0

.AUTHOR Teodora Manova \Teodora.Manova@partner.bmwgroup.com

.COMPANYNAME BMW Group

.TAGS Computers Computer Objects Disabled
#>
<#
    Histrory:
                2020-10-14 Teodora Manova Added "OU=AutoLogon_TEST,OU=INDUSTRIAL,OU=Accounts,DC=europe,DC=bmw,DC=corp" and "OU=AutoLogon_INT,OU=INDUSTRIAL,OU=Accounts,DC=europe,DC=bmw,DC=corp" to the removal functions under EMEA Switch
 /#>

<#
.SYNOPSIS
    The script is removing every account, which doesn't match any computer object under the 
.DESCRIPTION
    This script is developed to run every day in a scheduled task and removing every account without computer object matching its name
.EXAMPLE
    call it just .\Remove-AutologonAccounts.ps1
.INPUTS
    No inputs
.OUTPUTS
    4 files: 2 Logs, 2 reports and 1 list of the removed objects

#>
[CmdletBinding()]
param (
    [Parameter()]
    [switch]$EMEA,
    [switch]$ASAPC,
    [switch]$AMERICAS
)
#region Define scripting variable
$error.clear()
$date = (Get-Date -format 'yyyyMMdd-HHmm')
#[datetime]$date=Get-Date -Format d

[int]$week=get-date -UFormat %V

##Prod Root Path
#$rootpath="\\europe.bmw.corp\WINFS\FG-Data\_Topics\Client_Operation\Documentation\GPO\30_Backup_auto"

##test Root Path
$rootpath="E:\Other\Remove-BMWAutologonAccounts"
#$rootpath="C:\temp\Remove-AutologonAccounts"

$path="$rootpath\$week-$date"

#General Logging paths and files variables
$GeneralErrorLog="$rootpath\$(Get-Date -format 'yyyy-MM-dd')-GeneralErrorLog.log" 
$GeneralScriptLog="$rootpath\$(Get-Date -format 'yyyy-MM-dd')-GeneralScriptLog.log"
#region HTML Head
$head=@"

<Style> 

Body {

  font-family: "Trebuchet MS", Arial, Helvetica, sans-serif;

  border-collapse: collapse;

  width: 100%;

}
h2 {
    text-align: center;
    font-family: "Trebuchet MS", Arial, Helvetica, sans-serif

}

td, th {

  border: 1px solid #ddd;

  padding: 8px;

}



tr:nth-child(even){background-color: #f2f2f2;}



tr:hover {background-color: #ddd;}



th {

  padding-top: 12px;

  padding-bottom: 12px;

  text-align: left;

  background-color: #4CAF50;

  color: white;

} </style>

"@
#endregion

$global:html=@()
$global:html+="<h2>BMW Removed Autologon Accounts</h2>"
#$Summary=@()
$htmlReportPath="$path\$date-Remove-BMWAutologonAccounts_report.html"
#endregion
Write-Host "`r`n[$date] The Script Remove-AutologonAccounts has been started!"
function New-BmwScriptLogsDirectories
{

#region creating rootpath directory
    if (!(Test-Path $rootpath)){

                try{
                    New-Item -ItemType Directory -Force -Path $rootpath -Verbose -ErrorAction Stop
                }
                catch{
                     Write-Output "!!!An Error has bee thrown, while creating directory: $($error[0])" `
                    |write-log
                }

    }

#endregion

#region creating path directory
    if (!(Test-Path $path)){

                try{
                    New-Item -ItemType Directory -Force -Path $path -Verbose -ErrorAction Stop
                    sleep 5
                }
                catch{
                     Write-Output "!!!An Error has bee thrown, while creating directory: $($error[0])" `
                    |write-log -AdditionalLogPaths $GeneralErrorLog
                }
    }

#endregion


}


#generating the Computers OU DistinguishedName and PDC emulator fqdn
Function Remove-AutologonAccounts
{

    # Parameter help description
    [CmdletBinding()] 
        param ( 
            [parameter(
            Mandatory         = $true,
            ValueFromPipeline = $true)]
            #DomainName parameter is mendatory 
            [string]$DomainName,
            [parameter(
            Mandatory         = $false,
            ValueFromPipeline = $true)]
            #Accounts SearchBase parameter, bydefault is set to OU=Autologon,OU=Industrial,OU=Accounts,DC=Domain,DC=COM
            [string]$AcSearchBase,
            #Search Scope parameter, by default is set to OneLevel, it could be also Subtree or Base, which means 0 more see here https://docs.microsoft.com/en-us/powershell/module/addsadministration/get-aduser?view=win10-ps#parameters
            [string]$SearchScope,
            #Computers SearchBase parameter, by default is set to OU=Resources
            [string]$CNSearchbase,
            [int]$Limiter
        )


#region Parameters
    $Domain=Get-ADDomain $domainname
    if (!($SearchScope)){
        $SearchScope='Subtree'
    }
    $CN=$Domain.ComputersContainer
    $SPComps=$null
    $Error_SPComps=$false
    $CNReport=@()
    $CNCollection=[System.Collections.ArrayList]::new()
    $RemovedAccountReport=@()
    $AutologonAccountsReport=@()
    $FinalArray=@()
    $RemovedAccountList="$path\$date-RemovedAccountsList_$domainname.csv"
    $AccountCount=0
    #Paths
    $logfilepath="$path\$Date-Remove-AutologonAccounts_$domainname.log"
    #$CNCollectionPath="C:\ScriptsLogging\Remove-AutologonAccounts\$(get-date -Format yyyy-MM-dd_HHmm) Resources_Computers_report_$domainname.csv"
    $RemovedAccountReportpath="$path\$date-Remove-AutologonAccounts_report_$domainname.csv"
    $AutologonAccountsReportPath="$path\$date-AutologonAccounts_report_$domainname.csv"
#endregion

#region writing Outputs
    Write-Output "The Remove-AutologonAccounts has been started! " | Write-Log -AdditionalLogPaths $logfilepath,$GeneralScriptLog,$GeneralScriptLog

    Write-Host "Creating Logfilepatch and Reportpath variables: $logfilepath "
    Write-Output "Creating Logfilepatch and Reportpath variables:$logfilepath " | Write-Log -AdditionalLogPaths $logfilepath,$GeneralScriptLog
    sleep 1
    Write-Host -BackgroundColor DarkGreen "`r`n[$date] The script will request all searches to the PDC Emulator $($Domain.PDCEmulator) "
    Write-Output "The script will use the PDC Emulator $($Domain.PDCEmulator) for the LDAP requests" | Write-Log -AdditionalLogPaths $logfilepath,$GeneralScriptLog
    sleep 1
    Write-Host -BackgroundColor DarkGreen "`r`n[$date] The script is executed under $($Domain.DistinguishedName) and the Searchbase for the Computers OU is $($CNSearchbase)"
    Write-Output "The script is executed under $($Domain.DistinguishedName) and the Searchbase for the Computers OU is $($CNSearchbase)" | Write-Log -AdditionalLogPaths $logfilepath,$GeneralScriptLog
#endregion
        
    
    $global:server = Get-ADDomainController -DomainName $DomainName -Discover -Service PrimaryDC
    Write-Output "Primary DC has been discovered: $server" |Write-Log -AdditionalLogPaths $logfilepath,$GeneralScriptLog

#region generation an array of all computer objects under $CNSearchbase    
    try{
        #$SPComps=Get-ADComputer -SearchBase $CNsearchbase -Filter * -Properties Name, Enabled, DNSHostName, WhenCreated,Description,DistinguishedName,CN -Server $Server -SearchScope $searchscope

        ##In case we need an OU filter:
        <#
         $SPSCOUArray = Get-ADOrganizationalUnit -SearchScope $SearchScope -Filter * -SearchBase $CNsearchbase -Server $server
         
         $FinalArray += $SPSCOUArray
         $FinalArray+=$cn
         foreach ($OU in $SPSCOUArray){

         $SPComps+=Get-ADComputer -SearchBase $ou.DistinguishedName -SearchScope $SearchScope -Filter * -Server $server
         }
         #>
         Write-Output "Starting researching all computer objects under $CNSearchbase ..." |Write-Log -AdditionalLogPaths $logfilepath,$GeneralScriptLog
         $StopWatch = [System.Diagnostics.Stopwatch]::StartNew()
         $SPComps=Get-ADComputer -SearchBase $CNSearchbase -SearchScope $SearchScope -Filter * -Server $server -ErrorAction Stop
         $TotalCompCount=$SPComps.Count
         $StopWatch.Stop()
         $QueryTime = $StopWatch.Elapsed.TotalSeconds 
         Write-Output "The reaserch finished in '$QueryTime' seconds for '$TotalCompCount' Computers!" |write-log -AdditionalLogPaths $logfilepath,$GeneralScriptLog

         $QueryTime = 0
         if (!$Limiter){$Limiter=20}

        #Generating Report for all Autologon User accounts which doesn't match any computer object name under $CNSearchbase it will be saved under $RemovedAccountReportpath
        #Write-Host -BackgroundColor DarkGreen "`n[$date] Generating Report for a computer objects under $CNSearchbase it will be saved under $CNCollectionPath"
        #Write-Output "`r`n[$date] Generating Report for a computer objects under $CNSearchbase it will be saved under $CNCollectionPath" | Write-Log -AdditionalLogPaths $logfilepath,$GeneralScriptLog
                
        }
    catch{
        Write-Host -BackgroundColor DarkRed "`r`n[$date] $error"
        $Error_SPComps=$true
        Write-Output "!!!An error has been thrown, while discoverring all Computer accounts under '$CNsearchbase': $($error[0]) " | Write-Log -AdditionalLogPaths $logfilepath,$GeneralScriptLog, $GeneralErrorLog
        return
    }        
        Write-Output "`n`n***************************************************************************************************************************** `
        `r`n Domain: '$domainname' `r`n PDC: '$server' `r`n AccountSearchBase: '$AcSearchBase' `r`n ComputerSearchBase: '$CNSearchbase'`r`n SearchScope: '$SearchScope'`r`n Path of the Reports: '$RemovedAccountReportpath' `r`n Logfilepath: '$logFilePath' `r`n ScriptLoggingPath: $ScriptNameLog`
        `n `n***************************************************************************************************************************** "`
        |Write-Log -AdditionalLogPaths $logfilepath,$GeneralScriptLog

    
        Write-Output "All computer object has been susccessfully stored under the report object, next acction is to compare them with all account`
            and remove those accounts without computer objects matching same name!" |Write-Log -AdditionalLogPaths $logfilepath,$GeneralScriptLog
   
        #$CNCollection |Export-Csv -Path $CNCollectionPath -NoTypeInformation 
        #$html+= $CNCollection |ConvertTo-Html -As Table -Fragment 

#endregion
    try{
#region Autologon Accounts filtering and removing
        $AutologonAccounts=Get-ADUser -SearchBase $AcSearchBase -Filter * -Server $server -SearchScope OneLevel -property SamAccountName,Name,SurName,Enabled,Description,DistinguishedName,ObjectClass,UserPrincipalName,SID,CN,WhenCreated

        Write-Output "$($AutologonAccounts.count) has been discovered, performing a search for matching computer object..." | Write-Log -AdditionalLogPaths $logfilepath,$GeneralScriptLog

        if ($SPComps -ne $null -and $Error_SPComps -ne $true){
        $AccountsWithoutComputers=$AutologonAccounts.SamAccountName| Where-Object -FilterScript { $_ -notin $SPComps.Name} |Sort-Object -Descending |select -First $Limiter

        $TotalAccountsCount=$AccountsWithoutComputers.count
        Write-Output "$TotalAccountsCount accounts from $($AutologonAccounts.count) accounts under the OU, has been discovered without computer object matching the same SamAccountName." | Write-Log -AdditionalLogPaths $logfilepath,$GeneralScriptLog
        }
        else{
        "Error has been throlln while comparing objects: $($error)[0]"|Write-Log -AdditionalLogPaths $logfilepath,$GeneralScriptLog,$GeneralErrorLog
        return
        }
    }
    catch{
        Write-Host -BackgroundColor DarkRed "`r`n[$date] $($error[0])"
        Write-Output "!!!An error has been thrown, while discovering all autologon accounts under '$AccountSearchBase': $($error[0]) " | Write-Log -AdditionalLogPaths $logfilepath,$GeneralScriptLog, $GeneralErrorLog
    }
        if ($AccountsWithoutComputers -notlike $null){
            #Generating Report for all Autologon User accounts which doesn't match any computer object name under $CNSearchbase it will be saved under $AutologonAccountsReportpath
            Write-Host -BackgroundColor DarkGreen "`n[$date] Generating Report for all Autologon User accounts which doesn't match any computer object name under $CNSearchbase it will be saved under $RemovedAccountReportpath"
            Write-Output "Generating Report for all Autologon User accounts which doesn't match any computer object name under $CNSearchbase it will be saved under $RemovedAccountReportpath" | Write-Log -AdditionalLogPaths $logfilepath,$GeneralScriptLog

            foreach ($accountwithoutcomputer in $AccountsWithoutComputers){
                try{
                    Write-Host -BackgroundColor DarkBlue "`n[$date] Adding data for $accountwithoutcomputer \\\ ($AccountCount of $TotalAccountsCount) accounts"
                    Write-Output "Adding data for $accountwithoutcomputer \\\ ($AccountCount of $TotalAccountsCount)" | Write-Log -AdditionalLogPaths $logfilepath,$GeneralScriptLog

                    #generating a report of the accounts
                    $account= Get-ADUser -Identity $accountwithoutcomputer -Properties * -Server $domain.PDCEmulator |select Name,Surname,SamAccountName, Enabled,WhenCreated,Description,DistinguishedName,ObjectClass,SID,UserPrincipalName
                    $RemovedAccountReport+= New-Object -TypeName PSObject -Property @{
                                                                Name=$account.Name;
                                                                CN=$account.CN;
                                                                SamAccountName=$account.SamAccountName;
                                                                Surname=$account.Surname;
                                                                Enabled=$account.enabled;
                                                                WhenCreated=$account.WhenCreated;
                                                                Description=$account.Description;
                                                                DistinguishedName=$account.DistinguishedName;
                                                                ObjectClass=$account.ObjectClass;
                                                                SID=$account.SID;
                                                                UserPrincipalName=$account.UserPrincipalName
                                                                }
                }
                catch{
                    Write-Host -BackgroundColor DarkRed "`r`n[$date] $($error[0])"
                    Write-Output "!!!An error has been thrown, while creating Account Report: '$accountwithoutcomputer' Error: $($error[0]) " | Write-Log -AdditionalLogPaths $logfilepath,$GeneralScriptLog, $GeneralErrorLog
                }
                try{
                    #Set-ADUser -Identity $accountwithoutcomputer -Description "This account will be deleted \\`n[$date]" -Server $server
                    Write-Host -BackgroundColor DarkGreen "`n[$date] The Account: $accountwithoutcomputer has been deleted!"

                    Write-Output "The Account $accountwithoutcomputer has been deleted \\\ ($AccountCount of $TotalAccountsCount)" | Write-Log -AdditionalLogPaths $logfilepath,$GeneralScriptLog
                    Remove-ADUser -Identity $accountwithoutcomputer -Confirm:$false
                    $account.Name |Add-Content $RemovedAccountList 
                        
                }
                catch{
                    Write-Host -BackgroundColor DarkRed "`r`n[$date] $($error[0])"
                    Write-Output "!!!An error has been thrown, while Removing the account: '$accountwithoutcomputer' Error: $($error[0]) " | Write-Log -AdditionalLogPaths $logfilepath,$GeneralScriptLog, $GeneralErrorLog
                }   
                    
            }
            
            #Exporting the report for all users accounts which has been removed
            Write-Host -BackgroundColor DarkGreen "`n[$date] Exporting the report for all users accounts which has been removed: $RemovedAccountReportpath"
            Write-Output "`Exporting the report for all users accounts which has been removed under $RemovedAccountReport" | Write-Log -AdditionalLogPaths $logfilepath,$GeneralScriptLog

            $RemovedAccountReport |Export-Csv -Path $RemovedAccountReportpath -NoTypeInformation 
            #Generating HTML Report from User report
            Write-Output "Generating HTML Report from User report under $htmlReportPath" | Write-Log -AdditionalLogPaths $logfilepath,$GeneralScriptLog

            $global:html+="<h3>The script has been executed for the accounts under the OU:<p style='color:green'><i>$AcSearchBase</i></p> `
                            `r`nand all computers under the Special OUs, which are not matching any name of the AutologonAccounts, under the OU:<p style='color:green'><i>$CNSearchbase</i></p>`
                            `r`nDomain:<p style='color:green'><i> $DomainName</i></p></h3>"

            $global:html+="<h3>$TotalAccountsCount accounts from $($AutologonAccounts.count) accounts under the OU has been removed</h3>"

            $global:html+= $RemovedAccountReport |ConvertTo-Html -As Table -Fragment 

            Write-Host -BackgroundColor DarkGreen "`n[$date] HTML Report has been generated under $htmlReportPath for: Removed Autologon accounts under $UserSearchbase with no computer object accounts under $CNSearchbase  matching their names for Domain $DomainName"
            }
            else{
                Write-Host -BackgroundColor DarkRed "`n[$date] There is no account without computer object for Domain:$DomainName matching its name!"
                Write-Output "There is no account without computer object for Domain:$DomainName matching its name!" | Write-Log -AdditionalLogPaths $logfilepath,$GeneralScriptLog
                $global:html+="<h3>The script has been executed for the accounts under the OU:<p style='color:green'><i>$AcSearchBase</i></p> `
                            `r`nand all computers under the Special OUs, which are not matching any name of the AutologonAccounts, under the OU:<p style='color:green'><i>$CNSearchbase</i></p>`
                            `r`nDomain:<p style='color:green'><i> $DomainName</i></p></h3>"
                $global:html+="<h3>`r`n `r`nThere is no account without computer object for Domain:$DomainName matching its name!</h3>"

            }
    
#endregion
}


#Send Mail function
Function Send-RemovedAutologonAccountsMail
{
param(
        $FromUser,
        $Recipients,
        $SMTPServer,
        $DomainSwitch
)   
        #$user=$env:USERNAME
        #$fromUser=Get-ADUser -filter {Name -like $user} -Properties Mail |select -ExpandProperty Mail
        
        $SubjectDate=Get-Date
        #$Bcc=@()
    try{
        $MailMessage=@{}
        $MailMessage +=  @{
                            To=$Recipients;
                            #Bcc=$Bcc;
                            Attachments=@();
                            Body="Hello Team,`n `n Please find attached all the information regarding the removed Autologon Accounts!`n More Logs can be find under '$path' `n `n BR,`n `n AD\GPO FG-811";
                            Subject="$SubjectDate Daily accounts removal for Region $DomainSwitch!";
                            SmtpServer=$SMTPServer;
                            From=$fromUser
                            } # End Property hash table

    }
    catch{
        Write-Output "Unable to create @Mailmessage parameter set $($error[0])" | Write-Log -AdditionalLogPaths $GeneralErrorLog,$GeneralScriptLog
    } 
 
    try{
    #All reports, html and logfiles
    $RemovedAccountListFiles=Get-ChildItem $path -Recurse |Where-Object {$_.Name -like "*RemovedAccountsList*"} |Select-Object -ExpandProperty Fullname 

    #Adding Attachments
    $MailMessage.Attachments+=($htmlReportPath)
    #$MailMessage.Attachments+=($RemovedAccountListFiles)
    #$MailMessage.Attachments+=($GeneralScriptLog)
    if(Test-Path $GeneralErrorLog){
    #$MailMessage.Attachments+=($GeneralErrorLog)
    }
    
    }
    catch{
        Write-Output "Unable to attach any file for @Mailmessage parameter set $($error[0])" | Write-Log -AdditionalLogPaths $GeneralErrorLog,$GeneralScriptLog
    } 
        try{
        Send-MailMessage @MailMessage -Verbose
        Write-Output "E-mail with reports and Logfiles has been send to $($Recipients) successfully!" | Write-Log -AdditionalLogPaths $GeneralScriptLog
    
    }
    catch{
        Write-Output "Unable to send mail message Error: $($error[0])" | Write-Log -AdditionalLogPaths $GeneralErrorLog,$GeneralScriptLog
    } 
}


New-BmwScriptLogsDirectories

if ($EMEA){
    #europe
    Remove-AutologonAccounts -DomainName "europe.bmw.corp" -AcSearchBase "OU=AutoLogon,OU=INDUSTRIAL,OU=Accounts,DC=europe,DC=bmw,DC=corp" -CNSearchbase "OU=Resources,DC=europe,DC=bmw,DC=corp" -Limiter 20
    Remove-AutologonAccounts -DomainName "europe.bmw.corp" -AcSearchBase "OU=AutoLogon_INT,OU=INDUSTRIAL,OU=Accounts,DC=europe,DC=bmw,DC=corp" -CNSearchbase "OU=Resources,DC=europe,DC=bmw,DC=corp" -Limiter 20
    Remove-AutologonAccounts -DomainName "europe.bmw.corp" -AcSearchBase "OU=AutoLogon_TEST,OU=INDUSTRIAL,OU=Accounts,DC=europe,DC=bmw,DC=corp" -CNSearchbase "OU=Resources,DC=europe,DC=bmw,DC=corp" -Limiter 20

    Remove-AutologonAccounts -DomainName "africa.bmw.corp" -AcSearchBase "OU=Autologon,OU=INDUSTRIAL,OU=Accounts,DC=africa,DC=bmw,DC=corp" -CNSearchbase "OU=Resources,DC=africa,DC=bmw,DC=corp" -Limiter 20
    Remove-AutologonAccounts -DomainName "emeadecentral.bmw.corp" -AcSearchBase "OU=AutoLogon,OU=INDUSTRIAL,OU=Accounts,DC=emeadecentral,DC=bmw,DC=corp" -CNSearchbase "OU=Resources,DC=emeadecentral,DC=bmw,DC=corp" -Limiter 20

    #region Generating HTML report
    try{
    #Converting Html and sending mail with the reports

    ConvertTo-Html -Title "BMW Removed Autologon Accounts" -Body $html -Head $head |out-file $htmlReportPath

    }
        
    catch{
        Write-Host -BackgroundColor DarkRed "`r`n[$date] Unable to send mail message $error"
        Write-Output "Unable to generate HTML Report Error: $($error[0])" | Write-Log -AdditionalLogPaths $logfilepath,$GeneralScriptLog, $GeneralErrorLog
    }
    #endregion

    Send-RemovedAutologonAccountsMail -FromUser "qqcods0@bmw.de" -Recipients "DL-TDIS-IWS-Report@list.bmw.com"  -SMTPServer "smtp.muc" -DomainSwitch "EMEA"
}

if ($ASAPC){
    Remove-AutologonAccounts -DomainName "asiapacific.bmw.corp" -AcSearchBase "OU=AutoLogon,OU=INDUSTRIAL,OU=Accounts,DC=asiapacific,DC=bmw,DC=corp" -CNSearchbase "OU=Resources,DC=asiapacific,DC=bmw,DC=corp" -Limiter 20
    Remove-AutologonAccounts -DomainName "china.bmw.corp" -AcSearchBase "OU=AutoLogon,OU=INDUSTRIAL,OU=Accounts,DC=china,DC=bmw,DC=corp" -CNSearchbase "OU=Resources,DC=china,DC=bmw,DC=corp" -Limiter 20
    #region Generating HTML report
    try{
    #Converting Html and sending mail with the reports

    ConvertTo-Html -Title "BMW Removed Autologon Accounts" -Body $html -Head $head |out-file $htmlReportPath

    }
        
    catch{
        Write-Host -BackgroundColor DarkRed "`r`n[$date] Unable to send mail message $error"
        Write-Output "Unable to generate HTML Report Error: $($error[0])" | Write-Log -AdditionalLogPaths $logfilepath,$GeneralScriptLog, $GeneralErrorLog
    }
    #endregion

    Send-RemovedAutologonAccountsMail -FromUser "qqcods0@bmw.de" -Recipients "DL-TDIS-IWS-Report@list.bmw.com"  -SMTPServer "smtp.muc" -DomainSwitch "ASAPC"
}
if ($AMERICAS){
    Remove-AutologonAccounts -DomainName "americas.bmw.corp" -AcSearchBase "OU=AutoLogon,OU=INDUSTRIAL,OU=Accounts,DC=americas,DC=bmw,DC=corp" -CNSearchbase "OU=Resources,DC=americas,DC=bmw,DC=corp" -Limiter 20
    #region Generating HTML report
    try{
    #Converting Html and sending mail with the reports

    ConvertTo-Html -Title "BMW Removed Autologon Accounts" -Body $html -Head $head |out-file $htmlReportPath

    }
        
    catch{
        Write-Host -BackgroundColor DarkRed "`r`n[$date] Unable to send mail message $error"
        Write-Output "Unable to generate HTML Report Error: $($error[0])" | Write-Log -AdditionalLogPaths $logfilepath,$GeneralScriptLog, $GeneralErrorLog
    }
    #endregion

    Send-RemovedAutologonAccountsMail -FromUser "qqcods0@bmw.de" -Recipients "DL-TDIS-IWS-Report@list.bmw.com"  -SMTPServer "smtp.muc" -DomainSwitch "AMERICAS"
}
else {Write-Output "No Domain Switch parameter has been provided!"|Write-Log -AdditionalLogPaths $GeneralErrorLog,$GeneralScriptLog,$logfilepath}

[System.GC]::Collect() 
