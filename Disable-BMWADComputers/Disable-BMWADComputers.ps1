<#PSScriptInfo

.VERSION 1.0.0

.AUTHOR Teodora Manova \Teodora.Manova@partner.bmwgroup.com

.COMPANYNAME BMW Group

.TAGS Computers Computer Objects Disabled
#>

<#
.History
2020-08-04 (1.0.0) Teodora Manova Turn the deactivation of the computers on (Real test)
/#>

<#

.DESCRIPTION
Important!The script is developed to be used for scheduled taks!!!
This script is searching for enabled computer accounts under every given domain and creates a report for them. 
Disables them and set a description to this accounts.
After successfully disabling of the accounts, it sends a mail message to given addresses and attaches the reports.
Parameters:
$Threshold = Age of objects, which should be measured in days.
$recipientsnames = All recipients, which should receive the report
$SMTPServer = Mail Exchange server fqdn address
All Paths for the HTML and CSV Report, also for the Logs is hardcoded under C:\ScriptsLogging\Disable-BMWADComputers\, if this directory is not available the script will create it!

Call this script like this:
.\Disable-BMWADComputers.ps1 

#> 

[CmdletBinding()]
param (
    [Parameter()]
    [switch]$EMEA,
    [switch]$ASAPC,
    [switch]$AMERICAS
)
#NegotiateWithImplicitCredential

#region Define scripting variable
$error.clear()
$date = (Get-Date -format 'yyyyMMdd-HHmm')
#[datetime]$date=Get-Date -Format d

[int]$week=get-date -UFormat %V

##Prod Root Path
#$rootpath="\\europe.bmw.corp\WINFS\FG-Data\_Topics\Client_Operation\Documentation\GPO\30_Backup_auto"

##test Root Path
$rootpath="E:\Other\Disable-BMWADComputers"
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
#$Summary=@()
$htmlReportPath="$path\$date-Disable-BMWADComputers_report.html"
#endregion

$global:html=@()
$global:html+="<h2>BMW Disabled Computer Accounts</h2>"
$global:html+="<h3>Please keep in mind there is a limitation of 100 Computer objects for each execution!</h3>"

$Summary=@()
$htmlPath="$path\$date-Disable-BMWADComputers_report.html"


#function for creating needed directories
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
                }
                catch{
                     Write-Output "!!!An Error has bee thrown, while creating directory: $($error[0])" `
                    |write-log -AdditionalLogPaths $GeneralErrorLog
                }
    }

#endregion


}

#Main function for disabling all computers under the COmputers container, which are older then the given threshold
function Disable-BMWADComputers
{
    [CmdletBinding()] 
        param ( 
            [parameter(
            Mandatory         = $true,
            ValueFromPipeline = $true)]
            [string]$Domain,
            [int]$Threshold,
            [parameter(
            Mandatory         = $false,
            ValueFromPipeline = $true)]
            [string]$SearchBase,
            [string]$SearchScope
        )


#region important parameters
    $logFilePath="$path\$date-Disable-BMWADComputers-$domain.log"
    $ReportPath="$path\$date-Disable-BMWADComputers-$domain.csv"
    $report=@()
    #Generating threshold limit and age variable
    if ($Threshold -lt 7){$Threshold=7}
    $days=(get-date).AddDays(-$threshold)
#endregion

    Write-Output "The Script Disable-BMWADComputers has been started!" |Write-Log 
        
#region generating domain names and paths
    
    Write-Host "Domain: $domain" -foregroundcolor red -backgroundcolor yellow

    #Setting paths variables and discovering PrimaryDC for the given domain
    try{
            #Discover PDC emulator + alternate DC logic in the catch blok
            try {$global:server = Get-ADDomainController -DomainName $domain -Discover -Service PrimaryDC
            }
            catch {
            Write-Output "!!!An Error has bee thrown, while discovering PrimaryDC, switching to alternative DC: $($error[0])" `
            |Write-Log -AdditionalLogPaths $GeneralErrorLog,$logFilePath
            $server = Get-ADDomainController -DomainName $domain -Discover -ForceDiscover
            }
            #Domain check and Searchbase check
            $ADDomain=Get-ADDomain $domain -Verbose
            if (!($searchbase)){$searchbase=$ADDomain.ComputersContainer}
            if (!($SearchScope)){$SearchScope="OneLevel"}
            $domainname=($ADDomain.Name)

            Write-Output "`n`n***************************************************************************************************************************** `
            `r`n Domain: '$domainname' `r`n PDC: '$server' `r`n SearchBase: '$SearchBase' `r`n SearchScope: '$SearchScope'`r`n Path of the Reports: '$Path' `r`n Logfilepath: '$logFilePath' `r`n ScriptsLoggingPath: $ScriptNameLogPath `
            `n `n***************************************************************************************************************************** "`
            |Write-Log -AdditionalLogPaths $logFilePath,$GeneralScriptLog 
        }
    catch {
        Write-Output "!!!An Error has bee thrown, while creating Path's directory and discovering PrimaryDC: $($error[0])" `
        |Write-Log -AdditionalLogPaths $GeneralErrorLog,$logFilePath
        }
#endregion        
    
    ##Adding H1 to the html report 
    $global:html+="<h3>Report for all enabled Computer objects under the OU: <p style='color:green'><i>$SearchBase</i></p> For Scope: <p style='color:green'><i>$SearchScope</i></p> And for the Domain <p style='color:green'><i>$Domain</i></p> </h3>"

#region generating report and data for all computer objects under the given search base and domain
    $computers=@()
    $computers+=Get-ADComputer -SearchBase $searchbase -SearchScope $SearchScope -Filter {WhenCreated -lt $days} -Properties Name, Enabled, DNSHostName, WhenCreated,Description -Server $server |Where-Object {$_.Enabled -eq "True"} |Sort-Object Created | select -First 100
    ## Computers count
    $CompCount=$computers.count
    $i=0
    if ($CompCount -like $null){$CompCount="0"}
        try{    
                if ($computers -notlike $null){

                        foreach ($computer in $computers){
                            
                            $i++
                            #Extracting the owner of the computer object and his Q-Account and E-Mail Address
                            
                            #$owner=(Get-Acl -Path ("ActiveDirectory:://RootDSE/" + $Computer.DistinguishedName)).owner
                            [ADSI]$LDAPComputer=("LDAP://"+"$($computer.DistinguishedName)")
                            $SecObj=$LDAPComputer.ObjectSecurity.owner
                            [string]$owner=$secobj.Split('\')[1]

                            $report += New-Object -TypeName PSObject  -Property @{
                                                DistinguishedName=$computer.DistinguishedName;
                                                DNSHostName=$computer.DNSHostName;
                                                Name=$computer.Name;
                                                Enabled=$computer.Enabled;
                                                WhenCreated=$computer.WhenCreated;
                                                AgeInDays=((Get-Date) -($computer.WhenCreated)).Days;
                                                Description=$computer.Description;
                                                Owner=$owner
                                    } # End Property hash table
                            ##Logic for replacing A-account with Q-account and get its mail address
                            <#> if ($owner -match '^.{4,7}$'){
                                
                                $ownerQ=$owner.Replace($owner.Substring(0,1),'q')
                                $owneraddress=(Get-ADUser $ownerQ -Property proxyAddresses).proxyAddresses |Where-Object {$_ -clike "SMTP:*"}
                                if ($owneraddress){
                                $owneraddress=$owneraddress.Split(':')[1]
                                $MailMessage.bcc+=$owneraddress
                                }
                            }</#>

                            Write-Host -BackgroundColor DarkGreen "`r`n[$date]Adding data for $($computer.Name) to the Report File under $($reportpath)///\\\($i of $CompCount)"

                            Write-Output "`Adding data for $($computer.Name) to the Report File under '$ReportPath'///\\\($i of $CompCount)" |Write-Log  -AdditionalLogPaths $logFilePath,$GeneralScriptLog                    
                        }
                }
                else{
                    Write-Output "No enabled computers under  $($Domain.DistinguishedName) found" |Write-Log 
                                                                $report+=New-Object -TypeName PSCustomObject -Property @{
                            Status="No enabled computers found";
                            DistinguishedName="-";
                            DNSHostName="-";
                            Name="-";
                            Enabled="-";
                            WhenCreated="-";
                            AgeInDays="-";
                            Description="-";
                            Owner="-"
                            # End Property hash table
                            }
                }
        }
        catch{
            Write-Host -BackgroundColor DarkRed "`r`n[$date] $error"
            Write-Output "Unable to get information for Computer Objects under '$searchBase' for Domain: '$domainname' Error: $error[0]" | Write-Log -AdditionalLogPaths $GeneralErrorLog,$GeneralScriptLog
            #return
            }      

#endregion

#region Exporting the Report and writing outputs
                $report |Export-Csv -Path $reportpath -NoTypeInformation -Force

                Write-Host -BackgroundColor DarkGreen "`r`n[$date]The Report for $($domain.name) has been generated successfully"

                Write-Output "The Report for $($domain.name) has been generated successfully" |  Write-Log -AdditionalLogPaths $logFilePath,$GeneralScriptLog   


                Write-Output "Please check the Computers under the Report File '$ReportPath' and confirm if you want to disable the computers exceeded the threshold time of '$threshold' Days!" |  Write-Log -AdditionalLogPaths $logFilePath,$GeneralScriptLog
#endregion
#region main function. Disabling the accounts from the report. It will not browse again for those accounts, it will just take them from the reports and disable them directly
                try{
                    if ($computers -notlike $null){
                
                        Write-Host -BackgroundColor DarkGreen "$(get-date -Format s) Starting disabling the Computers exceeded the threshold time of $($threshold) Days" 

                        Write-Output "Starting disabling the Computers exceeded the threshold time of $($threshold) Days" |Write-Log -AdditionalLogPaths $logFilePath,$GeneralScriptLog
    
                        foreach ($ComputerObject in $report){

        
                                Write-Host -BackgroundColor DarkGreen "$(get-date -Format s)Disable $($computerObject)"

                                Write-Output "Disabling $($computerObject.DistinguishedName)" |Write-Log -AdditionalLogPaths $logFilePath,$GeneralScriptLog
                            
                                #Set Description to the computer objects

                                Set-ADComputer $ComputerObject.DistinguishedName -Server $Server -Description "// $(get-date -UFormat %s),Disable-BMWADComputers.ps1 was deactivated in CN=Computers at age: $($ComputerObject.AgeInDays) Days" -Verbose
                                sleep 2
                                ## AXW9632: added confirmation prompt - $false, so it does the step without asking;
                                Disable-ADAccount -Server $server  -Identity $ComputerObject.DistinguishedName -Confirm:$false -ErrorAction Stop                               
                  
                        }
                    }
               
                }
                catch{
                    Write-Host -BackgroundColor DarkRed "`r`n[$date] $error"
                    Write-Output "`r`n[$date]$error" |Write-Log -AdditionalLogPaths $logFilePath,$GeneralScriptLog,$GeneralErrorLog
                    #return
                }
#endregion
                #Adding attachment to @Mailmessage parameter set
                #$MailMessage.Attachments+=($ReportPath)
                #$MailMessage.Body+="`n"
                #$MailMessage.Body+="`nIn Domain \$domainname\ has been $CompCount Computer bojects disabled!"

                #Generating HTML fragment
                $global:html+= "<h2>Count of the active accounts is $CompCount</h2>"
                $global:html+= $report |ConvertTo-Html -As Table -Fragment
                #$report.Clear()
                sleep 2
                Write-Output "The function has been successfully executed, for more information check the log file  '$logfilepath' and '$ReportPath' for a table of all computers reached the given Threshold of $threshold days `r`n
                " |Write-Log -AdditionalLogPaths $logFilePath,$GeneralScriptLog
                Write-Host "The script has been successfully executed, for more information check the log file  C:\ScriptsLogging\Disable-BMWADComputers\$($logfilepath) and $($ReportPath) for a table of all computers reached the gi...."
                $computers.Clear()
    [System.GC]::Collect()
}

function Warn-BMWADComputers
{
    [CmdletBinding()] 
        param ( 
            [parameter(
            Mandatory         = $true,
            ValueFromPipeline = $true)]
            [string]$Domain,
            [int]$Threshold,
            [parameter(
            Mandatory         = $false,
            ValueFromPipeline = $true)]
            [string]$SearchBase,
            [string]$SearchScope
        )


#region important parameters
    $logFilePath="$path\$date-Disable-BMWADComputers-$domain.log"
    $ReportPath="$path\$date-Disable-BMWADComputers_WARNED-$domain.csv"
    $report=@()
    #Generating threshold limit and age variable
    if ($Threshold -lt 7){$Threshold=7}
    $days=(get-date).AddDays(-$threshold)
#endregion

    Write-Output "The Script Disable-BMWADComputers has been started!" |Write-Log 
        
#region generating domain names and paths
    
    Write-Host "Domain: $domain" -foregroundcolor red -backgroundcolor yellow

    #Setting paths variables and discovering PrimaryDC for the given domain
    try{
            #Discover PDC emulator + alternate DC logic in the catch blok
            try {$global:server = Get-ADDomainController -DomainName $domain -Discover -Service PrimaryDC
            }
            catch {
            Write-Output "!!!An Error has bee thrown, while discovering PrimaryDC, switching to alternative DC: $($error[0])" `
            |Write-Log -AdditionalLogPaths $GeneralErrorLog,$logFilePath
            $server = Get-ADDomainController -DomainName $domain -Discover -ForceDiscover
            }
            #Domain check and Searchbase check
            $ADDomain=Get-ADDomain $domain -Verbose
            if (!($searchbase)){$searchbase=$ADDomain.ComputersContainer}
            if (!($SearchScope)){$SearchScope="OneLevel"}
            $domainname=($ADDomain.Name)

            Write-Output "`n`n***************************************************************************************************************************** `
            `r`n Domain: '$domainname' `r`n PDC: '$server' `r`n SearchBase: '$SearchBase' `r`n SearchScope: '$SearchScope'`r`n Path of the Reports: '$Path' `r`n Logfilepath: '$logFilePath' `r`n ScriptsLoggingPath: $ScriptNameLogPath `
            `n `n***************************************************************************************************************************** "`
            |Write-Log -AdditionalLogPaths $logFilePath,$GeneralScriptLog 
        }
    catch {
        Write-Output "!!!An Error has bee thrown, while creating Path's directory and discovering PrimaryDC: $($error[0])" `
        |Write-Log -AdditionalLogPaths $GeneralErrorLog,$logFilePath
        }
#endregion        
    
    ##Adding H1 to the html report 
    $html+="<h2>BMW Warned Computer Accounts</h2>"
    $html+="<h3>Report for all warned Computer objects under the OU: <p style='color:green'><i>$SearchBase</i></p> For Scope: <p style='color:green'><i>$SearchScope</i></p> And for the Domain <p style='color:green'><i>$Domain</i></p> </h3>"

#region generating report and data for all computer objects under the given search base and domain
    $computers=@()
    $computers+=Get-ADComputer -SearchBase $searchbase -SearchScope $SearchScope -Filter {WhenCreated -lt $days} -Properties Name, Enabled, DNSHostName, WhenCreated,Description -Server $server |Where-Object {$_.Enabled -eq "True"} |Sort-Object Created | select -First 100
    ## Computers count
    $CompCount=$computers.count
    $i=0
    if ($CompCount -like $null){$CompCount="0"}
        try{    
                if ($computers -notlike $null){

                        foreach ($computer in $computers){
                            
                            $i++
                            #Extracting the owner of the computer object and his Q-Account and E-Mail Address
                            
                            #$owner=(Get-Acl -Path ("ActiveDirectory:://RootDSE/" + $Computer.DistinguishedName)).owner
                            [ADSI]$LDAPComputer=("LDAP://"+"$($computer.DistinguishedName)")
                            $SecObj=$LDAPComputer.ObjectSecurity.owner
                            [string]$owner=$secobj.Split('\')[1]

                            $report += New-Object -TypeName PSObject  -Property @{
                                                DistinguishedName=$computer.DistinguishedName;
                                                DNSHostName=$computer.DNSHostName;
                                                Name=$computer.Name;
                                                Enabled=$computer.Enabled;
                                                         WhenCreated=$computer.WhenCreated;
                                                AgeInDays=((Get-Date) -($computer.WhenCreated)).Days;
                                                Description=$computer.Description;
                                                Owner=$owner
                                    } # End Property hash table
                            ##Logic for replacing A-account with Q-account and get its mail address
                            <#> if ($owner -match '^.{4,7}$'){
                                
                                $ownerQ=$owner.Replace($owner.Substring(0,1),'q')
                                $owneraddress=(Get-ADUser $ownerQ -Property proxyAddresses).proxyAddresses |Where-Object {$_ -clike "SMTP:*"}
                                if ($owneraddress){
                                $owneraddress=$owneraddress.Split(':')[1]
                                $MailMessage.bcc+=$owneraddress
                                }
                            }</#>

                            Write-Host -BackgroundColor DarkGreen "`r`n[$date]Adding data for $($computer.Name) to the Report File under $($reportpath)///\\\($i of $CompCount)"

                            Write-Output "`Adding data for $($computer.Name) to the Report File under '$ReportPath'///\\\($i of $CompCount)" |Write-Log  -AdditionalLogPaths $logFilePath,$GeneralScriptLog                    
                        }
                }
                else{
                    Write-Output "No enabled computers under  $($Domain.DistinguishedName) found" |Write-Log 
                                                                $report+=New-Object -TypeName PSCustomObject -Property @{
                            Status="No enabled computers found";
                            DistinguishedName="-";
                            DNSHostName="-";
                            Name="-";
                            Enabled="-";
                                     WhenCreated="-";
                            AgeInDays="-";
                            Description="-";
                            Owner="-"
                            # End Property hash table
                            }
                }
        }
        catch{
            Write-Host -BackgroundColor DarkRed "`r`n[$date] $error"
            Write-Output "Unable to get information for Computer Objects under '$searchBase' for Domain: '$domainname' Error: $error[0]" | Write-Log -AdditionalLogPaths $logFilePath, $GeneralErrorLog,$GeneralScriptLog
            #return
            }      

#endregion

#region Exporting the Report and writing outputs
                $report |Export-Csv -Path $reportpath -NoTypeInformation -Force

                Write-Host -BackgroundColor DarkGreen "`r`n[$date]The Report for $($domain.name) has been generated successfully"

                Write-Output "The Report for $($domain.name) has been generated successfully" |  Write-Log -AdditionalLogPaths $logFilePath,$GeneralScriptLog   


                Write-Output "Please check the Computers under the Report File '$ReportPath' of computers exceeded the threshold time of '$threshold' Days!" |  Write-Log -AdditionalLogPaths $logFilePath,$GeneralScriptLog
#endregion
#region main function. Disabling the accounts from the report. It will not browse again for those accounts, it will just take them from the reports and disable them directly
                try{
                    if ($computers -notlike $null){
                
                        Write-Host -BackgroundColor DarkGreen "$(get-date -Format s) Starting warning the Computers exceeded the threshold time of $($threshold) Days" 

                        Write-Output "Starting warning the Computers exceeded the threshold time of $($threshold) Days" |Write-Log -AdditionalLogPaths $logFilePath,$GeneralScriptLog
    
                        foreach ($ComputerObject in $report.DistinguishedName){

        
                                Write-Host -BackgroundColor DarkGreen "$(get-date -Format s) Warning $($computerObject)"

                                Write-Output "Warning $($computerObject)" |Write-Log -AdditionalLogPaths $logFilePath,$GeneralScriptLog
                            
                                #Set Description to the computer objects

                                Set-ADComputer $ComputerObject -Server $Server -Description "// $(get-date -UFormat %s) Deactivation pre-warning" -Verbose

                                #Disable-ADAccount -Identity $ComputerObject -ErrorAction Stop 

                                
                        
                        }
                    }
               
                }
                catch{
                    Write-Host -BackgroundColor DarkRed "`r`n[$date] $error"
                    Write-Output "`r`n[$date]$error" |Write-Log -AdditionalLogPaths $logFilePath,$GeneralScriptLog,$GeneralErrorLog
                }
#endregion
                #Adding attachment to @Mailmessage parameter set
                #$MailMessage.Attachments+=($ReportPath)
                #$MailMessage.Body+="`n"
                #$MailMessage.Body+="`nIn Domain \$domainname\ has been $CompCount Computer bojects disabled!"

                #Generating HTML fragment
                $global:html+= "<h2>Count of the active warned accounts is $CompCount for $domainname</h2>"
                $global:html+= $report |ConvertTo-Html -As Table -Fragment
                #$report.Clear()
                sleep 2
                Write-Output "The function has been successfully executed, for more information check the log file  '$logfilepath' and '$ReportPath' for a table of all computers reached the given Threshold of $threshold days `r`n
                " |Write-Log -AdditionalLogPaths $logFilePath,$GeneralScriptLog
                Write-Host "The script has been successfully executed, for more information check the log file  C:\ScriptsLogging\Disable-BMWADComputers\$($logfilepath) and $($ReportPath) for a table of all computers reached the gi...."
                $computers.Clear()
    [System.GC]::Collect()
}


#Send Mail function
Function Send-DisabledADComputersMail
{
param(
        $FromUser,#=("teodora.manova@partner.bmwgroup.com"),
        $Recipients,#=("Konstantin.Atanassov@partner.bmwgroup.com","teodora.manova@partner.bmwgroup.com"),
        $SMTPServer,#="smtp.muc",
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
                            Body="Hello Team,`n `n Please find attached all the information regarding the performed deactivation of Computer objects uder the CN=Computers for the Region '$DomainSwitch'!`n `n BR,`n `n AD\GPO FG-811";
                            Subject="$SubjectDate Daily computers deactivating for region: $DomainSwitch!";
                            SmtpServer=$SMTPServer;
                            From=$fromUser
                            } # End Property hash table

    }
    catch{
        Write-Output "Unable to create @Mailmessage parameter set $($error[0])" | Write-Log -AdditionalLogPaths $GeneralErrorLog,$GeneralScriptLog
    } 
 
    try{
    #All reports, html and logfiles
    $DisableBMWADComputerFiles=Get-ChildItem -Path $path -Recurse |? {($_.Name -like "*Disable-BMWADComputers*") -and ($_.Name -like "*.csv") -or ($_.Name -like "*.html")} |select -ExpandProperty Fullname 

    #Adding Attachments
    $MailMessage.Attachments+=($DisableBMWADComputerFiles)
    #$MailMessage.Attachments+=($ScriptNameLog)
    if(Test-Path $GeneralErrorLog){
    #$MailMessage.Attachments+=($GeneralErrorLog)
    }
    
    }
    catch{
        Write-Output "Unable to attach the Missing GPO file for @Mailmessage parameter set $($error[0])" | Write-Log -AdditionalLogPaths $GeneralErrorLog,$GeneralScriptLog
    } 
        try{
        Send-MailMessage @MailMessage -Verbose
        Write-Output "E-mail with reports and Logfiles has been send to $($Recipients) successfully!" | Write-Log -AdditionalLogPaths $GeneralScriptLog
    
    }
    catch{
        Write-Output "Unable to send mail message Error: $($error[0])" | Write-Log -AdditionalLogPaths $GeneralErrorLog,$GeneralScriptLog
    } 
}

#Clean Logs
function Cleanup-BackupDirectory 
{ 
param(
      [int]$Age,
      $FoldersKeepCount
)
    Set-Location $rootpath
    $CleanupLogfilepath="$rootpath\Cleaned-Directories.txt"
    Write-Output "[$(get-date -Format 'yyyy-MM-dd HH:mm:ss')]Directory cleanup has been started "|Add-Content $CleanupLogfilepath,$GeneralScriptLog,$ScriptLog
    #$logfiles=@()

#region Discovering all subdirectories and log files under the $rootpath directory
    try{
        $Directories=Get-ChildItem $rootpath |Where-Object {$_.Mode -like "d-----"} |Sort-Object -Property CreationTime
        $Logfiles=Get-ChildItem $rootpath |Where-Object {$_.Mode -like "-a----"} |Sort-Object -Property CreationTime

        ##Calculating the count of the directories and testing the value
        if ($FoldersKeepCount -eq "All"){$DirectoriesCount=0}
        else {
        ## Because folders are created after the run of the line, that is why we need -1 for correcting the folders count in the directory
        $FoldersKeepCount= $FoldersKeepCount -1
        $DirectoriesCount=$Directories.count - $FoldersKeepCount
        $logfilescount=$logfiles.count - $FoldersKeepCount
        }
        
        if ($DirectoriesCount -le 0){
        $DirectoriesCount=0
        $logfilescount=0
        }

        $AgeDays=(Get-Date).AddDays(-($age))
        

        Write-Output "[$(get-date -Format 'yyyy-MM-dd HH:mm:ss')]Directories under $rootpath are $Directories" |Add-Content -Path $CleanupLogfilepath,$GeneralScriptLog,$ScriptLog
        
    }
    catch{
    Write-Output "[$(get-date -Format 'yyyy-MM-dd HH:mm:ss')]!!!An Error has bee thrown, while discovering the subfolders under the root directory and calculating their count : $($error[0])"`
    |Add-Content -Path $CleanupLogfilepath,$GeneralScriptLog,$GeneralErrorLog,$ScriptLog #Out-File $CleanupLogfilepath -Append
    }
 
    if ($DirectoriesCount -eq 0 ){
        Write-Output "[$(get-date -Format 'yyyy-MM-dd HH:mm:ss')]There is no directory older then $agedays or the folders count is under the given count from $FoldersKeepCount" |Add-Content -Path $CleanupLogfilepath,$GeneralScriptLog 
    }
    if ($DirectoriesCount -gt 0){
        $selectedDirectories=($directories |select -First $DirectoriesCount)
        
        Write-Output "[$(get-date -Format 'yyyy-MM-dd HH:mm:ss')]A list of all selected directories:`n$($directories|foreach {"`r`n"+$_.name})"`
        |Add-Content -Path $CleanupLogfilepath,$GeneralScriptLog,$ScriptLog
#endregion
#region Directroies delete
        foreach ($directory in $selectedDirectories){
        
            try{

                    if (($Directory).CreationTime -lt $AgeDays -and ($directory.Name -match '[0-9]{2}-[0-9]{4}(0[1-9]|1[0-2])(0[1-9]|[1-2][0-9]|3[0-1])-(2[0-3]|[01][0-9])[0-5][0-9]')){

                    $directorySize=$directory.FullName.lenght/1mb
                    Write-output "[$(get-date -Format 'yyyy-MM-dd HH:mm:ss')]The directory $directory is older then $agedays and will be removed!" |Add-Content -Path $CleanupLogfilepath,$GeneralScriptLog,$ScriptLog   

                    #removing the folders
                    Remove-Item $Directory -Recurse -Force -verbose -ErrorAction Stop

                    Write-output "[$(get-date -Format 'yyyy-MM-dd HH:mm:ss')]The directory $directory with Size $directorySize has been successfully removed!" |Add-Content -Path $CleanupLogfilepath,$GeneralScriptLog,$ScriptLog   


                    #Rename-Item -Path "$rootpath\$($directory.name)" -NewName "$($Directory.name)-WillBeRemoved" -Verbose

                    }
                    else{ Write-Output "[$(get-date -Format 'yyyy-MM-dd HH:mm:ss')]The Directory:'$directory' didn't reach the age of: $age Days or the folders count is under the given count from $FoldersKeepCount or the Directory doesn't match to the naming convension of the folders"`
                     |Add-Content -Path $CleanupLogfilepath,$GeneralScriptLog,$ScriptLog
                        }
                }
            catch{
            Write-Output "[$(get-date -Format 'yyyy-MM-dd HH:mm:ss')]!!!An Error has bee thrown, while removing the directories : $($error[0])"`
            | Add-Content -Path $CleanupLogfilepath,$GeneralScriptLog,$GeneralErrorLog,$ScriptLog
            }
        }
#endregion
    }

    
#region Logfiles delete
    if ($logfilescount -eq 0 ){
            Write-Output "[$(get-date -Format 'yyyy-MM-dd HH:mm:ss')]There is no Log File older then $agedays or the folders count is under the given count from $FoldersKeepCount" |Add-Content -Path $CleanupLogfilepath,$GeneralScriptLog 
        }
    if ($logfilescount -gt 0){
        $selectedLogFiles=($logfiles |select -First $logfilescount)
        foreach ($Logfile in $selectedLogFiles){
        
                try{

                        if (($Logfile).CreationTime -lt $AgeDays -and ($logfile.Name -match '[0-9]{2}-[0-9]{4}(0[1-9]|1[0-2])(0[1-9]|[1-2][0-9]|3[0-1])-(2[0-3]|[01][0-9])[0-5][0-9]')){

                        $LogfileSize=$Logfile.FullName.lenght/1mb
                        Write-output "[$(get-date -Format 'yyyy-MM-dd HH:mm:ss')]The Log File $($Logfile.Name) is older then $agedays and will be removed!" |Add-Content -Path $CleanupLogfilepath,$GeneralScriptLog,$ScriptLog   

                        #removing the folders
                        Remove-Item $Logfile -Recurse -Force -verbose -ErrorAction Stop

                        Write-output "[$(get-date -Format 'yyyy-MM-dd HH:mm:ss')]The Log File $($Logfile.Name) with Size $LogfileSize has been successfully removed!" |Add-Content -Path $CleanupLogfilepath,$GeneralScriptLog,$ScriptLog   


                        #Rename-Item -Path "$rootpath\$($directory.name)" -NewName "$($Directory.name)-WillBeRemoved" -Verbose

                        }
                        else{ Write-Output "[$(get-date -Format 'yyyy-MM-dd HH:mm:ss')]The Log File:'$($Logfile.Name)' didn't reach the age of: $age Days or the folders count is under the given count from $FoldersKeepCount or the Log doesn't match to the naming convension of the folders"`
                         |Add-Content -Path $CleanupLogfilepath,$GeneralScriptLog,$ScriptLog
                            }
                    }
                catch{
                Write-Output "[$(get-date -Format 'yyyy-MM-dd HH:mm:ss')]!!!An Error has bee thrown, while removing the log files : $($error[0])"`
                | Add-Content -Path $CleanupLogfilepath,$GeneralScriptLog,$GeneralErrorLog,$ScriptLog
                }
          }
    }
#endregion
}



New-BmwScriptLogsDirectories 

 
if ($EMEA){
    Disable-BMWADComputers -Domain "europe.bmw.corp" -Threshold 10 
    Warn-BMWADComputers -Domain "europe.bmw.corp" -Threshold 7 
    
    Disable-BMWADComputers -Domain "emeadecentral.bmw.corp" -Threshold 10
    Warn-BMWADComputers -Domain "emeadecentral.bmw.corp" -Threshold 7

    Disable-BMWADComputers -Domain "africa.bmw.corp" -Threshold 10 
    Warn-BMWADComputers -Domain "africa.bmw.corp" -Threshold 7 

    #region Generating HTML report
    try{
    #Converting Html and sending mail with the reports

    ConvertTo-Html -Title "BMW Disabled Computer Accounts" -Body $html -Head $head |out-file $htmlPath

    }
        
    catch{
        Write-Host -BackgroundColor DarkRed "`r`n[$date] Unable to send mail message $error"
        Write-Output "Unable to generate HTML Report Error: $($error[0])" | Write-Log -AdditionalLogPaths $logFilePath, $GeneralErrorLog,$GeneralScriptLog
    }
    #endregion

    Send-DisabledADComputersMail -FromUser "qqcods0@bmw.de" -Recipients "DL-TDIS-IWS-Report@list.bmw.com" -SMTPServer "smtp.muc" -DomainSwitch "EMEA"
}
elseif ($ASAPC){
    Disable-BMWADComputers -Domain "asiapacific.bmw.corp" -Threshold 10
    Warn-BMWADComputers -Domain "asiapacific.bmw.corp" -Threshold 7 

    Disable-BMWADComputers -Domain "china.bmw.corp" -Threshold 10 
    Warn-BMWADComputers -Domain "china.bmw.corp" -Threshold 7
     
    #region Generating HTML report
    try{
    #Converting Html and sending mail with the reports

    ConvertTo-Html -Title "BMW Disabled Computer Accounts" -Body $html -Head $head |out-file $htmlPath

    }
        
    catch{
        Write-Host -BackgroundColor DarkRed "`r`n[$date] Unable to send mail message $error"
        Write-Output "Unable to generate HTML Report Error: $($error[0])" | Write-Log -AdditionalLogPaths $logFilePath, $GeneralErrorLog,$GeneralScriptLog
    }
    #endregion

    Send-DisabledADComputersMail -FromUser "qqcods0@bmw.de" -Recipients "DL-TDIS-IWS-Report@list.bmw.com" -SMTPServer "smtp.muc" -DomainSwitch "ASAPC"
}
elseif ($AMERICAS){
    Disable-BMWADComputers -Domain "americas.bmw.corp" -Threshold 10     
    Warn-BMWADComputers -Domain "americas.bmw.corp" -Threshold 7
    
    #region Generating HTML report
    try{
    #Converting Html and sending mail with the reports

    ConvertTo-Html -Title "BMW Disabled Computer Accounts" -Body $html -Head $head |out-file $htmlPath

    }
        
    catch{
        Write-Host -BackgroundColor DarkRed "`r`n[$date] Unable to send mail message $error"
        Write-Output "Unable to generate HTML Report Error: $($error[0])" | Write-Log -AdditionalLogPaths $logFilePath, $GeneralErrorLog,$GeneralScriptLog
    }
    #endregion

    Send-DisabledADComputersMail -FromUser "qqcods0@bmw.de" -Recipients "DL-TDIS-IWS-Report@list.bmw.com" -SMTPServer "smtp.muc" -DomainSwitch "AMERICAS"
}
else {Write-Output "No Domain Switch parameter has been provided!"|Write-Log -AdditionalLogPaths $GeneralErrorLog,$GeneralScriptLog}

[System.GC]::Collect() 
