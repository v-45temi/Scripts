<#
.Synopsis
   Checkt which are the reported from the devices missing KBs
.DESCRIPTION
   It reads the not found log under the Standard place \\netupdate.HAJgroup.net\logs$\_not_found.log and analyse the missing KBs and the computers which has reported them
.EXAMPLE
   .\Get-NotfoundKBs.ps1
.EXAMPLE
   .\Get-NotfoundKBs.ps1 -debug
#>
#region Important Parameters
$date = (Get-Date -format 'yyyyMMdd_HHmm')

$FilesFolder = "E:\netupdate\notfoundlogs\$date"
Set-Location $FilesFolder
$notfoundlogpath = "E:\logs\netupdate\_not_found.log"

#In case issues with saving files under the shared folder, the folder should be mapped as PSDrive to bypass the long folder name error.
 
param ( 
        [parameter(
        Mandatory         = $true,
        ValueFromPipeline = $true)]
        [string]$SharedFolder,
        $SiteCode,
        $SiteServer

    ) 
#endregion

#region Write-Log Function 
function Write-Log 
{ 
    <#
    .Synopsis
        Write-Log is used to write logs directly by pipelining the message value
    .DESCRIPTION 
         This function is used to write logs by default in $env:ScriptsLoggingPath and could be used to write log regarding the script execution in any different location.
         By design it gets the name of the script in which is used and creates a folder with its name under $env:ScriptsLoggingPath and writes under the folder a log file
    .SYNOPSIS 
        This function creates or appends a line to a log file. 
 
    .PARAMETER  Message 
        -Message parameter is the log message you'd like to record to the log file. 
        -AdditianalLogPaths any additianal path, where the function should add the content, keep in mind the path should be whole file path plus its extension as example "C:\temp\thislog.txt"

    .EXAMPLE 
        PS C:\> Write-Log -Message 'Value1' 
        This example shows how to call the Write-Log function with named parameters.
    .EXAMPLE          
        PS C:\>"Value" | Write-Log 
    .EXAMPLE 
        PS C:\>"Value" | Write-Log -AdditioanaLogPaths "C:\temp\thislog.txt"
    .EXAMPLE 
        PS C:\>"Value" | Write-Log -AdditioanaLogPaths  $path1,$path2,$path3
    #> 

    [CmdletBinding()] 
    param ( 
        [parameter(
        Mandatory         = $true,
        ValueFromPipeline = $true)]
        [string]$Message,
        [parameter(
        Mandatory = $False)]
        [Array]$AdditionalLogPaths=@(),
        [string]$Logfilepath

    ) 
     #if ($debuger) {$DebugPreference = "Continue"}
     #Logfolder creation
     
     #if (!$Logfilepath){$Logfilepath="$logsfolder"}
     $Logfilepath = $filesfolder
    try{
        if (!(Test-Path $Logfilepath)){
            #Write-Debug "Creting '$Logfilepath' Folder under '$logsfolder'"
            New-Item -Path $Logfilepath -ItemType Directory -Force -ErrorAction Stop
        }
    }
    catch{
        #Write-Debug "Unable to create DeployScript Folder under '$logsfolder' it will switch to TEMP Folder"
        #$Logfilepath = $env:TEMP
        #Write-Debug "Default log folder path is '$env:TEMP'"
        Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR: Unable to create LOG Folder 'DeployScript' under '$Logfilepath'  ERROR: $($Error[0]) `r`n The log path has been set to '$env:TEMP'" |Add-Content $Logfilepath
        }

    $Logfile= "$filesfolder\$($date)-$(($MyInvocation.ScriptName | Split-Path -Leaf)).log"
    #Write-Debug "Log file name is: '$Logfile'"
    #Set-Location $LogsFolder 
    
    #Write-Debug "Changing working location to $((Get-Location).path)"
    # Check if logfile size exceeded the limitation of 5MB and removes it
    try{
        if ( (Get-Item $Logfile -ErrorAction SilentlyContinue).length /1MB -gt '5') {
            #Write-Debug "The log file size is bigger then 5MB, it will be deleted "
            Remove-Item $Logfile -Force
            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') WARNING: Logfile has reached size limitation and has been removed successfully!" |Add-Content $Logfile 
        }
    }
    catch{
        Write-Debug "Unable to delete big log file: '$Logfile', there will be created event under Application for this issue, please remove the file manuelly!"
        Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR: Unable to delete big log file: '$Logfile', there will be created event under Application for this issue, please remove the file manuelly! ERROR: $($Error[0])" |Add-Content $Logfile 
        $EventSourceName = "DeployScript"
        if ([System.Diagnostics.EventLog]::SourceExists($EventSourceName) -eq $false) {
            Write-Debug "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Creating event source [$EventSourceName] on event log [Application]"
            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Creating event source [$EventSourceName] on event log [Application]" |Add-Content $Logfile 
            [System.Diagnostics.EventLog]::CreateEventSource("$EventSourceName",'Application')
        } 
        else { 
            Write-Debug "Event source [$EventSourceName] is already registered"
            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') INFO: Event source [$EventSourceName] is already registered" |Add-Content $Logfile 
        }
        try {
            Write-EventLog -LogName "Application" -Source $EventSourceName -EventID 6666 -EntryType Warning -Message "A log file has reached size limitation and purging of the file failed,`
            please remove the file '$Logfile' manually!" -Category 1 
            Write-Debug "Event Log $EventSourceName  was created"
        } 
        catch {
            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR: Unable to create event: [$EventSourceName] ERROR: $($Error[0])" |Add-Content $Logfile 
            Write-Debug "Unable to create $EventSourceName"
        }
    }
    try 
    { 
        $AdditionalLogPaths+=$Logfile
        if ($debuger){
            $n=0
            foreach ($log in $AdditionalLogPaths){
                #Write-Debug "Log file ['$n' of '$($AdditionalLogPaths.count)' : '$log']"
                $n++
            }
        }
        $DateTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss' 
        $Invocation = <#>$($MyInvocation.PSCommandPath | Split-Path -Leaf):</#>"$($MyInvocation.ScriptLineNumber)" 
        Add-Content -Value "[$DateTime] Line:$Invocation $Message" -Path $AdditionalLogPaths -Force 
        #Write-Output "[$DateTime] Line:$Invocation $Message" 
    } 
    catch 
    {   Write-Debug " Unable to write log: ERROR: $($error[0])"
        Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR: Unable to write log: ERROR: $($error[0])" |Add-Content $Logfile
        Write-Error $_.Exception.Message 
    }
    #cd .. 
} 
#endregion

#region get=HAJupdates function
function Get-HAJAvailableUpdates {
    [CmdletBinding()]
    param (
        [string]$SiteCode,
        [string]$SiteServer,
        [array]$PatchID 
    )
    
    begin {
        #Parameters
        $global:report=@()
        $updates =@()
        try {
            $UpdatePackageIDs = (Get-WmiObject -ComputerName $SiteServer -Namespace root/SMS/site_$($SiteCode) -Class SMS_SoftwareUpdatesPackage)
            #Write-Debug "Found $UpdatePackageIDs.count"
            #Write-Debug $UpdatePackageIDs
        }
        catch {
            Write-Output "Unable to get Package IDs Error: $($error[0])"
        }
    }
    
    process {
        try {
            foreach ($UpdatePackageid in $UpdatePackageIDs){
                Write-Debug "Package ID: '$UpdatePackageid'"
                $Updates += Get-WmiObject -Namespace root/SMS/site_$($SiteCode) -ComputerName $SiteServer -Query "SELECT DISTINCT su.* FROM SMS_SoftwareUpdate AS su JOIN SMS_CIToContent AS cc `
                    ON  SU.CI_ID = CC.CI_ID JOIN SMS_PackageToContent AS pc ON pc.ContentID=cc.ContentID  WHERE  pc.PackageID='$($UpdatePackageid.PackageID)' "
                if ($patchid.count -gt 1){
                    Write-Debug "Patchid gt 1"
                    $ids = @()
                    foreach ($object in $patchid){
                        $ids += ($updates |Where-Object {$_.articleid -like "*$object*"})
                    }
                    if ($ids){
                        foreach ($update in $ids){
                            Write-Debug "Update: '$($update.articleid)'"
                            $global:report += New-Object -TypeName PSObject -Property @{
                                PackageID = $UpdatePackageid.PackageID
                                PkgName = $UpdatePackageid.Name;
                                PkgSourcePath = $UpdatePackageid.PkgSourcePath;
                                PkgDescription = $UpdatePackageid.Description;
                                ArticleID = $update.articleid;
                                IsDeployed = $update.IsDeployed;
                                IsExpired = $update.IsExpired;
                                IsSuperseded = $Update.IsSuperseded;
                                IsBundle = $update.IsBundle;
                                DateCreated = [datetime]::ParseExact(($update.DateCreated.Replace(".000000+000","")),'yyyyMMddHHmmss',$null);
                                DatePosted = [datetime]::ParseExact((($update.DatePosted).Replace(".000000+000","")),'yyyyMMddHHmmss',$null);
                                LocalizedCategoryInstanceNames = ($Update.LocalizedCategoryInstanceNames -join ";");
                                LocalizedDisplayName = $update.LocalizedDisplayName;
                                LocalizedInformativeURL = $update.LocalizedInformativeURL;
                            }
                        }
                    }
                    else {Write-Host "No Updates found under '$UpdatePackageid'"}

                }
                else{
                    Write-Debug "patchid not gt 1"
                    $foundupdates = ($updates |Where-Object {$_.articleid -like "*$PatchID*"})
                    if ($foundupdates){
                        foreach ($update in $foundupdates){
                            Write-Debug "Update: '$($update.articleid)'"
                            $global:report += New-Object -TypeName PSObject -Property @{
                                PackageID = $UpdatePackageid.PackageID
                                PkgName = $UpdatePackageid.Name;
                                PkgSourcePath = $UpdatePackageid.PkgSourcePath;
                                PkgDescription = $UpdatePackageid.Description;
                                ArticleID = $update.articleid;
                                IsDeployed = $update.IsDeployed;
                                IsExpired = $update.IsExpired;
                                IsSuperseded = $Update.IsSuperseded;
                                IsBundle = $update.IsBundle;
                                DateCreated = [datetime]::ParseExact(($update.DateCreated.Replace(".000000+000","")),'yyyyMMddHHmmss',$null);
                                DatePosted = [datetime]::ParseExact((($update.DatePosted).Replace(".000000+000","")),'yyyyMMddHHmmss',$null);
                                LocalizedCategoryInstanceNames = ($Update.LocalizedCategoryInstanceNames -join ";");
                                LocalizedDisplayName = $update.LocalizedDisplayName;
                                LocalizedInformativeURL = $update.LocalizedInformativeURL;
                            }
                        }
                    }
                }            
            }
            if ($foundupdates -or $ids){
                Write-Host "Generating report"
                $report
                $report |Export-Csv -Path "$FilesFolder\$date-PatchesNotFound.csv" -NoTypeInformation -Delimiter  ";" -Append 
            }
            else {
                Write-Host "No Updates found with this ID: '$patchID'!"
            }   
        }
        catch {
            Write-Host "Unable to get Info for $patchID"
        }
    }
    
    end {
        if (!$updates) {
            Write-Host "$patchId was not found under the HAJ Packages"
        }
        else {
            return $report
        }
    }
}

#endregion

#region main function
function Get-NotfoundKB
{
    [CmdletBinding()]
    Param
    (
        # Not found log patch
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        #$notfoundlogpath = 'E:\logs\netupdate\_not_found.log', #'\\netupdate.HAJgroup.net\logs$\netupdate\_not_found.log',
        [int]$n = 300
        
    )

    Begin
    {
        Write-Log "************************START************************"
        <#
        try {
            $notfoundlog = Get-Content -Path $notfoundlogpath 
        }
        catch {
            Write-Log "ERROR: Unable to get the content from the given path '$notfoundlogpath', please check the file again. Error: $($error[0])"
            exit
        }/#>
        try {
            $notfoundlogcsv = Import-Csv $notfoundlogpath -Delimiter ";" 
        }
        catch {
            Write-Log "ERROR: Unable to convert the notfound log content from csv in PsObject . Error: $($error[0])"
            exit
        }
    }
    Process
    {
        $TopNotFoundKBs = ($notfoundlogcsv |Group-Object -Property KbArticle -NoElement |Select-Object Name, Count|Sort-Object -Descending Count)[0..$n]

        
        Write-Log "Top Not found Kbs count is: '$($TopNotFoundKBs.count)'"

        try {
            $TopNotFoundKBs |Export-Csv -Delimiter ";" -NoTypeInformation -Path "$FilesFolder\$date-TopNotFoundKbs.csv"
            Write-Log "Top not found KBs: `
ArticleID:CountOfComputers            
$($TopNotFoundKBs |ForEach-Object {
$_.Name + ':' + $_.Count  + '
'
            })"
            #Write-Log "The report could be found under" + ".\$date" +"-TopNotFoundKbs.csv"
        }
        catch {
            Write-Log "ERROR: Unable to convert the object '$($TopNotFoundKBs.gettype())' to csv and export it. Error: $($error[0])"
        }
        Write-Log "Starting search of the missing KBs under the SCCM Library..."
        try {
            $timestart = Get-Date
            Write-Log "Startet at '$timestart'"
            $AvailableKBs = (Get-HAJAvailableUpdates -patchId ($TopNotFoundKBs.Name)).ArticleID -SiteCode $siteCode -SiteServer $SiteServer |Select-Object -Unique
            $timeend = Get-Date
            Write-Log "End at '$timeend'"
            if ($availablekbs){
                Write-Log "Found '$($AvailableKBs.count)' available in SCCM from '$($TopNotFoundKBs.count)' reported as missing! You can find the report under the path you have executed the script or under '$SharedFolder'"# + ".\$date-PatchesNotFound.csv)"
                $global:MissedKBs = ($TopNotFoundKBs |Where-Object {$_.name -NotIn $availablekbs.split(" ")})
                $MissedKBs |Export-Csv -Delimiter ";" -NoTypeInformation -Path "$filesfolder\$date-MissingKbs.csv"


                $global:MissingKBs_ForSCCMTeam = ($notfoundlogcsv |Group-Object -Property KbArticle,PatchID -NoElement |Select-Object Name, Count|Sort-Object -Descending Count)[0..$n] | Where-Object {$_.name -NotIn $availablekbs.split(" ")}


                Write-Log "Count of missing KBs is $($MissedKBs.count). The list of them is: $($MissedKBs.Name)"
            }
            else {Write-Log "No reported as missing kbs has been found, check the input data again!"}
        }
        catch {
            Write-Log "ERROR: Unable to execute the function Get-HAJAvailableUpdates. Error: $($error[0])"
        }
    }
    End
    {
        
        return $global:MissedKBs
        Write-Log "************************END************************"
    }
}
#endregion

 #region new html function
 function New-HtmlReport {
    [CmdletBinding()]
    
    param (
        $Path = (Get-Location),
        $title,
        $footer
    )
    if (!$date){$date = (Get-Date -format 'yyyyMMdd_HHmm')}
    
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
    position: right;
    border: 1px solid #ddd;
    width: 60%;
    padding: 8px;
    overflow-x:auto

}



tr:nth-child(even){background-color: #f2f2f2;}



tr:hover {background-color: #ddd;}



th {
    width: 60%;
    padding-top: 6px;

    padding-bottom: 12px;

    text-align: left;

    background-color: #4CAF50;

    color: white;

} </style>

"@
    #endregion

    try {
        $csv_PatchesNotFound = Get-ChildItem -Path (Get-Location).Path -Recurse |Where-Object {($_.Name -like "$($date)-PatchesNotFound.csv*")} |Select-Object -ExpandProperty Fullname 

        $csv_missingKB = Get-ChildItem -Path (Get-Location).Path -Recurse |Where-Object {($_.Name -like "$($date)-MissingKBs.csv*")} |Select-Object -ExpandProperty Fullname 
    }

    catch {
        Write-Log "ERROR: Unable to get the csv reports under the location of execution. Error: $($error[0])"
    }
    
    $global:html=@()
    $global:html+="<h2>$Title</h2>"
    #Missing KBs fragment
<#>    $global:html += '
<div class="dropdown">
<span>The following KB Articles were reported as not found from Netupdate Clients and was not found under the HAJ Library:</span>
<div class="dropdown-content">
<h3>The following KB Articles were reported as not found: </h3>'
$global:html+= Import-Csv -Delimiter ';' -LiteralPath $csv_missingKB |ConvertTo-Html -As Table -Fragment 
$global:html += '
</div>
</div>'</#>
    $global:html += "<h3>The following KB Articles were reported as not found from Netupdate Clients and was not found under the HAJ Library: </h3>"
    $global:html+= Import-Csv -Delimiter ';' -LiteralPath $csv_missingKB |ConvertTo-Html -As Table -Fragment

    #All the reported as not found, but actually available under HAJ
   <#> $global:html += '
    <div class="dropdown">
    <span>All the reported as not found, but actually available under HAJ:</span>
    <div class="dropdown-content">
    <h3>The following KB Articles were found under HAJ: </h3>'
    $global:html+= Import-Csv -Delimiter ';' -LiteralPath $csv_PatchesNotFound |ConvertTo-Html -As Table -Fragment 
    $global:html += '
    </div>
    </div>'</#>

    $global:html += "<h3>All the reported as not found, but actually available under HAJ: </h3>"
    $global:html+= Import-Csv -Delimiter ';' -LiteralPath $csv_PatchesNotFound |ConvertTo-Html -As Table -Fragment
    
    if ($footer){
        $global:html+= $footer #|ConvertTo-Html -As Table -Fragment
    }
    $htmlPath="$path\$date-$($title.replace(' ','-')).html"
    
    ConvertTo-Html -Title $title -Body $html -Head $head  |out-file $htmlPath.ToString()
}
   
#New-HtmlReport -title "NotFound MS Article IDs"
#endregion

#region Copy report files to the shared folder

function Copy-NotFoundReports {

    try{
        if (Test-Path $SharedFolder -ErrorAction Stop){
            Copy-Item -Path $FilesFolder -Destination $SharedFolder -Recurse -Force
            Write-Log "Successfully copied notfound reports from folder '$FilesFolder' to the shared folder '$SharedFolder'!"
        }
    }
    catch{
        Write-Log "ERROR while copying files folder '$FilesFolder' to shared folder '$SharedFolder' ERROR MESSAGE: $($Error[0])"
    }
}

#endregion

#region Send Mail function
Function Send-Mail
{
param(
        $FromUser,#=("teodora.manova@partner.HAJgroup.com"),
        $Recipients,#=("Konstantin.Atanassov@partner.HAJgroup.com","teodora.manova@partner.HAJgroup.com"),
        $SMTPServer,#="smtp.muc",
        $content 
        
        
)   
        #$user=$env:USERNAME
        #$fromUser=Get-ADUser -filter {Name -like $user} -Properties Mail |select -ExpandProperty Mail
        $SubjectDate=Get-Date
        #$log=Get-ChildItem -Path (Get-Location).Path -Recurse |Where-Object {($_.Name -like "*.log*")} |Select-Object -ExpandProperty Fullname 
        $csv_missingKB = Get-ChildItem -Path $FilesFolder -Recurse |Where-Object {($_.Name -like "$($date)-MissingKBs.csv*")} |Select-Object -ExpandProperty Fullname
        $content = $global:MissingKBs_ForSCCMTeam  #Import-Csv -Delimiter ';' -LiteralPath $csv_missingKB 

        #$Bcc=@()
    try{
        $MailMessage=@{}
        $MailMessage +=  @{
                            To=$Recipients;
                            #Bcc=$Bcc;
                            #Attachments=@();
                            Body="Hello Team,`n `n Please find  all the information regarding the monthly analyse of the missing KBs under the Not_Found.log under the shared folder: '$SharedFolder' !`n `n `
        Not Found Article IDs:`
        '$($content | ForEach-Object {"`r`n $_ "})'
        `r`n BR,
        `n `n DeployScript FG-811";
                            Subject="$SubjectDate Monthly Not_Found log analyse!";
                            SmtpServer=$SMTPServer;
                            From=$fromUser
                            } # End Property hash table

    }
    catch{
        Write-log "Unable to create @Mailmessage parameter set $($error[0])" 
    } 
    <#
    try{
        #All reports, html and logfiles
        $log=Get-ChildItem -Path $FilesFolder -Recurse |Where-Object {($_.Name -like "$($date)*.log*")} |Select-Object -ExpandProperty Fullname 
        $csvreports = Get-ChildItem -Path $FilesFolder -Recurse |Where-Object {($_.Name -like "$($date)*.csv*")} |Select-Object -ExpandProperty Fullname 
        $html = Get-ChildItem -Path $FilesFolder -Recurse |Where-Object {($_.Name -like "$($date)*.html*")} |Select-Object -ExpandProperty Fullname
        
        if ($log){
            #Adding Attachments
            $MailMessage.Attachments+=($log)
        }
        if ($csvreports){
            $MailMessage.Attachments+=($csvreports)
        }
        if ($html){
            $MailMessage.Attachments+=($html)
        }
    
    }
    catch{
        Write-Log "Unable to attach the file for @Mailmessage parameter set $($error[0])" 
    } /#>
        try{
        Send-MailMessage @MailMessage -Verbose
        Write-Log "E-mail with reports and Logfiles has been send to $($Recipients) successfully!" 
    
    }
    catch{
        Write-Log "Unable to send mail message Error: $($error[0])" 
    } 
}
#endregion

#region find patch thuesday
Function Get-PatchTuesday {
	  [CmdletBinding()]
	  Param
	  (
	    [Parameter(position = 0)]
	    [ValidateSet("Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday")]
	    [String]$weekDay = 'Tuesday',
	    [ValidateRange(0, 5)]
	    [Parameter(position = 1)]
	    [int]$findNthDay = 2
	  )
	  # Get the date and find the first day of the month
	  # Find the first instance of the given weekday
	  [datetime]$today = [datetime]::NOW
	  $todayM = $today.Month.ToString()
	  $todayY = $today.Year.ToString()
	  [datetime]$strtMonth = $todayM + '/1/' + $todayY
	  while ($strtMonth.DayofWeek -ine $weekDay ) { $strtMonth = $StrtMonth.AddDays(1) }
	  $firstWeekDay = $strtMonth
	
	  # Identify and calculate the day offset
	  if ($findNthDay -eq 1) {
	    $dayOffset = 0
	  }
	  else {
	    $dayOffset = ($findNthDay - 1) * 7
	  }
	  
	  # Return date of the day/instance specified
	  $patchTuesday = $firstWeekDay.AddDays($dayOffset) 
	  return $patchTuesday
	}

#endregion


#region calling Functions

$patchdaydate = Get-PatchTuesday

#The script will run 10 days after MS patchday
if ($patchdaydate.adddays(10).day -eq (Get-Date).day){

#getting not found KBs
    Get-NotfoundKB

#copying files to shared folder
    Copy-NotFoundReports
#Move and rename not found log
<# 

try {
    Move-Item $notfoundlogpath -Destination "$SharedFolder\$date\$date-_not_found.log"
}
Catch{
    Write-Log "Unable to move and rename the not_found.log ERROR: $($Error[0])"
}

/#>

#sending mail message
    Send-Mail    -SMTPServer "smtp.muc" -FromUser "qqntup0@europe.HAJ.corp" -Recipients "DeployScript_Operations@list.HAJ.com" 
}
else{
    Write-Log "It is just the $((Get-Date).day) of the Month! The script will run on $($patchdaydate.adddays(10))!"
}
#endregion