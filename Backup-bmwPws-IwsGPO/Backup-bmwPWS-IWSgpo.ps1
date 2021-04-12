<#
.Synopsis
   This script is used for archiving of GPO
.DESCRIPTION
   The script archives GPO via given csv input file with needfull information about the name of the gpo, which are is it placed and CRQ number of the change ticket.
.EXAMPLE
    .\Backup-bmwPWS-IWSgpo.ps1 -InputFile .\inputfile.csv 
.INPUTS
   InputFile .\inputfile.csv
   An example of the file is:
   "ChangeNumber"; "Domain"; "IWS"; "PWS"; "Path"; "PolicyName"
   "CRQ000000005433"; "europe"; "False"; "True"; "C:\GPO_Archive"; "GOChrome-TEST"
.OUTPUTS
   Output from this cmdlet creates a directory and stores the archive gpo data there
.NOTES
   No notes yet 
#>

#Requires -RunAsAdministrator
#Requires -Module GroupPolicy
#Requires -Version 5.0

param(
    [Parameter(Mandatory = $true)]
    [String]$InputFile
)
#region Write-Log Function 
function Write-Log { 
    <#
    .Synopsis
        Write-Log is used to write logs directly by pipelining the message value
    .DESCRIPTION 
         This function is used to write logs by default in $env:TEMP and could be used to write log regarding the script execution in any different location.
         By design it gets the name of the script in which is used and creates a folder with its name under $env:TEMP and writes under the folder a log file
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
            Mandatory = $true,
            ValueFromPipeline = $true)]
        [string]$Message,
        [parameter(
            Mandatory = $False)]
        [Array]$AdditionalLogPaths = @(),
        [string]$Logfilepath

    ) 
    #Logfolder creation
    $LogsFolder = "C:\GPO_Archive\_Logs"
    if (!$Logfilepath) { $Logfilepath = "$logsfolder" }
     
    try {
        if (!(Test-Path $Logfilepath)) {
            New-Item -Path $Logfilepath -ItemType Directory -Force -ErrorAction Stop
        }
    }
    catch {
        $Logfilepath = $env:TEMP
        #Write-Debug "Default log folder path is '$env:TEMP'"
        Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR: Unable to create LOG Folder 'DeployScript' under 'c:\Install\Logs\'  ERROR: $($Error[0]) `r`n The log path has been set to '$env:TEMP'" | Add-Content “$Logfilepath\write-log.log”
    }

    $Logfile = "$logfilepath\$(($MyInvocation.ScriptName | Split-Path -Leaf)).log"
    # Check if logfile size exceeded the limitation of 5MB and removes it
    try {
        if ( (Get-Item $Logfile).length / 1MB -gt '5') {
            Remove-Item $Logfile -Force
            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') WARNING: Logfile has reached size limitation and has been removed successfully!" | Add-Content $Logfile 
        }
    }
    catch {
        Write-Debug "Unable to delete big log file: '$Logfile', there will be created event under Application for this issue, please remove the file manuelly!"
        Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR: Unable to delete big log file: '$Logfile', there will be created event under Application for this issue, please remove the file manuelly! ERROR: $($Error[0])" | Add-Content $Logfile 
        $EventSourceName = "DeployScript"
        if ([System.Diagnostics.EventLog]::SourceExists($EventSourceName) -eq $false) {
            Write-Debug "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Creating event source [$EventSourceName] on event log [Application]"
            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Creating event source [$EventSourceName] on event log [Application]" | Add-Content $Logfile 
            [System.Diagnostics.EventLog]::CreateEventSource("$EventSourceName", 'Application')
        } 
        else { 
            Write-Debug "Event source [$EventSourceName] is already registered"
            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') INFO: Event source [$EventSourceName] is already registered" | Add-Content $Logfile 
        }
        try {
            Write-EventLog -LogName "Application" -Source $EventSourceName -EventID 6666 -EntryType Warning -Message "A log file has reached size limitation and purging of the file failed,`
            please remove the file '$Logfile' manually!" -Category 1 
            Write-Debug "Event Log $EventSourceName  was created"
        } 
        catch {
            Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR: Unable to create event: [$EventSourceName] ERROR: $($Error[0])" | Add-Content $Logfile 
            Write-Debug "Unable to create $EventSourceName"
        }
    }
    try { 
        $AdditionalLogPaths += $Logfile
        $DateTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $Invocation = "$($MyInvocation.ScriptLineNumber)" 
        Add-Content -Value "[$DateTime] Line:$Invocation $Message" -Path $AdditionalLogPaths -Force 
        Write-Output "[$DateTime] Line:$Invocation $Message" 
    } 
    catch {
        Write-Debug " Unable to write log: ERROR: $($error[0])"
        Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR: Unable to write log: ERROR: $($error[0])" | Add-Content $Logfile
        Write-Error $_.Exception.Message 
    }
} 
#endregion

# Invalid Characters remove function
Function Remove-InvalidFileNameChars {
    param(
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [String]$Name
    )

    $invalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
    $re = "[{0}]" -f [RegEx]::Escape($invalidChars)
    return ($Name -replace $re)
}

#Creation of the backup store directory
function New-Directory {
    
    [CmdletBinding(DefaultParameterSetName = "IWS")]
    Param (
        #Parameter Sets
        # Domain 
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1)]
        [Parameter(ParameterSetName = 'PWS')]
        [Parameter(ParameterSetName = 'IWS')]
        [Validateset("africa", "americas", "asiapacific", "china", "europe", "dxc")]
        [string]$Domain,

        # Change Number
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'PWS')]
        [Parameter(ParameterSetName = 'IWS')]
        # Regex (^(INC)\d{12}$)|(^(CRQ)\d{12}$) 
        [ValidatePattern('(?i)(^(INC)\d{12}$)|(^(CRQ)\d{12}$)')]
        [string]$ChangeNumber,

        # Folder path
        [string]$path,

        #Group Policy Name
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'PWS')]
        [Parameter(ParameterSetName = 'IWS')]
        [string]$PolicyName,

        
        # PWS OR IWS Switch
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0,
            ParameterSetName = 'PWS')]
        [switch]$PWS,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0,
            ParameterSetName = 'IWS')]
        [switch]$IWS
    ) 
            

    Begin {
        # Parameters
        Write-Log "******************START******************"
        Write-Progress -Id 1 -Activity "Directory creation" -Status "Begin" -PercentComplete 1
        Write-Log "Begin Directory Creation ..."
        $date = (Get-Date -format 'yyyy-MM-dd-HHmm')

        # Root Name of the Policy extracting to generate a root path in case there are INT,PROD or TEST Policies
        $PolicyFileName = $PolicyName.ToString() | Remove-InvalidFileNameChars
        if ($PolicyFileName -like "*-INT*") {
            $GPORootName = $PolicyName.Replace("-INT", "") 
            Write-Debug "Policy Name: '$PolicyName' has -INT so the root will be '$GPORootName'"
        }
        elseif ($PolicyFileName -like "*-PROD*") {
            $GPORootName = $PolicyFileName.Replace("-PROD", "") 
            Write-Debug "Policy Name: '$PolicyName' has -PROD so the root will be '$GPORootName'"

        }
        elseif ($PolicyFileName -like "*-TEST*") {
            $GPORootName = $PolicyFileName.Replace("-TEST", "") 
            Write-Debug "Policy Name: '$PolicyName' has -TEST so the root will be '$GPORootName'"
            
        }
        elseif ($PolicyFileName -like "*_TEST*") {
            $GPORootName = $PolicyFileName.Replace("_TEST", "") 
            Write-Debug "Policy Name: '$PolicyName' has -TEST so the root will be '$GPORootName'"
            
        }
        else {
            $GPORootName = $PolicyFileName
            Write-Debug "Policy Name: '$PolicyFileName' doesn't have any INT,PROD or TEST so the root will be '$GPORootName'"

        }
        
        # Folder Name Patch generating
        if ($PWS) {
            #######################
            $global:folderpath = "$path\$domain\PWS_$domain\$GPORootName\$PolicyFileName\$($(get-date -Format 'yyyy-MM-dd'))_$ChangeNumber"
            Write-Debug "PWS Policy has been set"
        }
        else {
            $global:folderpath = "$path\$domain\IWS_$domain\$GPORootName\$PolicyFileName\$($(get-date -Format 'yyyy-MM-dd'))_$ChangeNumber"
            Write-Debug "IWS Policy has been set"
        }
        Write-Log "Parameters are set as fallow:`
        Date:'$date'`
        Policy Name: '$PolicyName'`
        Root Policy: '$GPORootName'`
        PWS: '$PWS'`
        IWS: '$IWS'`
        Folder Path: '$folderpath'`
        Change Number: '$ChangeNumber'`
        "
        Write-Debug "Parameters are set as fallow:`
        Date:'$date'`
        Policy Name: '$PolicyName'`
        Root Policy: '$GPORootName'`
        PWS: '$PWS'`
        IWS: '$IWS'`
        Folder Path: '$folderpath'`
        Change Number: '$ChangeNumber'`
        "

    }
    Process {
        try {
            if (Test-Path $folderpath) {
                Write-Debug "Folder path '$folderpath' already exists"
                Write-Log "Folder path '$folderpath' already exists"

            }
            else {
                Write-Debug "Folder '$folderpath' is missing, trying to crate it...."
                Write-Log "Folder '$folderpath' is missing, trying to crate it...."

                Write-Progress -Id 1 -Activity "Directory creation" -Status "Progress" -PercentComplete 50
                #Directory creation
                New-Item $folderpath -ItemType Directory -Force -ErrorAction Stop | Write-Log

                Write-Debug "Directory has been created successfully!"
                Write-Log "Directory has been created successfully!"

            }
        }
        catch [System.ArgumentException] {
            Write-Debug "An Error has been trown, there is invalid charachter in the path: $($Error[0])"
            Write-Log "An Error has been trown, there is invalid charachter in the path: $($Error[0])"
        }
        catch {
            Write-Log "Unable to create directory, please check input data again: $($Error[0])"
            Write-Debug "Unable to create directory, please check input data again: $($Error[0])"
            exit
        }
    
    }
    End {
        Write-Progress -Id 1 -Activity "Directory creation" -Status "Finished" -PercentComplete 100 
        #Backup path
        return $folderpath
    }
}


function Backup-CompanyGPO {
    

    Param (
        #Parameter Sets
        # Domain 
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1)]
        [Validateset("dxc", "Africa", "Americas", "AsiaPacific", "China", "europe", "europe.dxc.test", "Africa.dxc.test", "Americas.dxc.test", "AsiaPacific.dxc.test", "China.dxc.test", "dxc.test")]
        [string]$Domain,

        # Folder path
        [string]$BackupFolderPath,

        #Group Policy Name
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$PolicyName
    ) 

    Begin {
        Write-Progress -Id 2 -Activity "Directory creation" -Status "Begin" -PercentComplete 1
        #Domain names
        if ($domain -like "dxc") { $domain = "dxc.test" }
        if ($domain -like "europe") { $domain = "europe.dxc.test" }
        if ($domain -like "Africa") { $domain = "Africa.dxc.test" }
        if ($domain -like "Americas") { $domain = "Americas.dxc.test" }
        if ($domain -like "AsiaPacific") { $domain = "AsiaPacific.dxc.test" }
        if ($domain -like "China") { $domain = "China.dxc.test" }
        
        Write-Log "Begin..."
        Write-Log "Started by :'$env:USERDOMAIN\$env:USERNAME'"

        # Parameters        
    }
    Process {
        Write-Debug "PROCESS"
        #Domain controller resolution
        Write-Progress -Id 2 -Activity "Domain controler resolution" -Status "Process" -PercentComplete 5
        $DCs = (Get-ADDomain -Identity $domain ).ReplicaDirectoryServers
        [int]$DCn = 1 

        #Get GPO to check existance
        $DCdxc = $dcs | ? { $_ -like "*dxc*" } | Select-Object -First 1
        if ($DCdxc) {
            try {    
                Write-Progress -Id 2 -Activity "Domain controler resolution" -Status "Process" -PercentComplete 25            
                $GpoObject = Get-GPO -Name $PolicyName -Domain $domain -Server $DCdxc -ErrorAction Stop 
                Write-Log "Current DC is $DCdxc"
                $server = $DCdxc
                Write-Progress -Id 2 -Activity "Domain controler resolution" -Status "Process" -PercentComplete 30
            
            }
            catch [System.Runtime.InteropServices.COMException] {
                write-log "!!!An Error has bee thrown, while performing Get-GPO '$PolicyName' for $domain under PDC:'$($DCdxc)' : $($error[0].Exception.Message)"
            } 
            catch [System.ArgumentException] {
                write-log "!!!An Error has bee thrown, while performing Get-GPO '$PolicyName' for $domain under PDC:'$($DCdxc)' : $($error[0].Exception.Message)"
                exit
            } 
        }
        elseif (!$GpoObject) {
            Write-Progress -Id 2 -Activity "Domain controler resolution" -Status "Process" -PercentComplete 25
            do {
                try { 
                    Write-Progress -Id 2 -Activity "GPO check" -Status "Process" -PercentComplete ($DCn / $dcs.count * 100)               
                    $GpoObject = Get-GPO -Name $PolicyName -Domain $domain -Server $DCs[$dcn] -ErrorAction Stop 
                    Write-Log "Current DC is $($Dcs[$dcn]) ($dcn of $($dcs.Count))"
            
                }
                catch [System.Runtime.InteropServices.COMException] {
                    write-log "!!!An Error has bee thrown, while performing Get-GPO '$PolicyName' for $domain under PDC:'$($DCs[$dcn])' (Retry $dcn of $($dcs.Count)): $($error[0].Exception.Message)"
                } 
                catch [System.ArgumentException] {
                    write-log "!!!An Error has bee thrown, while performing Get-GPO '$PolicyName' for $domain under PDC:'$($DCs[$dcn])' (Retry $dcn of $($dcs.Count)): $($error[0].Exception.Message)"
                    exit
                }          
                $DCn++
            }
            until (($null -ne $GpoObject ) -or ($dcn -eq $dcs.count))
            $server = $DCs[$dcn]
            Write-Progress -Id 2 -Activity "GPO check" -Status "Finished" -PercentComplete 100
        }
        Write-Debug "Server is '$server'"

        $GpoID = $GpoObject.ID
        
        #Backup GPO
        try {
            Write-Log "Starting Backup of $PolicyName with an ID: $GpoID"
            Write-Progress -Id 2 -Activity "Backup Gpo $($GpoObject.Name)" -Status "Process" -PercentComplete 1

            #Action
            Backup-GPO -GUID $GpoID -path $BackupFolderPath -Domain $Domain  -ErrorAction Stop -Confirm:$false  -Server $server
            Write-Progress -Id 2 -Activity "Backup Gpo $($GpoObject.Name)" -Status "Process" -PercentComplete 60

            Write-Log "Finished backup of $PolicyName with an ID: $GpoID"
            Write-Progress -Id 2 -Activity "Backup Gpo $($GpoObject.Name)" -Status "Process" -PercentComplete 80
        }
        catch {
            Write-Log "ERROR:Unable to perform the backup Error:$($error[0])"
        }

        #Generate Report
        try {
            Write-Log "Starting report generation of $PolicyName with an ID: $GpoID"

            Write-Progress -Id 2 -Activity "Generate Gpo Report for $($GpoObject.Name)" -Status "Process" -PercentComplete 90
            #Action
            Get-GPOReport -Guid $GPOId -ReportType Html -Domain $domain -Path "$BackupFolderPath\$PolicyName.html" -Server $server

            Write-Log "Finished report generation of $PolicyName with an ID: $GpoID"
            Write-Progress -Id 2 -Activity "Generate Gpo Report for $($GpoObject.Name)" -Status "Process" -PercentComplete 90
        }
        catch {
            Write-Log "ERROR:Unable to generate report Error:$($error[0])"
        }
        
        
    }
    End {
        Write-Progress -Id 2 -Activity "Generate Gpo Report for $($GpoObject.Name)" -Status "Finished" -PercentComplete 100
        Write-Log "******************END******************"
    }
}

#Main call
if (Test-Path $InputFile) {
    Write-Debug "Test path for '$InputFile' successfull!"
    $InputObject = Import-Csv $InputFile -Delimiter ";"
    Write-Debug "Object Impoted"
    $i = 1
    foreach ($item in $InputObject) {
        if ($item.Pws -eq $true) {
            Write-Progress -Activity "Creating Directory for Policy: $($item.policyname) under the domain: $($item.domain)" -Status 'Progress' -PercentComplete ($i / (($InputObject.count * 100) - 5))
            New-Directory -Domain $item.domain  -path $item.Path -PolicyName $item.policyname -PWS -ChangeNumber $item.ChangeNumber


        }
        else { 
            Write-Debug "IWS scenario"
            Write-Progress -Activity "Creating Directory for Policy: $($item.policyname) under the domain: $($item.domain)" -Status 'Progress' -PercentComplete ($i / (($InputObject.count * 100) - 5))  
            New-Directory -Domain $item.domain  -path $item.Path -PolicyName $item.policyname -IWS -ChangeNumber $item.ChangeNumber
        }
        
        Write-Log "DEBUG: $global:folderpath "
        Write-Debug "Calling Backup-CompanyGPO  function"
        Write-Progress -Activity "Backup Policy: $($item.policyname) under the domain: $($item.domain)" -Status 'Progress' -PercentComplete ($i / $InputObject.count * 100)   
        Backup-CompanyGPO  -Domain $item.domain  -PolicyName $item.policyname -BackupFolderPath $global:folderpath 
        $i++
    }
    Write-Progress -Activity "Backup Policy: $($item.policyname) under the domain: $($item.domain)" -Status 'Finished' -PercentComplete 100

}
else { Write-Log "Input file is missing" }

