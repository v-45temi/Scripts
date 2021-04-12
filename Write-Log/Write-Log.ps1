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
     
     if (!$Logfilepath){$Logfilepath="$logsfolder"}
     
    try{
        if (!(Test-Path $Logfilepath)){
            #Write-Debug "Creting '$Logfilepath' Folder under '$logsfolder'"
            New-Item -Path $Logfilepath -ItemType Directory -Force -ErrorAction Stop
        }
    }
    catch{
        #Write-Debug "Unable to create DeployScript Folder under '$logsfolder' it will switch to TEMP Folder"
        $Logfilepath = $env:TEMP
        #Write-Debug "Default log folder path is '$env:TEMP'"
        Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR: Unable to create LOG Folder 'DeployScript' under 'c:\Install\Logs\'  ERROR: $($Error[0]) `r`n The log path has been set to '$env:TEMP'" |Add-Content $Logfilepath
        }

    $Logfile= "$logfilepath\$(($MyInvocation.ScriptName | Split-Path -Leaf)).log"
    #Write-Debug "Log file name is: '$Logfile'"
    #Set-Location $LogsFolder 
    
    #Write-Debug "Changing working location to $((Get-Location).path)"
    # Check if logfile size exceeded the limitation of 5MB and removes it
    try{
        if ( (Get-Item $Logfile).length /1MB -gt '5') {
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
        $DateTime = Get-Date -Format ‘yyyy-MM-dd HH:mm:ss’ 
        $Invocation = <#>$($MyInvocation.PSCommandPath | Split-Path -Leaf):</#>"$($MyInvocation.ScriptLineNumber)" 
        Add-Content -Value "[$DateTime] Line:$Invocation $Message" -Path $AdditionalLogPaths -Force 
        Write-Output "[$DateTime] Line:$Invocation $Message" 
    } 
    catch 
    {   Write-Debug " Unable to write log: ERROR: $($error[0])"
        Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR: Unable to write log: ERROR: $($error[0])" |Add-Content $Logfile
        Write-Error $_.Exception.Message 
    }
    #cd .. 
} 
#endregion