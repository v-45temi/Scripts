<#
.Synopsis
   The script deactivates vlan tags and enables monitore mode
.DESCRIPTION
   There are some known issues capturing V-LAN tagged Ethernet frames in Windows using a standard NIC. Some NICs remove the V-LAN tags or drop V-LAN frames completely. You can find a more detailed explanation and some configuration flags for various NIC manufacturers in the Wireshark Wiki (https://gitlab.com/wireshark/wireshark/-/wikis/CaptureSetup/VLAN#windows).

    Die Einstellung "VLAN Tags enabled" ist für diejenige Ethernet-Karte erforderlich, an der die Messtechnik (der Fa. Vector Informatik hängt), um v-lan-tagged Ethernet frames aufzeichnen zu können.

    Folgende Einstellung soll an der betroffenen Netzwerkkarte der Fa. Intel, Modell I350 - verwendet  in dem BIV-Gerät der Fa.  Supermicro - vorgenommen werden dürfen:

    # Eigenschaften -> Konfiguration -> Priority&VLAN – disabled setzen
    # Registry editieren (regedit.exe)

                    HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx\MonitorModeEnabled  DWORD 1

                    HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx\MonitorMode  DWORD: 1

                     “xx” entspricht dabei dem Netzwerkinterface dessen Priority&VLAN Key auf 0 steht
    
    # Windows-Neustart ist notwendig, damit Änderungen übernommen werden
    Rechnername: MMUC815635 Netzwerkarte.Nr.7
    Logs are stored under C:\Install\Logs

.EXAMPLE
   .\Disable-HAJVLANTag.ps1 -EnableMonitor
   Standard use, it will disable Vlan & Priority Tag and create and enable monitor mode

.EXAMPLE
    .\Disable-HAJVLANTag.ps1 -DisableMonitor -Enablevlantag
    Reverts the settings by disabling the monitor mode and enabling vlan & priority tag (as setting the registry to 3, this could also changed on "if ($enablevlantag){$regvaluevlan='3'}")
.AUTHOR
   07.12.2020 Teodora Manova 
#>

<#Requires -RunAsAdministrator/#>



#region IMPORTANT parameters!
[CmdletBinding(DefaultParameterSetName="Enable")]
Param
(
    # Log folder path
    [Parameter(Mandatory=$false,
                ValueFromPipelineByPropertyName=$true,
                Position=0)]
    [Parameter(ParameterSetName = 'Disable')]
    [Parameter(ParameterSetName = 'Enable')]
    [string]$LogsFolder="C:\Install\Logs",

    # Interface description parameter
    [Parameter(ParameterSetName = 'Disable')]
    [Parameter(ParameterSetName = 'Enable')]
    [string]$InterfaceDescription= 'Intel(R) I350 Gigabit Network Connection #7',

    # PCAP hardware parameter
    [Parameter(ParameterSetName = 'Disable')]
    [Parameter(ParameterSetName = 'Enable')]
    [string]$SlotName='PCAP',

    # Registry Key
    [Parameter(ParameterSetName = 'Disable')]
    [Parameter(ParameterSetName = 'Enable')]
    $RegKey='HKLM:\SYSTEM\ControlSet001\Control\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}',
    
    # 'MonitorModeEnabled' property parameter
    [Parameter(ParameterSetName = 'Disable')]
    [Parameter(ParameterSetName = 'Enable')]
    $RegKeyWord1='MonitorModeEnabled',

    # 'MonitorMode' property parameter
    [Parameter(ParameterSetName = 'Disable')]
    [Parameter(ParameterSetName = 'Enable')]
    $RegKeyWord2='MonitorMode',

    # Type of the registry as property parameter
    [Parameter(ParameterSetName = 'Disable')]
    [Parameter(ParameterSetName = 'Enable')]
    $RegKeyType='REG_DWORD',

    #Switch parameter for EnableMonitor mode, which will enable the monitor but disable vlan tag as requested initially 
    #[Parameter(Mandatory=$true,ParameterSetName = 'Enable')]
    #[switch]$EnableMonitor,

    #Switch parameter for DisableMonitor mode, which will disable the monitor. It can be used with EnableVLANtag parameter
    #[Parameter(Mandatory=$true,ParameterSetName = 'Disable')]
    #[switch]$DisableMonitor,

    #Switch parameter for EnableVLANTag, which will enable the VLAN Tag and set it to the value of 3. It could be used only with DisableMonitor
    #[Parameter(ParameterSetName = 'Disable')]
    #[switch]$Enablevlantag
    
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

#region Main function
function Disable-VLANTag
{
    [CmdletBinding()]
    Param
    (
        # Function parameters blok
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $InterfaceDescription,
        $RegKey,
        $RegKeyWord1,
        $RegKeyWord2,
        $RegKeyType,
        $SlotName,
        #Switch parameter for EnableMonitor mode, which will enable the monitor but disable vlan tag as requested initially 
        [switch]$EnableMonitor,
    
        #Switch parameter for DisableMonitor mode, which will disable the monitor. It can be used with EnableVLANtag parameter
        [switch]$DisableMonitor,
    
        #Switch parameter for EnableVLANTag, which will enable the VLAN Tag and set it to the value of 3. It could be used only with DisableMonitor
        [switch]$Enablevlantag

    )

    Begin
    {
        # PCAP Interface 
        try{
            if (Get-NetAdapter -Name $SlotName -ErrorAction Stop){
                $NetAdapter = Get-NetAdapter -Name $SlotName
                $InterfaceDescription = $NetAdapter.InterfaceDescription
                Write-Debug " Interface : $InterfaceDescription"
                Write-Log "INFO: Slot with the name '$SlotName' was found. Its description is: '$InterfaceDescription' "
            }
            else {Write-Debug " Interface : $InterfaceDescription"}
            
        }
        catch {
            if (($error[0].exception -like "*keine MSFT_NetAdapter-Objekte gefunden, bei denen die Name-Eigenschaft gleich "+ '"'+ $slotname +'"'+ " ist*") -or ($error[0].exception -like "No MSFT_NetAdapter objects found with property 'Name' equal to " + "'" + $slotname+ "'")){
                Write-Log "WARNING: No MSFT_NetAdapter objects found with property 'Name' equal to '$slotname'. The script will perform the action on the Interface: '$InterfaceDescription'!!!"
            }
            else{
                Write-Log "ERROR: Unable to check if there is a network adapter with the slot name: '$SlotName' Error: $($error[0])"
                exit
            }
        }
        #region start logging and additional information for the device
        Write-Log " ***********************************************************************************************
        Name of the Machine:            '$($env:COMPUTERNAME)'`
        UserAccount:                    '$($env:USERDOMAIN + "\" + $env:USERNAME)'`
        Architecture:                   '$(if ([system.environment]::Is64BitOperatingSystem){"64-bit"} else {"32-bit"})'`
        NetworkAdapter:                 '$(Get-NetAdapter -InterfaceDescription $InterfaceDescription)'
        ParameterSwitch:                '$(if ($EnableMonitor){"EnableMonitor"} else{"DisableMonitor"})'"
        
        #endregion 

        if ($EnableMonitor){$regvalue='1'}
        if ($DisableMonitor){$regvalue='0'}
        if ($enablevlantag){$regvaluevlan='3'}
        else{$regvaluevlan='0'}
        Write-Debug "RegValue is '$regvalue'"
        Write-Debug "RegValueVlan is '$regvaluevlan'"
        $ProcessValue=0
        try{
            $Net7AP = Get-NetAdapterAdvancedProperty -InterfaceDescription $InterfaceDescription -AllProperties -ErrorAction Stop |? {$_.RegistryKeyword -like 'NetCfgInstanceID' }
            Write-Debug $Net7AP
            Write-Log "INFO: The network device with the Name '$($net7ap.name)' and Description '$InterfaceDescription' was found under the MAC Address '$($Net7AP.RegistryValue)'"
        }
        catch {
            Write-Log "ERROR: Unable to get network adapter advance property and retriev the MAC Address of the card. Error: '$($error[0])'"
            exit
        }
        for($i = 0; $i -le 30; $i++) {
        # you need to double-up the opening and closing curly brackets on the GUID here, otherwise
        # the '-f' formatting operator will error out trying to find the '{0:0000}' to replace..
        $path = $RegKey+"\{0:0000}" -f $i
        #'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{{4D36E972-E325-11CE-BFC1-08002bE10318}}\{0:0000}\NetCfgInstanceID'
            try{
                if (Get-ItemProperty $path -ErrorAction SilentlyContinue  |? {$_.NetCfgInstanceId -like "$($Net7AP.RegistryValue)"})
                {
                    $itemProperty=Get-ItemProperty $path  |? {$_.NetCfgInstanceId -like "$($Net7AP.RegistryValue)"}
                    Write-Debug "$path"
                    Write-DEbug "$itemProperty"
                    Write-Log "Registry Path for: '$path'"
                    break
                }
            }
            
            catch{
                Write-Log "Unable to get item property for the NIC with the MAC Address '$($Net7AP.RegistryValue)' Error: '$($error[0])' "
            }
        }
        try{
            $PriorityVTAG=Get-NetAdapterAdvancedProperty  -RegistryKeyword "*PriorityVLANTag*"  -InterfaceDescription $InterfaceDescription
            Write-Debug "$PriorityVTAG"
            Write-Log "INFO: Priority/VLAN tag in the regkey '$($PriorityVTAG.RegistryKeyword)' is in state: '$($PriorityVTAG.DisplayValue)' and registry value '$($PriorityVTAG.RegistryValue)'"
        }
        catch{
            Write-Log "ERROR:Unable to get Priority/VLAN tag state. Error: '$($error[0])'"
        }
        try{
            $MonitorMode=Get-NetAdapterAdvancedProperty  -RegistryKeyword "MonitorMode*" -AllProperties  -InterfaceDescription $InterfaceDescription
            $MonitorMode | ForEach-Object {Write-Log "INFO: Monitore Mode regstry '$($_.RegistryKeyword)' is in the initial state '$($_.RegistryValue)'"}
            Write-Log "Found MonitoreMode Advanced Property for Monitor Mode with the count of '$($MonitorMode.count)'"
        }
        catch{
            Write-Log "ERROR: Unable to get Monitore Mode status"
        }
    }
    Process
    {
        Write-Log "Process of the main function..."
        #Priority Vlan TAg disable (or enable)   
        try{
            if ($PriorityVTAG.RegistryValue -notlike $regvaluevlan){
                Set-NetAdapterAdvancedProperty -InterfaceDescription $InterfaceDescription -RegistryKeyword ($PriorityVTAG.RegistryKeyword) -RegistryValue $regvaluevlan 
                $ProcessValue++
                Write-Log "INFO: Successfully set PriorityVLANTag to '$regvaluevlan'!"
                $PriorityVTAG=Get-NetAdapterAdvancedProperty  -RegistryKeyword "*PriorityVLANTag*"  -InterfaceDescription $InterfaceDescription
                Write-Debug "$PriorityVTAG"
                Write-Log "INFO: Priority/VLAN tag in the regkey '$($PriorityVTAG.RegistryKeyword)' is in state: '$($PriorityVTAG.DisplayValue)' and registry value '$($PriorityVTAG.RegistryValue)'"
            }
            else{
                Write-Log "INFO: Priority/VLAN tag is already set to the value of '$regvaluevlan'"
            }
           
        }
        catch{
            Write-Log "ERROR: Unable to set NIC advanced property of the PriorityVLANTag to '$regvaluevlan' (Unable to deactivate the vlan tag!) Error: '$($error[0])'"
        }
        
        # In case the monitore mode registry are not created
        if (!$MonitorMode){
            try{
                New-NetAdapterAdvancedProperty  -RegistryKeyword $RegKeyWord1 -RegistryValue $regvalue -RegistryDataType $RegKeyType -InterfaceDescription $InterfaceDescription
                $ProcessValue++
                Write-Log "INFO: Successfully created new NIC advance property with the Name '$RegKeyWord1' and the value '$regvalue' of the type '$RegKeyType'"
                $MonitorMode=Get-NetAdapterAdvancedProperty  -RegistryKeyword "MonitorMode*" -AllProperties  -InterfaceDescription $InterfaceDescription
                $MonitorMode | ForEach-Object {Write-Log "INFO: MonitoreMode regstry '$($_.RegistryKeyword)' is in the state '$($_.RegistryValue)'"}
            }
            catch {
            Write-Log "ERROR: Unable to create new advance property with the RegKeyWord: '$RegKeyWord1' and the value og '$regvalue' : '$($error[0])'"
            }
            try{
                New-NetAdapterAdvancedProperty -InterfaceDescription $InterfaceDescription -RegistryKeyword $RegKeyWord2 -RegistryValue $regvalue -RegistryDataType $RegKeyType
                $ProcessValue++
                Write-Log "INFO: Successfully created new NIC advance property with the Name '$RegKeyWord2' and the value '$regvalue' of the type '$RegKeyType'"

            }
            catch {
                Write-Log "ERROR: Unable to create new advance property with the RegKeyWord: '$RegKeyWord2' and the value og '$regvalue' : '$($error[0])'"
            }
        }
        # In case there are already created
        elseif (($MonitorMode.GetType().basetype.name -like 'array') -and ($MonitorMode.Count -lt 3)){
            foreach ($item in $MonitorMode){
                try{
                    if ($item.RegistryValue -notlike $regvalue){
                        Set-NetAdapterAdvancedProperty -InterfaceDescription $InterfaceDescription -RegistryKeyword ($item.RegistryKeyword) -RegistryValue $regvalue -AllProperties
                        $ProcessValue++
                        Write-Log "INFO: Successfully set NIC advance property with the Name '$($item.RegistryKeyword)' and the value '$regvalue'"
                        Start-Sleep 5
                        $MonitorMode=Get-NetAdapterAdvancedProperty  -RegistryKeyword "MonitorMode*" -AllProperties  -InterfaceDescription $InterfaceDescription
                        $MonitorMode | ForEach-Object {Write-Log "INFO: MonitoreMode regstry '$($_.RegistryKeyword)' now is in the state '$($_.RegistryValue)'"}
                    }
                    else{
                        Write-Log "INFO: MonitoreMode regstry '$($Item.RegistryKeyword)' is already set to the value of '$regvalue'"
                    }
                }
                catch{
                    Write-Log "ERROR: Unable to set advance property with the RegKeyWord: '$($item.RegistryKeyword)' and the value og '$regvalue' : '$($error[0]) '"
                }
            }
        }
        else{
            if (($MonitorMode.RegistryKeyword -like $RegKeyWord1) -and ($MonitorMode.RegistryValue -notlike $regvalue)){
                try{
                    Set-NetAdapterAdvancedProperty  -RegistryKeyword $RegKeyWord1 -RegistryValue $regvalue  -InterfaceDescription $InterfaceDescription -AllProperties
                    $ProcessValue++
                    Write-Log "INFO: Successfully set NIC advance property with the Name '$RegKeyWord1' and the value '$regvalue' of the type '$RegKeyType'"
                    Start-Sleep 5
                    $MonitorMode=Get-NetAdapterAdvancedProperty  -RegistryKeyword "MonitorMode*" -AllProperties  -InterfaceDescription $InterfaceDescription
                    $MonitorMode | ForEach-Object {Write-Log "INFO: MonitoreMode regstry '$($_.RegistryKeyword)' now is in the state '$($_.RegistryValue)'"}
                }
                catch {
                Write-Log "ERROR: Unable to set advance property with the RegKeyWord: '$RegKeyWord1' and the value og '$regvalue' : '$($error[0])'"
                }
            }
            elseif (($MonitorMode.RegistryKeyword -like $RegKeyWord2) -and ($MonitorMode.RegistryValue -notlike $regvalue)){
                try{
                    Set-NetAdapterAdvancedProperty  -RegistryKeyword $RegKeyWord2 -RegistryValue $regvalue  -InterfaceDescription $InterfaceDescription -AllProperties
                    $ProcessValue++
                    Write-Debug "Process Value:'$ProcessValue'"
                    Write-Log "INFO: Successfully created new NIC advance property with the Name '$RegKeyWord2' and the value '$regvalue' of the type '$RegKeyType'"
                    Start-Sleep 5
                    $MonitorMode=Get-NetAdapterAdvancedProperty  -RegistryKeyword "MonitorMode*" -AllProperties  -InterfaceDescription $InterfaceDescription
                    $MonitorMode | ForEach-Object {Write-Log "INFO: MonitoreMode regstry '$($_.RegistryKeyword)' now is in the state '$($_.RegistryValue)'"}
                }
                catch {
                Write-Log "ERROR: Unable to set advance property with the RegKeyWord: '$RegKeyWord2' and the value og '$regvalue' : '$($error[0])'"
                }
            }
            else{
                Write-Log "Warning: No property was changed,'$RegKeyWord1' or '$RegKeyWord2' were already set with the given paramters, please use '-Debug' to investigate`
                 the code and the given parameters or ignore the warning, if the settings are correct!"
            }
        }      
       
    }
    End
    {
        Write-Log "End of the main function..."
        if ($ProcessValue -gt 0){
            Write-Log "Successfully finished '$ProcessValue' of 3 tasks`
            !!!!!You must reboot the computer to complete the action!!!!!
            "
            $EventSourceName = "HAJVlanTags"
            if ([System.Diagnostics.EventLog]::SourceExists($EventSourceName) -eq $false) {
                Write-Debug "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Creating event source [$EventSourceName] on event log [Application]"
                Write-Log "Creating event source [$EventSourceName] on event log [Application]" 
                [System.Diagnostics.EventLog]::CreateEventSource("$EventSourceName",'Application')
            } 
            else { 
                Write-Log "Event source [$EventSourceName] is already registered"
                 
            }
            try {
                Write-EventLog -LogName "Application" -Source $EventSourceName -EventID 6660 -EntryType Warning -Message "Successfully finished '$ProcessValue' of 3 tasks of disabling Priority & VLAN Tags and creating MonitoreMode Registries,`
                for more information please check the log under $LogsFolder!" -Category 1 
                Write-log "Event Log $EventSourceName  was created"
            } 
            catch {
                Write-Log "ERROR: Unable to create event: [$EventSourceName] ERROR: $($Error[0])" 
            }
            #Write-Debug "Countdown started..."
            #Start-Countdown -seconds 60
            #Write-Debug "ProcessValue is '$($ProcessValue.count)'"
            #Write-Debug "Countdown finished..."
        }
    }
}
#endregion
Disable-VLANTag -InterfaceDescription $InterfaceDescription -RegKey $RegKey -RegKeyWord1 $RegKeyWord1 -RegKeyWord2 $RegKeyWord2 -RegKeyType $RegKeyType -SlotName $SlotName -EnableMonitor 