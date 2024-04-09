Function Redo-LTService{
    <#
    .SYNOPSIS
        This function will reinstall the LabTech agent from the machine.
    
    .DESCRIPTION
        This script will attempt to pull all current settings from machine and issue an 'Uninstall-LTService', 'Install-LTService' with gathered information.
        If the function is unable to find the settings it will ask for needed parameters.
    
    .PARAMETER Server
        This is the URL to your LabTech server.
        Example: https://lt.domain.com
        This is used to download the installation and removal utilities.
        If no server is provided the uninstaller will use Get-LTServiceInfo to get the server address.
        If it is unable to find LT currently installed it will try Get-LTServiceInfoBackup
    
    .PARAMETER ServerPassword
        This is the Server Password to your LabTech server.
        SELECT SystemPassword FROM config;
    
    .PARAMETER InstallerToken
        Permits use of installer tokens for customized MSI downloads. (Other installer types are not supported)
    
    .PARAMETER LocationID
        The LocationID of the location that you want the agent in
        example: 555
    
    .PARAMETER Backup
        This will run a New-LTServiceBackup command before uninstalling.
    
    .PARAMETER Hide
        Will remove from add-remove programs
    
    .PARAMETER Rename
        This will call Rename-LTAddRemove to rename the install in Add/Remove Programs
    
    .PARAMETER SkipDotNet
        This will disable the error checking for the .NET 3.5 and .NET 2.0 frameworks during the install process.
    
    .PARAMETER Force
        This will force operation on an agent detected as a probe.
    
    .EXAMPLE
        Redo-LTService
        This will ReInstall the LabTech agent using the server address in the registry.
    
    .EXAMPLE
        Redo-LTService -Server https://lt.domain.com -Password sQWZzEDYKFFnTT0yP56vgA== -LocationID 42
        This will ReInstall the LabTech agent using the provided server URL to download the installation files.
    #>
        [CmdletBinding(SupportsShouldProcess=$True,DefaultParameterSetName = 'deployment')]
        Param(
            [Parameter(ParameterSetName = 'deployment')]
            [Parameter(ParameterSetName = 'installertoken')]
            [Parameter(ValueFromPipelineByPropertyName = $True, ValueFromPipeline=$True)]
            [AllowNull()]
            [string[]]$Server,
            [Parameter(ParameterSetName = 'deployment')]
            [Parameter(ValueFromPipelineByPropertyName = $True, ValueFromPipeline=$True)]
            [Alias("Password")]
            [string]$ServerPassword,
            [Parameter(ParameterSetName = 'installertoken')]
            [ValidatePattern('(?s:^[0-9a-z]+$)')]
            [string]$InstallerToken,
            [Parameter(ValueFromPipelineByPropertyName = $True)]
            [AllowNull()]
            [string]$LocationID,
            [switch]$Backup,
            [switch]$Hide,
            [Parameter()]
            [AllowNull()]
            [string]$Rename,
            [switch]$SkipDotNet,
            [switch]$Force
        )
    
        Begin{
            Clear-Variable PasswordArg, RenameArg, Svr, ServerList, Settings -EA 0 -WhatIf:$False -Confirm:$False #Clearing Variables for use
            Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)"
    
            # Gather install stats from registry or backed up settings
            Try {
                $Settings = Get-LTServiceInfo -EA 0 -Verbose:$False -WhatIf:$False -Confirm:$False
                If ($Null -ne $Settings) {
                    If (($Settings|Select-Object -Expand Probe -EA 0) -eq '1') {
                        If ($Force -eq $True) {
                            Write-Output "Probe Agent Detected. Re-Install Forced."
                        } Else {
                            If ($WhatIfPreference -ne $True) {
                                Write-Error -Exception [System.OperationCanceledException]"ERROR: Line $(LINENUM): Probe Agent Detected. Re-Install Denied." -ErrorAction Stop
                            } Else {
                                Write-Error -Exception [System.OperationCanceledException]"What If: Line $(LINENUM): Probe Agent Detected. Re-Install Denied." -ErrorAction Stop
                            }#End If
                        }#End If
                    }#End If
                }#End If
            } Catch {
                Write-Debug "Line $(LINENUM): Failed to retrieve current Agent Settings."
            }#End Catch
            If ($Null -eq $Settings) {
                Write-Debug "Line $(LINENUM): Unable to retrieve current Agent Settings. Testing for Backup Settings"
                Try {
                    $Settings = Get-LTServiceInfoBackup -EA 0
                } Catch {}
            }
            $ServerList=@()
        }#End Begin
    
        Process{
            if (-not ($Server)){
                if ($Settings){
                    $Server = $Settings|Select-Object -Expand 'Server' -EA 0
                }
                if (-not ($Server)){
                    $Server = Read-Host -Prompt 'Provide the URL to your LabTech server (https://lt.domain.com):'
                }
            }
            if (-not ($LocationID)){
                if ($Settings){
                    $LocationID = $Settings|Select-Object -Expand LocationID -EA 0
                }
                if (-not ($LocationID)){
                    $LocationID = Read-Host -Prompt 'Provide the LocationID'
                }
            }
            if (-not ($LocationID)){
                $LocationID = "1"
            }
            $ServerList += $Server
        }#End Process
    
        End{
            If ($Backup){
                If ( $PSCmdlet.ShouldProcess("LTService","Backup Current Service Settings") ) {
                    New-LTServiceBackup
                }#End If
            }#End If
    
            $RenameArg=''
            If ($Rename){
                $RenameArg = "-Rename $Rename"
            }
    
            If ($PSCmdlet.ParameterSetName -eq 'installertoken') {
                $PasswordPresent = "-InstallerToken 'REDACTED'"
            } ElseIf (($ServerPassword)){
                $PasswordPresent = "-Password 'REDACTED'"
            }
    
            Write-Output "Reinstalling LabTech with the following information, -Server $($ServerList -join ',') $PasswordPresent -LocationID $LocationID $RenameArg"
            Write-Verbose "Starting: Uninstall-LTService -Server $($ServerList -join ',')"
            Try{
                Uninstall-LTService -Server $ServerList -ErrorAction Stop -Force
            }#End Try
    
            Catch{
                Write-Error "ERROR: Line $(LINENUM): There was an error during the reinstall process while uninstalling. $($Error[0])" -ErrorAction Stop
            }#End Catch
    
            Finally{
                If ($WhatIfPreference -ne $True) {
                    Write-Verbose "Waiting 20 seconds for prior uninstall to settle before starting Install."
                    Start-Sleep 20
                }
            }
    
            Write-Verbose "Starting: Install-LTService -Server $($ServerList -join ',') $PasswordPresent -LocationID $LocationID -Hide:`$$($Hide) $RenameArg"
            Try{
                If ($PSCmdlet.ParameterSetName -ne 'installertoken') {
                    Install-LTService -Server $ServerList -ServerPassword $ServerPassword -LocationID $LocationID -Hide:$Hide -Rename $Rename -SkipDotNet:$SkipDotNet -Force
                } Else {
                    Install-LTService -Server $ServerList -InstallerToken $InstallerToken -LocationID $LocationID -Hide:$Hide -Rename $Rename -SkipDotNet:$SkipDotNet -Force
                }
            }#End Try
    
            Catch{
                Write-Error "ERROR: Line $(LINENUM): There was an error during the reinstall process while installing. $($Error[0])" -ErrorAction Stop
            }#End Catch
    
            If (!($?)){
                $($Error[0])
            }#End If
            Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)"
        }#End End
    }#End Function Redo-LTService
    Set-Alias -Name ReInstall-LTService -Value Redo-LTService

    Function Uninstall-LTService{
        <#
        .SYNOPSIS
            This function will uninstall the LabTech agent from the machine.
        
        .DESCRIPTION
            This function will stop all the LabTech services. It will then download the current agent install MSI and issue an uninstall command.
            It will then download and run Agent_Uninstall.exe from the LabTech server. It will then scrub any remaining file/registry/service data.
        
        .PARAMETER Server
            This is the URL to your LabTech server.
            Example: https://lt.domain.com
            This is used to download the uninstall utilities.
            If no server is provided the uninstaller will use Get-LTServiceInfo to get the server address.
        
        .PARAMETER Backup
            This will run a 'New-LTServiceBackup' before uninstalling.
        
        .PARAMETER Force
            This will force operation on an agent detected as a probe.
        
        .EXAMPLE
            Uninstall-LTService
            This will uninstall the LabTech agent using the server address in the registry.
        
        .EXAMPLE
            Uninstall-LTService -Server 'https://lt.domain.com'
            This will uninstall the LabTech agent using the provided server URL to download the uninstallers.
        #>
            [CmdletBinding(SupportsShouldProcess=$True)]
            Param(
                [Parameter(ValueFromPipelineByPropertyName = $true)]
                [AllowNull()]
                [string[]]$Server,
                [Parameter(ValueFromPipelineByPropertyName = $true)]
                [switch]$Backup,
                [switch]$Force
            )
        
            Begin{
                Clear-Variable Executables,BasePath,reg,regs,installer,installerTest,installerResult,LTSI,uninstaller,uninstallerTest,uninstallerResult,xarg,Svr,SVer,SvrVer,SvrVerCheck,GoodServer,AlternateServer,Item -EA 0 -WhatIf:$False -Confirm:$False #Clearing Variables for use
                Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)"
        
                If (-not ([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()|Select-Object -Expand groups -EA 0) -match 'S-1-5-32-544'))) {
                    Throw "Line $(LINENUM): Needs to be ran as Administrator"
                }
        
                $LTSI = Get-LTServiceInfo -EA 0 -Verbose:$False -WhatIf:$False -Confirm:$False -Debug:$False
                If (($LTSI) -and ($LTSI|Select-Object -Expand Probe -EA 0) -eq '1') {
                    If ($Force -eq $True) {
                        Write-Output "Probe Agent Detected. UnInstall Forced."
                    } Else {
                        Write-Error -Exception [System.OperationCanceledException]"Line $(LINENUM): Probe Agent Detected. UnInstall Denied." -ErrorAction Stop
                    }#End If
                }#End If
        
                If ($Backup){
                    If ( $PSCmdlet.ShouldProcess("LTService","Backup Current Service Settings") ) {
                        New-LTServiceBackup
                    }#End If
                }#End If
        
                $BasePath = $(Get-LTServiceInfo -EA 0 -Verbose:$False -WhatIf:$False -Confirm:$False -Debug:$False|Select-Object -Expand BasePath -EA 0)
                If (-not ($BasePath)) {$BasePath = "${env:windir}\LTSVC"}
                $UninstallBase="${env:windir}\Temp"
                $UninstallEXE='Agent_Uninstall.exe'
                $UninstallMSI='RemoteAgent.msi'
        
                New-PSDrive HKU Registry HKEY_USERS -ErrorAction SilentlyContinue -WhatIf:$False -Confirm:$False -Debug:$False| Out-Null
                $regs = @( 'Registry::HKEY_LOCAL_MACHINE\Software\LabTechMSP',
                    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\LabTech\Service',
                    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\LabTech\LabVNC',
                    'Registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node\LabTech\Service',
                    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Products\D1003A85576B76D45A1AF09A0FC87FAC',
                    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Products\D1003A85576B76D45A1AF09A0FC87FAC',
                    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Managed\\Installer\Products\C4D064F3712D4B64086B5BDE05DBC75F',
                    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\D1003A85576B76D45A1AF09A0FC87FAC\InstallProperties',
                    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{58A3001D-B675-4D67-A5A1-0FA9F08CF7CA}',
                    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{3426921d-9ad5-4237-9145-f15dee7e3004}',
                    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Appmgmt\{40bf8c82-ed0d-4f66-b73e-58a3d7ab6582}',
                    'Registry::HKEY_CLASSES_ROOT\Installer\Dependencies\{3426921d-9ad5-4237-9145-f15dee7e3004}',
                    'Registry::HKEY_CLASSES_ROOT\Installer\Dependencies\{3F460D4C-D217-46B4-80B6-B5ED50BD7CF5}',
                    'Registry::HKEY_CLASSES_ROOT\Installer\Products\C4D064F3712D4B64086B5BDE05DBC75F',
                    'Registry::HKEY_CLASSES_ROOT\Installer\Products\D1003A85576B76D45A1AF09A0FC87FAC',
                    'Registry::HKEY_CLASSES_ROOT\CLSID\{09DF1DCA-C076-498A-8370-AD6F878B6C6A}',
                    'Registry::HKEY_CLASSES_ROOT\CLSID\{15DD3BF6-5A11-4407-8399-A19AC10C65D0}',
                    'Registry::HKEY_CLASSES_ROOT\CLSID\{3C198C98-0E27-40E4-972C-FDC656EC30D7}',
                    'Registry::HKEY_CLASSES_ROOT\CLSID\{459C65ED-AA9C-4CF1-9A24-7685505F919A}',
                    'Registry::HKEY_CLASSES_ROOT\CLSID\{7BE3886B-0C12-4D87-AC0B-09A5CE4E6BD6}',
                    'Registry::HKEY_CLASSES_ROOT\CLSID\{7E092B5C-795B-46BC-886A-DFFBBBC9A117}',
                    'Registry::HKEY_CLASSES_ROOT\CLSID\{9D101D9C-18CC-4E78-8D78-389E48478FCA}',
                    'Registry::HKEY_CLASSES_ROOT\CLSID\{B0B8CDD6-8AAA-4426-82E9-9455140124A1}',
                    'Registry::HKEY_CLASSES_ROOT\CLSID\{B1B00A43-7A54-4A0F-B35D-B4334811FAA4}',
                    'Registry::HKEY_CLASSES_ROOT\CLSID\{BBC521C8-2792-43FE-9C91-CCA7E8ACBCC9}',
                    'Registry::HKEY_CLASSES_ROOT\CLSID\{C59A1D54-8CD7-4795-AEDD-F6F6E2DE1FE7}',
                    'Registry::HKEY_CLASSES_ROOT\Installer\Products\C4D064F3712D4B64086B5BDE05DBC75F',
                    'Registry::HKEY_CLASSES_ROOT\Installer\Products\D1003A85576B76D45A1AF09A0FC87FAC',
                    'Registry::HKEY_CURRENT_USER\SOFTWARE\LabTech\Service',
                    'Registry::HKEY_CURRENT_USER\SOFTWARE\LabTech\LabVNC',
                    'Registry::HKEY_CURRENT_USER\Software\Microsoft\Installer\Products\C4D064F3712D4B64086B5BDE05DBC75F',
                    'HKU:\*\Software\Microsoft\Installer\Products\C4D064F3712D4B64086B5BDE05DBC75F'
                )
        
                $xarg = "/x ""$UninstallBase\$UninstallMSI"" /qn"
            }#End Begin
        
            Process{
                If (-not ($Server)){
                    $Server = Get-LTServiceInfo -EA 0 -Verbose:$False -WhatIf:$False -Confirm:$False -Debug:$False|Select-Object -Expand 'Server' -EA 0
                }
                If (-not ($Server)){
                    $Server = Read-Host -Prompt 'Provide the URL to your LabTech server (https://lt.domain.com)'
                }
                If (-not ($Server)){
                    #Download $UninstallEXE
                    $AlternateServer=$Null
                    $uninstaller='https://s3.amazonaws.com/assets-cp/assets/Agent_Uninstall.exe'
                    If ($PSCmdlet.ShouldProcess("$uninstaller", "DownloadFile")) {
                        Write-Debug "Line $(LINENUM): Downloading $UninstallEXE from $uninstaller"
                        $Script:LTServiceNetWebClient.DownloadFile($uninstaller,"$UninstallBase\$UninstallEXE")
                        If ((Test-Path "$UninstallBase\$UninstallEXE")) {
                            If(((Get-Item "$UninstallBase\$UninstallEXE" -EA 0).length/1KB -gt 80)) {
                                $AlternateServer='https://s3.amazonaws.com'
                            } Else {
                                Write-Warning "Line $(LINENUM): $UninstallEXE size is below normal. Removing suspected corrupt file."
                                Remove-Item "$UninstallBase\$UninstallEXE" -ErrorAction SilentlyContinue -Force -Confirm:$False   
                            }#End If
                        }#End If
                    }#End If
                }
                $Server=ForEach ($Svr in $Server) {If (($Svr)) {If ($Svr -notmatch 'https?://.+') {"https://$($Svr)"}; $Svr}}
                ForEach ($Svr in $Server) {
                    If (-not ($GoodServer)) {
                        If ($Svr -match '^(https?://)?(([12]?[0-9]{1,2}\.){3}[12]?[0-9]{1,2}|[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)*)$') {
                            Try{
                                If ($Svr -notmatch 'https?://.+') {$Svr = "http://$($Svr)"}
                                $SvrVerCheck = "$($Svr)/LabTech/Agent.aspx"
                                Write-Debug "Line $(LINENUM): Testing Server Response and Version: $SvrVerCheck"
                                $SvrVer = $Script:LTServiceNetWebClient.DownloadString($SvrVerCheck)
        
                                Write-Debug "Line $(LINENUM): Raw Response: $SvrVer"
                                $SVer = $SvrVer|select-string -pattern '(?<=[|]{6})[0-9]{1,3}\.[0-9]{1,3}'|ForEach-Object {$_.matches}|Select-Object -Expand value -EA 0
                                If ($Null -eq ($SVer)) {
                                    Write-Verbose "Unable to test version response from $($Svr)."
                                    Continue
                                }
                                $installer = "$($Svr)/LabTech/Service/LabTechRemoteAgent.msi"
                                $installerTest = [System.Net.WebRequest]::Create($installer)
                                If (($Script:LTProxy.Enabled) -eq $True) {
                                    Write-Debug "Line $(LINENUM): Proxy Configuration Needed. Applying Proxy Settings to request."
                                    $installerTest.Proxy=$Script:LTWebProxy
                                }#End If
                                $installerTest.KeepAlive=$False
                                $installerTest.ProtocolVersion = '1.0'
                                $installerResult = $installerTest.GetResponse()
                                $installerTest.Abort()
                                If ($installerResult.StatusCode -ne 200) {
                                    Write-Warning "WARNING: Line $(LINENUM): Unable to download $UninstallMSI from server $($Svr)."
                                    Continue
                                }
                                Else {
                                    If ($PSCmdlet.ShouldProcess("$installer", "DownloadFile")) {
                                        Write-Debug "Line $(LINENUM): Downloading $UninstallMSI from $installer"
                                        $Script:LTServiceNetWebClient.DownloadFile($installer,"$UninstallBase\$UninstallMSI")
                                        If ((Test-Path "$UninstallBase\$UninstallMSI")) {
                                            If (!((Get-Item "$UninstallBase\$UninstallMSI" -EA 0).length/1KB -gt 1234)) {
                                                Write-Warning "WARNING: Line $(LINENUM): $UninstallMSI size is below normal. Removing suspected corrupt file."
                                                Remove-Item "$UninstallBase\$UninstallMSI" -ErrorAction SilentlyContinue -Force -Confirm:$False
                                                Continue
                                            } Else {
                                                $AlternateServer = $Svr
                                            }#End If
                                        }#End If
                                    }#End If
                                }#End If
        
                                #Using $SVer results gathered above.
                                If ([System.Version]$SVer -ge [System.Version]'110.374') {
                                    #New Style Download Link starting with LT11 Patch 13 - The Agent Uninstaller URI has changed.
                                    $uninstaller = "$($Svr)/LabTech/Service/LabUninstall.exe"
                                } Else {
                                    #Original Uninstaller URL
                                    $uninstaller = "$($Svr)/LabTech/Service/LabUninstall.exe"
                                }
                                $uninstallerTest = [System.Net.WebRequest]::Create($uninstaller)
                                If (($Script:LTProxy.Enabled) -eq $True) {
                                    Write-Debug "Line $(LINENUM): Proxy Configuration Needed. Applying Proxy Settings to request."
                                    $uninstallerTest.Proxy=$Script:LTWebProxy
                                }#End If
                                $uninstallerTest.KeepAlive=$False
                                $uninstallerTest.ProtocolVersion = '1.0'
                                $uninstallerResult = $uninstallerTest.GetResponse()
                                $uninstallerTest.Abort()
                                If ($uninstallerResult.StatusCode -ne 200) {
                                    Write-Warning "WARNING: Line $(LINENUM): Unable to download Agent_Uninstall from server."
                                    Continue
                                } Else {
                                    #Download $UninstallEXE
                                    If ($PSCmdlet.ShouldProcess("$uninstaller", "DownloadFile")) {
                                        Write-Debug "Line $(LINENUM): Downloading $UninstallEXE from $uninstaller"
                                        $Script:LTServiceNetWebClient.DownloadFile($uninstaller,"$UninstallBase\$UninstallEXE")
                                        If ((Test-Path "$UninstallBase\$UninstallEXE") -and !((Get-Item "$UninstallBase\$UninstallEXE" -EA 0).length/1KB -gt 80)) {
                                            Write-Warning "WARNING: Line $(LINENUM): $UninstallEXE size is below normal. Removing suspected corrupt file."
                                            Remove-Item "$UninstallBase\$UninstallEXE" -ErrorAction SilentlyContinue -Force -Confirm:$False
                                            Continue
                                        }#End If
                                    }#End If
                                }#End If
                                If ($WhatIfPreference -eq $True) {
                                    $GoodServer = $Svr
                                } ElseIf ((Test-Path "$UninstallBase\$UninstallMSI") -and (Test-Path "$UninstallBase\$UninstallEXE")) {
                                    $GoodServer = $Svr
                                    Write-Verbose "Successfully downloaded files from $($Svr)."
                                } Else {
                                    Write-Warning "WARNING: Line $(LINENUM): Error encountered downloading from $($Svr). Uninstall file(s) could not be received."
                                    Continue
                                }#End If
                            }#End Try
                            Catch {
                                Write-Warning "WARNING: Line $(LINENUM): Error encountered downloading from $($Svr)."
                                Continue
                            }
                        } ElseIf ($Svr) {
                            Write-Verbose "Server address $($Svr) is not formatted correctly. Example: https://lt.domain.com"
                        }#End If
                    } Else {
                        Write-Debug "Line $(LINENUM): Server $($GoodServer) has been selected."
                        Write-Verbose "Server has already been selected - Skipping $($Svr)."
                    }#End If
                }#End Foreach
            }#End Process
        
            End{
                If ($GoodServer -match 'https?://.+' -or $AlternateServer -match 'https?://.+') {
                    Try{
                        Write-Output "Starting Uninstall."
        
                        Try { Stop-LTService -ErrorAction SilentlyContinue } Catch {}
        
                        #Kill all running processes from %ltsvcdir%
                        If (Test-Path $BasePath){
                            $Executables = (Get-ChildItem $BasePath -Filter *.exe -Recurse -ErrorAction SilentlyContinue|Select-Object -Expand FullName)
                            If ($Executables) {
                                Write-Verbose "Terminating LabTech Processes from $($BasePath) if found running: $(($Executables) -replace [Regex]::Escape($BasePath),'' -replace '^\\','')"
                                Get-Process | Where-Object {$Executables -contains $_.Path } | ForEach-Object {
                                    Write-Debug "Line $(LINENUM): Terminating Process $($_.ProcessName)"
                                    $($_) | Stop-Process -Force -ErrorAction SilentlyContinue
                                }
                                Get-ChildItem $BasePath -Filter labvnc.exe -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction 0
                            }#End If
        
                            If ($PSCmdlet.ShouldProcess("$($BasePath)\wodVPN.dll", "Unregister DLL")) {
                                #Unregister DLL
                                Write-Debug "Line $(LINENUM): Executing Command ""regsvr32.exe /u $($BasePath)\wodVPN.dll /s"""
                                Try {& "${env:windir}\system32\regsvr32.exe" /u "$($BasePath)\wodVPN.dll" /s 2>''}
                                Catch {Write-Output "Error calling regsvr32.exe."}
                            }#End If
                        }#End If
        
                        If ($PSCmdlet.ShouldProcess("msiexec.exe $($xarg)", "Execute MSI Uninstall")) {
                            If ((Test-Path "$UninstallBase\$UninstallMSI")) {
                                #Run MSI uninstaller for current installation
                                Write-Verbose "Launching MSI Uninstall."
                                Write-Debug "Line $(LINENUM): Executing Command ""msiexec.exe $($xarg)"""
                                Start-Process -Wait -FilePath "${env:windir}\system32\msiexec.exe" -ArgumentList $xarg -WorkingDirectory $UninstallBase
                                Start-Sleep -Seconds 5
                            } Else {
                                Write-Verbose "WARNING: $UninstallBase\$UninstallMSI was not found."
                            }
                        }#End If
        
                        If ($PSCmdlet.ShouldProcess("$UninstallBase\$UninstallEXE", "Execute Agent Uninstall")) {
                            If ((Test-Path "$UninstallBase\$UninstallEXE")) {
                                #Run $UninstallEXE
                                Write-Verbose "Launching Agent Uninstaller"
                                Write-Debug "Line $(LINENUM): Executing Command ""$UninstallBase\$UninstallEXE"""
                                Start-Process -Wait -FilePath "$UninstallBase\$UninstallEXE" -WorkingDirectory $UninstallBase
                                Start-Sleep -Seconds 5
                            } Else {
                                Write-Verbose "WARNING: $UninstallBase\$UninstallEXE was not found."
                            }
                        }#End If
        
                        Write-Verbose "Removing Services if found."
                        #Remove Services
                        @('LTService','LTSvcMon','LabVNC') | ForEach-Object {
                            If (Get-Service $_ -EA 0) {
                                If ( $PSCmdlet.ShouldProcess("$($_)","Remove Service") ) {
                                    Write-Debug "Line $(LINENUM): Removing Service: $($_)"
                                    Try {& "${env:windir}\system32\sc.exe" delete "$($_)" 2>''}
                                    Catch {Write-Output "Error calling sc.exe."}
                                }#End If
                            }#End If
                        }#End ForEach-Object
        
                        Write-Verbose "Cleaning Files remaining if found."
                        #Remove %ltsvcdir% - Depth First Removal, First by purging files, then Removing Folders, to get as much removed as possible if complete removal fails
                        @($BasePath, "${env:windir}\temp\_ltupdate", "${env:windir}\temp\_ltupdate") | foreach-object {
                            If ((Test-Path "$($_)" -EA 0)) {
                                If ( $PSCmdlet.ShouldProcess("$($_)","Remove Folder") ) {
                                    Write-Debug "Line $(LINENUM): Removing Folder: $($_)"
                                    Try {
                                        Get-ChildItem -Path $_ -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { ($_.psiscontainer) } | foreach-object { Get-ChildItem -Path "$($_.FullName)" -EA 0 | Where-Object { -not ($_.psiscontainer) } | Remove-Item -Force -ErrorAction SilentlyContinue -Confirm:$False -WhatIf:$False }
                                        Get-ChildItem -Path $_ -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { ($_.psiscontainer) } | Sort-Object { $_.fullname.length } -Descending | Remove-Item -Force -ErrorAction SilentlyContinue -Recurse -Confirm:$False -WhatIf:$False
                                        Remove-Item -Recurse -Force -Path $_ -ErrorAction SilentlyContinue -Confirm:$False -WhatIf:$False
                                    } Catch {}
                                }#End If
                            }#End If
                        }#End Foreach-Object
        
                        Write-Verbose "Cleaning Registry Keys if found."
                        #Remove all registry keys - Depth First Value Removal, then Key Removal, to get as much removed as possible if complete removal fails
                        Foreach ($reg in $regs) {
                            If ((Test-Path "$($reg)" -EA 0)) {
                                Write-Debug "Line $(LINENUM): Found Registry Key: $($reg)"
                                If ( $PSCmdlet.ShouldProcess("$($Reg)","Remove Registry Key") ) {
                                    Try {
                                        Get-ChildItem -Path $reg -Recurse -Force -ErrorAction SilentlyContinue | Sort-Object { $_.name.length } -Descending | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -Confirm:$False -WhatIf:$False
                                        Remove-Item -Recurse -Force -Path $reg -ErrorAction SilentlyContinue -Confirm:$False -WhatIf:$False
                                    } Catch {}
                                }#End If
                            }#End If
                        }#End Foreach
                    }#End Try
        
                    Catch{
                        Write-Error "ERROR: Line $(LINENUM): There was an error during the uninstall process. $($Error[0])" -ErrorAction Stop
                    }#End Catch
        
                    If ($WhatIfPreference -ne $True) {
                        If ($?){
                            #Post Uninstall Check
                            If((Test-Path "${env:windir}\ltsvc") -or (Test-Path "${env:windir}\temp\_ltupdate") -or (Test-Path registry::HKLM\Software\LabTech\Service) -or (Test-Path registry::HKLM\Software\WOW6432Node\Labtech\Service)){
                                Start-Sleep -Seconds 10
                            }#End If
                            If((Test-Path "${env:windir}\ltsvc") -or (Test-Path "${env:windir}\temp\_ltupdate") -or (Test-Path registry::HKLM\Software\LabTech\Service) -or (Test-Path registry::HKLM\Software\WOW6432Node\Labtech\Service)){
                                Write-Error "ERROR: Line $(LINENUM): Remnants of previous install still detected after uninstall attempt. Please reboot and try again."
                            } Else {
                                Write-Output "LabTech has been successfully uninstalled."
                            }#End If
                        } Else {
                            $($Error[0])
                        }#End If
                    }#End If
                } ElseIf ($WhatIfPreference -ne $True) {
                    Write-Error "ERROR: Line $(LINENUM): No valid server was reached to use for the uninstall." -ErrorAction Stop
                }#End If
        
                If ($WhatIfPreference -ne $True) {
                    #Cleanup uninstall files
                    Remove-Item "$UninstallBase\$UninstallEXE","$UninstallBase\$UninstallMSI" -ErrorAction SilentlyContinue -Force -Confirm:$False
                }#End If
        
                Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)"
            }#End End
        }#End Function Uninstall-LTService

        Function Get-LTServiceInfo{
            <#
            .SYNOPSIS
                This function will pull all of the registry data into an object.
            #>
                [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact='Low')]
                Param ()
            
                Begin{
                    Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)"
                    Clear-Variable key,BasePath,exclude,Servers -EA 0 -WhatIf:$False -Confirm:$False #Clearing Variables for use
                    $exclude = "PSParentPath","PSChildName","PSDrive","PSProvider","PSPath"
                    $key = $Null
                }#End Begin
            
                Process{
                    If ((Test-Path 'HKLM:\SOFTWARE\LabTech\Service') -eq $False){
                        Write-Error "ERROR: Line $(LINENUM): Unable to find information on LTSvc. Make sure the agent is installed."
                        Return $Null
                    }#End If
            
                    If ($PSCmdlet.ShouldProcess("LTService", "Retrieving Service Registry Values")) {
                        Write-Verbose "Checking for LT Service registry keys."
                        Try{
                            $key = Get-ItemProperty 'HKLM:\SOFTWARE\LabTech\Service' -ErrorAction Stop | Select-Object * -exclude $exclude
                            If ($Null -ne $key -and -not ($key|Get-Member -EA 0|Where-Object {$_.Name -match 'BasePath'})) {
                                If ((Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LTService') -eq $True) {
                                    Try {
                                        $BasePath = Get-Item $( Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LTService' -ErrorAction Stop|Select-Object -Expand ImagePath | Select-String -Pattern '^[^"][^ ]+|(?<=^")[^"]+'|Select-Object -Expand Matches -First 1 | Select-Object -Expand Value -EA 0 -First 1 ) | Select-Object -Expand DirectoryName -EA 0
                                    } Catch {
                                        $BasePath = "${env:windir}\LTSVC"
                                    }#End Try
                                } Else {
                                    $BasePath = "${env:windir}\LTSVC"
                                }#End If
                                Add-Member -InputObject $key -MemberType NoteProperty -Name BasePath -Value $BasePath
                            }#End If
                            $key.BasePath = [System.Environment]::ExpandEnvironmentVariables($($key|Select-Object -Expand BasePath -EA 0)) -replace '\\\\','\'
                            If ($Null -ne $key -and ($key|Get-Member|Where-Object {$_.Name -match 'Server Address'})) {
                                $Servers = ($Key|Select-Object -Expand 'Server Address' -EA 0).Split('|')|ForEach-Object {$_.Trim() -replace '~',''}|Where-Object {$_ -match '.+'}
                                Add-Member -InputObject $key -MemberType NoteProperty -Name 'Server' -Value $Servers -Force
                            }#End If
                        }#End Try
            
                        Catch{
                            Write-Error "ERROR: Line $(LINENUM): There was a problem reading the registry keys. $($Error[0])"
                        }#End Catch
                    }#End If
                }#End Process
            
                End{
                    If ($?){
                        Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)"
                        return $key
                    } Else {
                        Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)"
                    }#End If
                }#End End
            }#End Function Get-LTServiceInfo

            Function Restart-LTService{
                <#
                .SYNOPSIS
                    This function will restart the LabTech Services.
                #>
                    [CmdletBinding(SupportsShouldProcess=$True)]
                    Param()
                
                    Begin{
                        Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)"
                    }#End Begin
                
                    Process{
                        if (-not (Get-Service 'LTService','LTSvcMon' -ErrorAction SilentlyContinue)) {
                            If ($WhatIfPreference -ne $True) {
                                Write-Error "ERROR: Line $(LINENUM): Services NOT Found $($Error[0])"
                                return
                            } Else {
                                Write-Error "What-If: Line $(LINENUM): Stopping: Services NOT Found"
                                return
                            }#End If
                        }#End IF
                        Try{
                            Stop-LTService
                        }#End Try
                        Catch{
                            Write-Error "ERROR: Line $(LINENUM): There was an error stopping the services. $($Error[0])"
                            return
                        }#End Catch
                
                        Try{
                            Start-LTService
                        }#End Try
                        Catch{
                            Write-Error "ERROR: Line $(LINENUM): There was an error starting the services. $($Error[0])"
                            return
                        }#End Catch
                    }#End Process
                
                    End{
                        If ($WhatIfPreference -ne $True) {
                            If ($?) {Write-Output "Services Restarted successfully."}
                            Else {$Error[0]}
                        }#End If
                        Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)"
                    }#End End
                }#End Function Restart-LTService
                
                Function Stop-LTService{
                <#
                .SYNOPSIS
                    This function will stop the LabTech Services.
                
                .DESCRIPTION
                    This function will verify that the LabTech services are present then attempt to stop them.
                    It will then check for any remaining LabTech processes and kill them.
                #>
                    [CmdletBinding(SupportsShouldProcess=$True)]
                    Param()
                
                    Begin{
                        Clear-Variable sw,timeout,svcRun -EA 0 -WhatIf:$False -Confirm:$False -Verbose:$False #Clearing Variables for use
                        Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)"
                    }#End Begin
                
                    Process{
                        if (-not (Get-Service 'LTService','LTSvcMon' -ErrorAction SilentlyContinue)) {
                            If ($WhatIfPreference -ne $True) {
                                Write-Error "ERROR: Line $(LINENUM): Services NOT Found $($Error[0])"
                                return
                            } Else {
                                Write-Error "What If: Line $(LINENUM): Stopping: Services NOT Found"
                                return
                            }#End If
                        }#End If
                        If ($PSCmdlet.ShouldProcess("LTService, LTSvcMon", "Stop-Service")) {
                            $Null=Invoke-LTServiceCommand ('Kill VNC','Kill Trays') -EA 0 -WhatIf:$False -Confirm:$False
                            Write-Verbose "Stopping Labtech Services"
                            Try{
                                ('LTService','LTSvcMon') | Foreach-Object {
                                    Try {$Null=& "${env:windir}\system32\sc.exe" stop "$($_)" 2>''}
                                    Catch {Write-Output "Error calling sc.exe."}
                                }
                                $timeout = new-timespan -Minutes 1
                                $sw = [diagnostics.stopwatch]::StartNew()
                                Write-Host -NoNewline "Waiting for Services to Stop."
                                Do {
                                    Write-Host -NoNewline '.'
                                    Start-Sleep 2
                                    $svcRun = ('LTService','LTSvcMon') | Get-Service -EA 0 | Where-Object {$_.Status -ne 'Stopped'} | Measure-Object | Select-Object -Expand Count
                                } Until ($sw.elapsed -gt $timeout -or $svcRun -eq 0)
                                Write-Host ""
                                $sw.Stop()
                                if ($svcRun -gt 0) {
                                    Write-Verbose "Services did not stop. Terminating Processes after $(([int32]$sw.Elapsed.TotalSeconds).ToString()) seconds."
                                }
                                Get-Process | Where-Object {@('LTTray','LTSVC','LTSvcMon') -contains $_.ProcessName } | Stop-Process -Force -ErrorAction Stop -Whatif:$False -Confirm:$False
                            }#End Try
                
                            Catch{
                                Write-Error "ERROR: Line $(LINENUM): There was an error stopping the LabTech processes. $($Error[0])"
                                return
                            }#End Catch
                        }#End If
                    }#End Process
                
                    End{
                        If ($WhatIfPreference -ne $True) {
                            If ($?) {
                                If((('LTService','LTSvcMon') | Get-Service -EA 0 | Where-Object {$_.Status -ne 'Stopped'} | Measure-Object | Select-Object -Expand Count) -eq 0){
                                    Write-Output "Services Stopped successfully."
                                } Else {
                                    Write-Warning "WARNING: Line $(LINENUM): Services have not stopped completely."
                                }
                            } Else {$Error[0]}
                        }#End If
                        Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)"
                    }#End End
                }#End Function Stop-LTService
                
                Function Start-LTService{
                <#
                .SYNOPSIS
                    This function will start the LabTech Services.
                
                .DESCRIPTION
                    This function will verify that the LabTech services are present.
                    It will then check for any process that is using the LTTray port (Default 42000) and kill it.
                    Next it will start the services.
                #>
                    [CmdletBinding(SupportsShouldProcess=$True)]
                    Param()
                
                    Begin{
                        Write-Debug "Starting $($myInvocation.InvocationName) at line $(LINENUM)"
                        #Identify processes that are using the tray port
                        [array]$processes = @()
                        $Port = (Get-LTServiceInfo -EA 0 -Verbose:$False -WhatIf:$False -Confirm:$False -Debug:$False|Select-Object -Expand TrayPort -EA 0)
                        if (-not ($Port)) {$Port = "42000"}
                        $startedSvcCount=0
                    }#End Begin
                
                    Process{
                        If (-not (Get-Service 'LTService','LTSvcMon' -ErrorAction SilentlyContinue)) {
                            If ($WhatIfPreference -ne $True) {
                                Write-Error "ERROR: Line $(LINENUM): Services NOT Found $($Error[0])"
                                return
                            } Else {
                                Write-Error "What If: Line $(LINENUM): Stopping: Services NOT Found"
                                return
                            }#End If
                        }#End If
                        Try{
                            If((('LTService') | Get-Service -EA 0 | Where-Object {$_.Status -eq 'Stopped'} | Measure-Object | Select-Object -Expand Count) -gt 0) {
                                Try {$netstat=& "${env:windir}\system32\netstat.exe" -a -o -n 2>'' | Select-String -Pattern " .*[0-9\.]+:$($Port).*[0-9\.]+:[0-9]+ .*?([0-9]+)" -EA 0}
                                Catch {Write-Output "Error calling netstat.exe."; $netstat=$null}
                                Foreach ($line in $netstat){
                                    $processes += ($line -split ' {4,}')[-1]
                                }#End Foreach
                                $processes = $processes | Where-Object {$_ -gt 0 -and $_ -match '^\d+$'}| Sort-Object | Get-Unique
                                If ($processes) {
                                    Foreach ($proc in $processes){
                                        Write-Output "Process ID:$proc is using port $Port. Killing process."
                                        Try{Stop-Process -ID $proc -Force -Verbose -EA Stop}
                                        Catch {
                                            Write-Warning "WARNING: Line $(LINENUM): There was an issue killing the following process: $proc"
                                            Write-Warning "WARNING: Line $(LINENUM): This generally means that a 'protected application' is using this port."
                                            $newPort = [int]$port + 1
                                            if($newPort -gt 42009) {$newPort = 42000}
                                            Write-Warning "WARNING: Line $(LINENUM): Setting tray port to $newPort."
                                            New-ItemProperty -Path "HKLM:\Software\Labtech\Service" -Name TrayPort -PropertyType String -Value $newPort -Force -WhatIf:$False -Confirm:$False | Out-Null
                                        }#End Catch
                                    }#End Foreach
                                }#End If
                            }#End If
                            If ($PSCmdlet.ShouldProcess("LTService, LTSvcMon", "Start Service")) {
                                @('LTService','LTSvcMon') | ForEach-Object {
                                    If (Get-Service $_ -EA 0) {
                                        Set-Service $_ -StartupType Automatic -EA 0 -Confirm:$False -WhatIf:$False
                                        $Null=& "${env:windir}\system32\sc.exe" start "$($_)" 2>''
                                        $startedSvcCount++
                                        Write-Debug "Line $(LINENUM): Executed Start Service for $($_)"
                                    }#End If
                                }#End ForEach-Object
                            }#End If
                        }#End Try
                
                        Catch{
                            Write-Error "ERROR: Line $(LINENUM): There was an error starting the LabTech services. $($Error[0])"
                            return
                        }#End Catch
                    }#End Process
                
                    End{
                        If ($WhatIfPreference -ne $True) {
                            If ($?){
                                $svcnotRunning = ('LTService') | Get-Service -EA 0 | Where-Object {$_.Status -ne 'Running'} | Measure-Object | Select-Object -Expand Count
                                If ($svcnotRunning -gt 0 -and $startedSvcCount -eq 2) {
                                    $timeout = new-timespan -Minutes 1
                                    $sw = [diagnostics.stopwatch]::StartNew()
                                    Write-Host -NoNewline "Waiting for Services to Start."
                                    Do {
                                        Write-Host -NoNewline '.'
                                        Start-Sleep 2
                                        $svcnotRunning = ('LTService') | Get-Service -EA 0 | Where-Object {$_.Status -ne 'Running'} | Measure-Object | Select-Object -Expand Count
                                    } Until ($sw.elapsed -gt $timeout -or $svcnotRunning -eq 0)
                                    Write-Host ""
                                    $sw.Stop()
                                }#End If
                                If ($svcnotRunning -eq 0) {
                                    Write-Output "Services Started successfully."
                                    $Null=Invoke-LTServiceCommand 'Send Status' -EA 0 -Confirm:$False
                                } ElseIf ($startedSvcCount -gt 0) {
                                    Write-Output "Service Start was issued but LTService has not reached Running state."
                                } Else {
                                    Write-Output "Service Start was not issued."
                                }#End If
                            }
                            Else{
                                $($Error[0])
                            }#End If
                        }#End If
                        Write-Debug "Exiting $($myInvocation.InvocationName) at line $(LINENUM)"
                    }#End End
                }#End Function Start-LTService