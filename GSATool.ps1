﻿<#
.SYNOPSIS
    GSATool V2.1 PowerShell script.

.DESCRIPTION
    Global Secure Access Troubleshooter Tool is a PowerShell script that troubleshoots Global Secure Access common issues.

.PARAMETER TestMicrosoftTraffic
    Use it to troubleshoot Entra Microsoft Traffic

.PARAMETER TestPrivateAccess
    Use it to troubleshoot Microsoft Entra Private Access

.PARAMETER TestInternetAccess
    Use it to troubleshoot Microsoft Entra Internet Access

.PARAMETER TestPrivateDNS
    Use it to troubleshoot Microsoft Entra Private DNS

.Example
    .\GSATool.ps1 -TestMicrosoftTraffic -UserUPN <testUserUPN>

.Example
    .\GSATool.ps1 -TestPrivateAccess -FQDNorIP <FQDN> -PortNumber <portNumber> -Protocol <protocol> -UserUPN <testUserUPN>

.EXAMPLE
    .\GSATool.ps1
    Enter (1) to troubleshoot Entra Microsoft 365
    Enter (2) to troubleshoot Entra Private Access
    Enter (3) to troubleshoot Entra Internet Access
    Enter (4) to troubleshoot Entra Private DNS
    Enter (Q) to Quit
#>

Param (
    [Parameter(Mandatory=$false)]
    [string] $TestNumber,

    [Parameter(Mandatory=$false)]
    [string] $FQDNorIP,
        
    [Parameter(Mandatory=$false)]
    [int] $PortNumber,
        
    [Parameter(Mandatory=$false)]
    [ValidateSet("TCP","UDP")]
    [string] $Protocol,

    [Parameter(Mandatory=$false)]
    [mailaddress] $UserUPN,

    [Parameter(Mandatory=$false)]
    [switch] $TestMicrosoftTraffic,

    [Parameter(Mandatory=$false)]
    [switch] $TestPrivateAccess,

    [Parameter(Mandatory=$false)]
    [switch] $TestInternetAccess,

    [Parameter(Mandatory=$false)]
    [switch] $TestPrivateDNS
)

Function Write-Log{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [ValidateSet("INFO", "WARN", "ERROR", "FATAL", "DEBUG", "SUCCESS")]
        [String] $Level = "INFO",

        [Parameter(Mandatory=$True)]
        [string] $Message,

        [Parameter(Mandatory=$False)]
        [string] $logfile = "GSATool.log",
        
        [Parameter(Mandatory=$false)]
        $ForegroundColor,
        
        [Parameter(Mandatory=$false)]
        [switch]$LogOnly   
    )

    $Date = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff")
  

    if ($Message -eq " "){
        Add-Content $logfile -Value " " -ErrorAction SilentlyContinue
    }else{
        $logMessage = $Message.Trim("`n")
        Add-Content $logfile -Value "[$date] [$Level] $logMessage" -ErrorAction SilentlyContinue
    }
    if ($LogOnly){ return }
    if ($ForegroundColor) { Write-Host -ForegroundColor $ForegroundColor $Message } 
    else { Write-Host $Message }
}

Function Invoke-GraphRequest {
    param (
        [string]$Uri,
        [string]$Method = "GET",
        [hashtable]$Body = $null 
    )

    $Headers = @{
        'Authorization' = "Bearer $global:accesstoken"
        "Content-Type" = "application/json"
    }

    $maxRetries = 5
    $retryInterval = 2

    for ($i = 0; $i -lt $maxRetries; $i++) {
        try {
            if ($Method -eq "GET" -or $null -eq $Body) {
                $response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method $Method
            } else {
                $jsonBody = $Body | ConvertTo-Json -Depth 10
                $response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method $Method -Body $jsonBody
            }
            return $response
        }
        catch {
            $errorResponse = $_.Exception.Response
            if ($errorResponse -and $errorResponse.StatusCode -eq 429) {
                # Handle throttling (429 Too Many Requests)
                $retryAfter = $errorResponse.Headers["Retry-After"]
                $waitTime = if ($retryAfter) { [int]$retryAfter } else { $retryInterval * [math]::Pow(2, $i) }
                Write-Log -Message "Throttled! Retrying in $waitTime seconds..."
                Start-Sleep -Seconds $waitTime
            }
            else {
                Write-Log -Message "Error: $_"
                break
            }
        }
    }
}

Function GSAToolStart{
    Write-Log -Message "GSATool 2.1 has started" -ForegroundColor Yellow
    Write-Log -Message ([String]::Format("Device Name : {0}",$env:computername))  -ForegroundColor Yellow
    $global:LoggedOnUserUPN=whoami /upn
    $msg = "User Account: $(whoami), UPN: $($global:LoggedOnUserUPN)`n"
    Write-Log -Message $msg  -ForegroundColor Yellow
}

Function Show-FeedbackAndLog {
    Write-Log -Message "`n🌐 The GSATool.log file has been created under $((Get-Location).Path)`n" -ForegroundColor Green
    Write-Host "`n🌟 Your feedback maters! Please submit your feedback at https://aka.ms/GSAToolFeedback`n`n" -ForegroundColor White
}

Function Exit-GSATool {
    param (
        [Parameter(Mandatory=$false)]
        [int] $ExitCode = 0
    )
    
    Show-FeedbackAndLog
    exit $ExitCode
}

Function testDeviceStatus{
    $DSReg = dsregcmd /status
    try{ $EntraConnected = ($DSReg | select-string -Pattern 'AzureADJoined' -SimpleMatch) -Match 'YES'} catch {$_}
    #Checking if device is connected to Entra ID:
    Write-Log -Message "Checking if the device is connected to Microsoft Entra ID..." -ForegroundColor Yellow
    if ($EntraConnected){
        Write-Log -Message "Test passed: $($env:COMPUTERNAME) device is connected to Entra ID`n" -ForegroundColor Green -Level SUCCESS
    }else{
        Write-Log -Message "Test failed: $($env:COMPUTERNAME) device is NOT connected to Entra ID`n" -ForegroundColor Red -Level ERROR
        Write-Log -Message "Recommended action: Make sure your device is either Entra Joined or Hybrid Entra Joined`n`n" -ForegroundColor Yellow
        Exit-GSATool 1
    }
    return $true
}

Function testGSAServices{
    param (
        [string]$isPATest
    )
    #Checking Tunneling Service:
    Write-Log -Message "Checking Tunneling Service..." -ForegroundColor Yellow
    $Service = (Get-Service -Name GlobalSecureAccessTunnelingService -ErrorAction SilentlyContinue).status
    if ($Service -eq 'Running'){
        Write-Log -Message "Test passed: Tunneling Service is running`n" -ForegroundColor Green -Level SUCCESS
    }else{
        Write-Log -Message "Test failed: Tunneling Service is not running`n" -ForegroundColor Red -Level ERROR
        Write-Log -Message "Recommended action: Make sure GlobalSecureAccessTunnelingService service is running`n`n" -ForegroundColor Yellow
        Exit-GSATool 1
    }

    #Checking Management Service:
    Write-Log -Message "Checking Management Service..." -ForegroundColor Yellow
    $Service = (Get-Service -Name GlobalSecureAccessClientManagerService -ErrorAction SilentlyContinue).status
    if ($Service -eq 'Running'){
        Write-Log -Message "Test passed: Management Service is running`n" -ForegroundColor Green  -Level SUCCESS
    }else{
        Write-Log -Message "Test failed: Management Service is not running`n" -ForegroundColor Red -Level ERROR
        Write-Log -Message "Recommended action: Make sure GlobalSecureAccessClientManagerService service is running`n`n" -ForegroundColor Yellow
        Exit-GSATool 1
    }

    #Checking Policy Retriever Service:
    Write-Log -Message "Checking Policy Retriever Service..." -ForegroundColor Yellow
    $Service = (Get-Service -Name GlobalSecureAccessPolicyRetrieverService -ErrorAction SilentlyContinue).status
    if ($Service -eq 'Running'){
        Write-Log -Message "Test passed: Policy Retriever Service is running`n" -ForegroundColor Green -Level SUCCESS
    }else{
        Write-Log -Message "Test failed: Policy Retriever Service is not running`n" -ForegroundColor Red -Level ERROR
        Write-Log -Message "Recommended action: Make sure GlobalSecureAccessPolicyRetrieverService service is running`n`n" -ForegroundColor Yellow
        Exit-GSATool 1
    }

    #Checking Management Service:
    Write-Log -Message "Checking GSA Driver Service..." -ForegroundColor Yellow
    $Service = (Get-Service -Name GlobalSecureAccessDriver -ErrorAction SilentlyContinue).status
    if ($Service -eq 'Running'){
        Write-Log -Message "Test passed: GSA Driver Service is running`n" -ForegroundColor Green -Level SUCCESS
    }else{
        Write-Log -Message "Test failed: GSA Driver Service is not running`n" -ForegroundColor Red -Level ERROR
        Write-Log -Message "`nRecommended action: Make sure GlobalSecureAccessDriver service is running`n`n" -ForegroundColor Yellow
        Exit-GSATool 1
    }

    if ($isPATest){
        #Checking Private Access disablement:
        Write-Log -Message "Checking Private Access registry key value..." -ForegroundColor Yellow
        $reg = Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Global Secure Access Client' -ErrorAction SilentlyContinue
        if ($reg.IsPrivateAccessDisabledByUser -ne 1){
            Write-Log -Message "Test passed: Private Access is enabled`n" -ForegroundColor Green -Level SUCCESS
        }else{
            Write-Log -Message "Test failed: Private Access is disabled`n" -ForegroundColor Red -Level ERROR
            Write-Log -Message "`nRecommended action: Make sure 'IsPrivateAccessDisabledByUser' value is set to 0 in HKCU\Software\Microsoft\Global Secure Access Client`n`n" -ForegroundColor Yellow
            Exit-GSATool 1
        }
    }

    return $true
}

Function Connect-AzureDevicelogin {
    [cmdletbinding()]
    param( 
        [Parameter()]
        $ClientID = 'd3590ed6-52b3-4102-aeff-aad2292ab01c',
        
        [Parameter()]
        $Scope = 'https://graph.microsoft.com/.default NetworkAccess.Read.All Application.Read.All',
                
        [Parameter()]
        [switch]$Interactive,
        
        [Parameter()]
        $TenantID = 'common',
        
        [Parameter()]
        $Resource = "https://graph.microsoft.com/",
        
        # Timeout in seconds to wait for user to complete sign in process
        [Parameter(DontShow)]
        $Timeout = 1
        #$Timeout = 300
    )
    try {
        $DeviceCodeRequestParams = @{
            Method = 'POST'
            Uri    = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/devicecode"
            ContentType = "application/x-www-form-urlencoded"
            Body   = @{
                client_id = $ClientId
                scope = 'https://graph.microsoft.com/.default'
            }
        }
        $DeviceCodeRequest = Invoke-RestMethod @DeviceCodeRequestParams
 
        # Copy device code to clipboard
        $DeviceCode = ($DeviceCodeRequest.message -split "code " | Select-Object -Last 1) -split " to authenticate."
        Set-Clipboard -Value $DeviceCode
        Write-Host "`nDevice code " -ForegroundColor Yellow -NoNewline
        Write-Host $DeviceCode -ForegroundColor Green -NoNewline
        Write-Host "has been copied to the clipboard, please paste it into the opened 'Microsoft Graph Authentication' window, complete the sign in, and close the window to proceed." -ForegroundColor Yellow
        Write-Host "Note: If 'Microsoft Graph Authentication' window didn't open,"($DeviceCodeRequest.message -split "To sign in, " | Select-Object -Last 1) -ForegroundColor gray
        $msg= "Device code $DeviceCode has been copied to the clipboard, please paste it into the opened 'Microsoft Graph Authentication' window, complete the signin, and close the window to proceed.`n                                 Note: If 'Microsoft Graph Authentication' window didn't open,"+($DeviceCodeRequest.message -split "To sign in, " | Select-Object -Last 1)
        Write-Log -Message $msg -LogOnly


        # Open Authentication form window
        Add-Type -AssemblyName System.Windows.Forms
        $form = New-Object -TypeName System.Windows.Forms.Form -Property @{ Width = 440; Height = 640 }
        $web = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{ Width = 440; Height = 600; Url = "https://www.microsoft.com/devicelogin" }
        $web.Add_DocumentCompleted($DocComp)
        $web.DocumentText
        $form.Controls.Add($web)
        $form.Add_Shown({ $form.Activate() })
        $web.ScriptErrorsSuppressed = $true
        $form.AutoScaleMode = 'Dpi'
        $form.text = "Microsoft Graph Authentication"
        $form.ShowIcon = $False
        $form.AutoSizeMode = 'GrowAndShrink'
        $Form.StartPosition = 'CenterScreen'
        $form.ShowDialog() | Out-Null
        
        $TokenRequestParams = @{
            Method = 'POST'
            Uri    = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
            ContentType = "application/x-www-form-urlencoded"
            Body   = @{
                grant_type = "urn:ietf:params:oauth:grant-type:device_code"
                code       = $DeviceCodeRequest.device_code
                client_id  = $ClientId
            }
        }
        $TimeoutTimer = [System.Diagnostics.Stopwatch]::StartNew()
        while ([string]::IsNullOrEmpty($TokenRequest.access_token)) {
            if ($TimeoutTimer.Elapsed.TotalSeconds -gt $Timeout) {
                throw 'Login timed out, please try again.'
            }
            $TokenRequest = try {
                Invoke-RestMethod @TokenRequestParams -ErrorAction Stop
            }
            catch {
                $Message = $_.ErrorDetails.Message | ConvertFrom-Json
                if ($Message.error -ne "authorization_pending") {
                    throw
                }
            }
            Start-Sleep -Seconds 1
        }
        Write-Output $TokenRequest.access_token
    }
    finally {
        try {
            Remove-Item -Path $TempPage.FullName -Force -ErrorAction Stop
            $TimeoutTimer.Stop()
        }
        catch {
            #Ignore errors here
        }
    }
}

Function Decode-JwtToken {
    param (
        [string]$jwtToken
    )

    # Function to add padding to Base64Url encoded strings
    function Add-Padding {
        param (
            [string]$base64Url
        )
        switch ($base64Url.Length % 4) {
            2 { $base64Url += '==' }
            3 { $base64Url += '=' }
        }
        return $base64Url
    }

    # Split the JWT token into its parts
    $tokenParts = $jwtToken -split '\.'
    $header = $tokenParts[0]
    $payload = $tokenParts[1]

    # Add padding to the Base64Url encoded parts
    $header = Add-Padding -base64Url $header
    $payload = Add-Padding -base64Url $payload

    # Decode the Base64Url encoded parts
    $headerJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($header))
    $payloadJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))

    # Convert the JSON to a PowerShell object
    $headerObject = $headerJson | ConvertFrom-Json
    $payloadObject = $payloadJson | ConvertFrom-Json

    return $payloadObject
}

Function ConnectToEntraID{
    Write-Log -Message "Checking if there is a valid Access Token..." -ForegroundColor Yellow
    
    $claims = Decode-JwtToken -jwtToken $global:accesstoken
    $ExpirationTime = $claims.exp
    # Get the current time in Unix epoch format
    $currentTime = [int][double]::Parse((Get-Date -UFormat %s))
    if ($global:accesstoken.Length -ge 1 -or ($currentTime -lt $ExpirationTime)){
        $headers = @{ 
                    'Authorization' = "Bearer $global:accesstoken"
                    }
        $GraphLink = "https://graph.microsoft.com/beta/networkAccess/tenantStatus"
        $GraphResult=$null
        $GraphResult = (Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET").Content | ConvertFrom-Json
        if (!$GraphResult){ throw "404 Not Found" }
        if($GraphResult.'@odata.context'.length -ge 1){
            $claims = Decode-JwtToken -jwtToken $global:accesstoken
            $User_DisplayName=$claims.name
            $User_UPN=$claims.upn
            Write-Log -Message "There is a valid Access Token for user: $User_DisplayName, UPN: $User_UPN`n" -ForegroundColor Green -Level SUCCESS
            $global:onboardingStatus = $GraphResult.onboardingStatus
        }else{
            Write-Log -Message "There no valid Access Token, please sign-in to get an Access Token" -ForegroundColor Yellow
            $global:accesstoken = Connect-AzureDevicelogin
            ''
            if ($global:accesstoken.Length -ge 1){
                # Decode the token
                $claims = Decode-JwtToken -jwtToken $global:accesstoken
                $User_DisplayName=$claims.name
                $User_UPN=$claims.upn
                Write-Log -Message "You signed-in successfully, and got an Access Token for user: $User_DisplayName, UPN: $User_UPN`n" -ForegroundColor Green -Level SUCCESS
                try{
                    $GraphLink = "https://graph.microsoft.com/beta/networkAccess/tenantStatus"
                    $GraphResult = Invoke-GraphRequest -Uri $GraphLink
                    if (!$GraphResult){ throw "404 Not Found" }
                    $global:onboardingStatus = $GraphResult.onboardingStatus
                }catch{
                    Write-Log -Message "`nOperation aborted. Unable to connect to Microsoft Entra ID, please check you entered a correct credentials and you have the needed permissions`n`n" -ForegroundColor Red -Level ERROR
                    Exit-GSATool 1
                }
            }
        }
    }else{
        Write-Log -Message "There no valid Access Token, please sign-in to get an Access Token" -ForegroundColor Yellow
        $global:accesstoken ="" 
        $global:accesstoken = Connect-AzureDevicelogin
        if (!($global:accesstoken.Length -ge 1)){
            Write-Log -Message "`nOperation aborted. Unable to connect to Microsoft Entra ID, please check you entered a correct credentials and you have the needed permissions`n" -ForegroundColor Red -Level ERROR
            Write-Log -Message "Recommended action: Ensure that you have entered valid credentials and completed the sign-in process`n`n" -ForegroundColor Yellow
            Exit-GSATool 1
        }
        # Decode the token
        $claims = Decode-JwtToken -jwtToken $global:accesstoken
        $User_DisplayName=$claims.name
        $User_UPN=$claims.upn
        Write-Log -Message "You signed-in successfully, and got an Access Token for user: $User_DisplayName, UPN: $User_UPN`n" -ForegroundColor Green -Level SUCCESS
        try{
            $GraphLink = "https://graph.microsoft.com/beta/networkAccess/tenantStatus"
            $GraphResult = Invoke-GraphRequest -Uri $GraphLink
            if (!$GraphResult){ throw "404 Not Found" }
            $global:onboardingStatus = $GraphResult.onboardingStatus
        }catch{
            Write-Log -Message "`nOperation aborted. Unable to connect to Microsoft Entra ID, please check you entered a correct credentials and you have the needed permissions`n`n" -ForegroundColor Red -Level ERROR
            Exit-GSATool 1
        }
    }
    
    return $true
}

Function testProfileConfig(){
    param (
        [string]$UserUPN,
        [string]$profileType
    )
    
    if ($profileType -eq 'm365'){
        $profileName = "Microsoft Traffic"
    }elseif ($profileType -eq 'private'){
        $profileName = "Private Access"
    }elseif ($profileType -eq 'internet'){
        $profileName = "Internet Access"
    }

    if (!(ConnectToEntraID)) {Exit-GSATool 1}
    
    Write-Log -Message "Checking the Global Secure Access activation status..." -ForegroundColor Yellow
    #Testing if tenant onboarded to GSA
    if($global:onboardingStatus -eq 'onboarded'){
            #Tenant onboarded
            Write-Log -Message "Test passed: Global Secure Access is activated in the tenant`n" -ForegroundColor Green -Level SUCCESS
        }else{
            #Tenant isn't onboarded
            Write-Log -Message "Test failed: Global Secure Access is NOT activated on the tenant`n" -ForegroundColor Red -Level ERROR
            Write-Log -Message "`nRecommended action: Activate Global Secure Access in your tenant by navigating to Global Secure Access > Get started > Activate Global Secure Access in your tenant, select Activate`n`n" -ForegroundColor Yellow
            Exit-GSATool 1
        }

    #Fetshing forwardingProfiles 
    Write-Log -Message "Checking the $($profileName) forwarding profile..." -ForegroundColor Yellow
    try{
        $GraphLink = "https://graph.microsoft.com/beta/networkAccess/forwardingProfiles?`$filter=trafficForwardingType eq '$($profileType)'"
        $GraphResult = Invoke-GraphRequest -Uri $GraphLink
        if (!$GraphResult){ throw "404 Not Found" }
    }catch{
        Write-Log -Message "`nOperation aborted. Unable to connect to Microsoft Entra ID, please check you entered a correct credentials and you have the needed permissions`n`n" -ForegroundColor Red -Level ERROR
        Exit-GSATool 1
    }
    
    $PrivateProfile = $GraphResult.value
    if($PrivateProfile.state -ge 'enabled'){
        #Profile is enabled
        Write-Log -Message "Test passed: $($profileName) forwarding profile is enabled`n" -ForegroundColor Green -Level SUCCESS
    }else{
        #Profile is disabled
        Write-Log -Message "Test failed: $($profileName) forwarding profile is NOT enabled`n" -ForegroundColor Red -Level ERROR
        Write-Log -Message "`nRecommended action: Please enable $($profileName) profile from Entra > Global Secure Access > Connect > Traffic forwarding`n`n" -ForegroundColor Yellow
        Exit-GSATool 1
    }
    
    #getting user objectID
    $msg = "Please enter UPN (or press ENTER to use the signed in user: $($global:LoggedOnUserUPN)`)"
    if (!$UserUPN){ $EnteredUPN = Read-Host -Prompt $msg }else {$EnteredUPN = $UserUPN}
    if (![string]::IsNullOrEmpty($EnteredUPN)) {
        $global:LoggedOnUserUPN = $EnteredUPN
    }
    try{
        $GraphLink = "https://graph.microsoft.com/v1.0/users/$($global:LoggedOnUserUPN)"
        $GraphResult = Invoke-GraphRequest -Uri $GraphLink
        if (!$GraphResult){ throw "404 Not Found" }
    }catch{
        Write-Log -Message "`nOperation aborted. Make sure to enter a valid UPN and you have the needed permissions`n`n" -ForegroundColor Red -Level ERROR
        Exit-GSATool 1
    }
    $EntraUser = $GraphResult
    if($EntraUser.id.Length -ge 1){
        #User returned
        $global:userObjID = $EntraUser.id
    }

    #Fetshing Private profile SP
    Write-Log -Message "Checking user assignments to the $($profileName) forwarding profile..." -ForegroundColor Yellow
    $PrivateSPId = $PrivateProfile.servicePrincipal.id
    try{
        $GraphLink = "https://graph.microsoft.com/v1.0/servicePrincipals/$($PrivateSPId)?`$select=id,appid,accountEnabled,appRoleAssignmentRequired&`$expand=appRoleAssignedTo(`$select=principalId,principalType,principalDisplayName)"
        $GraphResult = Invoke-GraphRequest -Uri $GraphLink
        if (!$GraphResult){ throw "404 Not Found" }
    }catch{
        Write-Log -Message "`nOperation aborted. Unable to connect to Microsoft Entra ID, please check you entered a correct credentials and you have the needed permissions`n`n" -ForegroundColor Red -Level ERROR
        Exit-GSATool 1
    }

    $appRoleAssignedToUsers = $GraphResult.appRoleAssignedTo | Where-Object -Property principalType -eq 'User'
    $appRoleAssignedToGroups = ($GraphResult.appRoleAssignedTo | Where-Object -Property principalType -eq 'Group' | Select-Object -Property principalId).principalId
    $appRoleAssignment = $GraphResult.appRoleAssignmentRequired
    if($appRoleAssignment -eq $false){
        #All users are assigned
        Write-Log -Message "All users are assigned to $($profileName) profile" -ForegroundColor Green -Level SUCCESS
    }else{
        #Selected users/groups are assigned.
        Write-Log -Message "Limited users are assigned to $($profileName) profile`n" -ForegroundColor Yellow
        Write-Log -Message "Checking if the user is directly assigned to $($profileName) profile..." -ForegroundColor Yellow
        #Checking if user is assigned directly to Private access profile
        try{
            #Search if the user assigned
            $userassigned = $false
            foreach ($role in $appRoleAssignedToUsers){
                if ($role.principalId -eq $global:userObjID){
                    Write-Log -Message "$($global:LoggedOnUserUPN) user is assigned directly to $($profileName) profile`n" -ForegroundColor Green -Level SUCCESS
                    $userassigned = $true
                    break
                }
            }
            if (!$userassigned) {
                Write-Log -Message "$($global:LoggedOnUserUPN) User is NOT assigned directly to $($profileName) profile, checking user's group" -ForegroundColor Yellow
                if ($appRoleAssignedToGroups){
                    #Check group membership
                    try{
                        $body =  @{
                                'groupIds' = @($appRoleAssignedToGroups)
                                }
                        $GraphLink = "https://graph.microsoft.com/beta/users/$($global:LoggedOnUserUPN)/checkMemberGroups"
                        $GraphResult = Invoke-GraphRequest -Uri $GraphLink -Method "POST" -Body $body
                        if (!$GraphResult){ throw "404 Not Found" }
                        $Groups = $GraphResult.value
                        if ($Groups.Count -ge 1){
                            # User is member of at least one group
                            Write-Log -Message "$($global:LoggedOnUserUPN) user is a member of a group assigned to $($profileName) profile`n" -ForegroundColor Green -Level SUCCESS
                        }else{
                            Write-Log -Message "Test failed: user is not member of any of groups assigned to $($profileName) profile`n" -ForegroundColor Red -Level ERROR
                            Write-Log -Message "`nRecommended action: Please ensure the user is directly assigned to the $($profileName) profile or is a member of a group assigned to it`n`n" -ForegroundColor Yellow
                            Exit-GSATool 1
                        }
                    }catch{
                        Write-Log -Message "`nOperation aborted. Unable to connect to Microsoft Entra ID, please check you entered a correct credentials and you have the needed permissions`n`n" -ForegroundColor Red -Level ERROR
                        Exit-GSATool 1
                    }
                }else{
                    Write-Log -Message "Test Failed: There are no groups assigned to $($profileName) profile`n" -ForegroundColor Red -Level ERROR
                    Write-Log -Message "`nRecommended action: Please ensure the user is directly assigned to the $($profileName) profile or is a member of a group assigned to it`n`n" -ForegroundColor Yellow
                    Exit-GSATool 1
                }
            }
        }catch{
            Write-Log -Message "`nOperation aborted. Unable to connect to Microsoft Entra ID, please check you entered a correct credentials and you have the needed permissions`n`n" -ForegroundColor Red -Level ERROR
            Exit-GSATool 1
        }
            
    }
    return $true
}


Function testPAApplication{
    param (
        [string]$PAappID,
        [string]$PappDisplayName,
        [string]$PAAppObjID,
        [int]$portNumber,
        [string]$PAProtocol,
        [string]$FQDNorIP
    )
    
    # Fetshing selected app SP:
    Write-Log -Message "Checking Private Access application status..." -ForegroundColor Yellow
    try{
        $GraphLink = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appid eq '$($PAappID)'&`$select=id,appid,accountEnabled,appRoleAssignmentRequired&`$expand=appRoleAssignedTo(`$select=principalId,principalType,principalDisplayName)"
        $GraphResult = Invoke-GraphRequest -Uri $GraphLink
        if (!$GraphResult){ throw "404 Not Found" }
    }catch{
        Write-Log -Message "`nOperation aborted. Unable to connect to Microsoft Entra ID, please check you entered a correct credentials and you have the needed permissions`n`n" -ForegroundColor Red -Level ERROR
        Exit-GSATool 1
    }
    $isSPEnabled = $GraphResult.value.accountEnabled
    if (!$isSPEnabled){
        Write-Log -Message "Test Failed: '$($PappDisplayName)' Private Access application is disabled`n" -ForegroundColor Red -Level ERROR
        Write-Log -Message "Recommended Action: Please ensure enable Private Access application: $($PappDisplayName).`n`n" -ForegroundColor Yellow
        Exit-GSATool 1
    }
    Write-Log -Message "'$($PappDisplayName)' Private Access application is enabled`n" -ForegroundColor Green -Level SUCCESS

    Write-Log -Message "Checking the Private Access Application user configuration..." -ForegroundColor Yellow
    if (!($GraphResult.value).appRoleAssignmentRequired){
        Write-Log -Message "assignment is not required for Private access application: $($PappDisplayName), all users can access it`n" -ForegroundColor Green
    }else{
        Write-Log -Message "Assignment is required for Private access application: $($PappDisplayName), checking user assignment" -ForegroundColor Yellow
        $appRoleAssignedToUsers = ($GraphResult.value).appRoleAssignedTo | Where-Object -Property principalType -eq 'User'
        $appRoleAssignedToGroups = (($GraphResult.value).appRoleAssignedTo | Where-Object -Property principalType -eq 'Group' | Select-Object -Property principalId).principalId
        #Checking if the user directly assigned
        try{
            #Search if the user assigned
            $userassigned = $false
            foreach ($role in $appRoleAssignedToUsers){
                if ($role.principalId -eq $global:userObjID){
                    Write-Log -Message "$($global:LoggedOnUserUPN) user is assigned directly to Private access application: $($PappDisplayName)`n" -ForegroundColor Green
                    $userassigned = $true
                    break
                }
            }
            if (!$userassigned) {
                Write-Log -Message "$($global:LoggedOnUserUPN) User is NOT assigned directly to Private access application: $($PappDisplayName), checking user's group" -ForegroundColor Yellow
                if ($appRoleAssignedToGroups){
                    #Check group membership
                    try{
                        $body =  @{
                                'groupIds' = @($appRoleAssignedToGroups)
                                }
                        $GraphLink = "https://graph.microsoft.com/beta/users/$($global:LoggedOnUserUPN)/checkMemberGroups"
                        $GraphResult = Invoke-GraphRequest -Uri $GraphLink -Method "POST" -Body $body
                        if (!$GraphResult){ throw "404 Not Found" }
                        $Groups = $GraphResult.value
                        if ($Groups.Count -ge 1){
                            # User is member of at least one group
                            Write-Log -Message "$($global:LoggedOnUserUPN) user is a member of a group assigned to Private access application: $($PappDisplayName)" -ForegroundColor Green -Level SUCCESS
                        }else{
                            Write-Log -Message "Test failed: user is not member of any of groups assigned to Private access application: $($PappDisplayName)`n" -ForegroundColor Red -Level ERROR
                            Write-Log -Message "`nRecommended action: Please ensure the user is directly assigned to the Private Access application: $($PappDisplayName) or is a member of a group assigned to it`n`n" -ForegroundColor Yellow
                            Exit-GSATool 1
                        }
                    }catch{
                        Write-Log -Message "`nOperation aborted. Unable to connect to Microsoft Entra ID, please check you entered a correct credentials and you have the needed permissions`n`n" -ForegroundColor Red -Level ERROR
                        Exit-GSATool 1
                    }
                }else{
                    Write-Log -Message "Test Failed: There are no groups assigned to Private access application: $($PappDisplayName)`n" -ForegroundColor Red -Level ERROR
                    Write-Log -Message "`nRecommended action: Please ensure the user is directly assigned to the Private Access application : $($PappDisplayName) or is a member of a group assigned to it`n`n" -ForegroundColor Yellow
                    Exit-GSATool 1
                }
            }
        }catch{
            Write-Log -Message "`nOperation aborted. Unable to connect to Microsoft Entra ID, please check you entered a correct credentials and you have the needed permissions`n`n" -ForegroundColor Red -Level ERROR
            Exit-GSATool 1
        }
    }
    
    # Fetshing selected app SP:
    try{
        $GraphLink = "https://graph.microsoft.com/beta/applications/$($PAAppObjID)/onPremisesPublishing/segmentsConfiguration/microsoft.graph.ipSegmentConfiguration/applicationSegments"
        $GraphResult = Invoke-GraphRequest -Uri $GraphLink
        if (!$GraphResult){ throw "404 Not Found" }
    }catch{
        Write-Log -Message "`nOperation aborted. Unable to connect to Microsoft Entra ID, please check you entered a correct credentials and you have the needed permissions`n`n" -ForegroundColor Red -Level ERROR
        Exit-GSATool 1
    }
    $applicationSegments = ""
    $item = ""
    $portFound = $false
    $ProtocolFound = $false
    $input = Test-IPorFQDN -FQDNorIP $FQDNorIP
    if ($input -eq "FQDN"){
        $nameFound = $false
        $applicationSegments = $GraphResult.value | Where-Object { $_.destinationType -eq "fqdn" }
        foreach ($appSegment in $applicationSegments){
            $nameFound = $false
            if (($DestinationHost -eq $InputHost) -or ($DestinationHost -match "^\*\.(.+)$")) {
                $nameFound = $true
                if ($portNumber -match "^\d+$") {
                    foreach ($range in $appSegment.ports) {
                        $bounds = $range -split "-"
                        if ($bounds.Count -eq 2) {
                            $lower = [int]$bounds[0]
                            $upper = [int]$bounds[1]
                            if ($portNumber -ge $lower -and $portNumber -le $upper) {
                                $portFound = $true
                                # Checking the protocol
                                if ($appSegment.protocol -cmatch "\b$($PAProtocol)\b"){
                                    $ProtocolFound = $true
                                    break
                                }
                            }
                        }
                    }
                }
            }
            if ($ProtocolFound){break}
        }

        if ($portFound){
            Write-Log -Message "Port $portNumber is configured for Private Access application: $($PappDisplayName)" -ForegroundColor Green
            # Checking the protocol
            if ($ProtocolFound){
                Write-Log -Message "$($PAProtocol) protocol is configured for port number $($portNumber)" -ForegroundColor Green
            }else{
                Write-Log -Message "$($PAProtocol) protocol is NOT configured for port number $($portNumber)`n`n" -ForegroundColor Red -Level ERROR
                Write-Log -Message "Recommended action: Ensure you enter a correct protocol and its configured in the Private Access Application: $($PappDisplayName)`n`n" -ForegroundColor Yellow
                Exit-GSATool 1
            }
        }else{
            Write-Log -Message "Port $portNumber is NOT configured for Private Access application: $($PappDisplayName)`n`n" -ForegroundColor Red -Level ERROR
            Write-Log -Message "Recommended action: Ensure you enter a correct port number and its configured in the Private Access Application: $($PappDisplayName)`n`n" -ForegroundColor Yellow
            Exit-GSATool 1
        }

    }elseif ($input -eq "ip"){
        $applicationSegments = $GraphResult.value | Where-Object { $_.destinationType -match "ip" }
        foreach ($appSegment in $applicationSegments){
            $portFound = $false
            $ProtocolFound = $false
            switch ($appSegment.destinationType){
                "ipRangeCidr"{
                    $CIDR = $appSegment.destinationHost -split "/"
                    $BaseIP = [System.Net.IPAddress]::Parse($CIDR[0]).GetAddressBytes()
                    [array]::Reverse($BaseIP)
                    $BaseIP = [BitConverter]::ToUInt32($BaseIP, 0)
                    $Mask = -bnot ([math]::Pow(2, (32 - [int]$CIDR[1])) - 1)
                    $StartIP = $BaseIP -band $Mask
                    $EndIP = $StartIP -bor (-bnot $Mask)
                    $CheckIP = [System.Net.IPAddress]::Parse($FQDNorIP).GetAddressBytes()
                    [array]::Reverse($CheckIP)
                    $CheckIP = [BitConverter]::ToUInt32($CheckIP, 0)
                    if ($CheckIP -ge $StartIP -and $CheckIP -le $EndIP) {
                        if ($portNumber -match "^\d+$") {
                            foreach ($range in $appSegment.ports) {
                                $bounds = $range -split "-"
                                if ($bounds.Count -eq 2) {
                                    $lower = [int]$bounds[0]
                                    $upper = [int]$bounds[1]
                                    if ($portNumber -ge $lower -and $portNumber -le $upper) {
                                        $portFound = $true
                                        # Checking the protocol
                                        if ($appSegment.protocol -cmatch "\b$($PAProtocol)\b"){
                                            $ProtocolFound = $true
                                            break
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                "ipRange" {
                    $Range = $appSegment.destinationHost -split "\.\."
                    $StartIP = [System.Net.IPAddress]::Parse($Range[0]).GetAddressBytes()
                    $EndIP = [System.Net.IPAddress]::Parse($Range[1]).GetAddressBytes()
                    $CheckIP = [System.Net.IPAddress]::Parse($FQDNorIP).GetAddressBytes()
                    if ([BitConverter]::ToUInt32($CheckIP, 0) -ge [BitConverter]::ToUInt32($StartIP, 0) -and [BitConverter]::ToUInt32($CheckIP, 0) -le [BitConverter]::ToUInt32($EndIP, 0)) {
                        if ($portNumber -match "^\d+$") {
                            $portNumber = [int]$portNumber
                            foreach ($range in $appSegment.ports) {
                                $bounds = $range -split "-"
                                if ($bounds.Count -eq 2) {
                                    $lower = [int]$bounds[0]
                                    $upper = [int]$bounds[1]
                                    if ($portNumber -ge $lower -and $portNumber -le $upper) {
                                        $portFound = $true
                                        # Checking the protocol
                                        if ($appSegment.protocol -cmatch "\b$($PAProtocol)\b"){
                                            $ProtocolFound = $true
                                            break
                                        }
                                    }
                                }
                            }
                        }

                    }
                }
                "ip" {
                    if ($FQDNorIP -eq $appSegment.destinationHost) {
                        if ($portNumber -match "^\d+$") {
                            $portNumber = [int]$portNumber
                            foreach ($range in $appSegment.ports) {
                                $bounds = $range -split "-"
                                if ($bounds.Count -eq 2) {
                                    $lower = [int]$bounds[0]
                                    $upper = [int]$bounds[1]
                                    if ($portNumber -ge $lower -and $portNumber -le $upper) {
                                        $portFound = $true
                                        # Checking the protocol
                                        if ($appSegment.protocol -cmatch "\b$($PAProtocol)\b"){
                                            $ProtocolFound = $true
                                            break
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }if ($portFound -and $ProtocolFound) { break}
        }


        if ($portFound){
            Write-Log -Message "Port $portNumber is configured for Private Access application: $($PappDisplayName)" -ForegroundColor Green
            # Checking the protocol
            if ($ProtocolFound){
                Write-Log -Message "$($PAProtocol) protocol is configured for port number $($portNumber)" -ForegroundColor Green
            }else{
                Write-Log -Message "$($PAProtocol) protocol is NOT configured for port number $($portNumber)`n`n" -ForegroundColor Red -Level ERROR
                Write-Log -Message "Recommended action: Ensure you enter a correct protocol and its configured in the Private Access Application: $($PappDisplayName)`n`n" -ForegroundColor Yellow
                Exit-GSATool 1
            }
        }else{
            Write-Log -Message "Port $portNumber is NOT configured for the Private Access application: $($PappDisplayName)`n`n" -ForegroundColor Red -Level ERROR
            Write-Log -Message "Recommended action: Ensure you enter a correct port number and its configured in the Private Access Application: $($PappDisplayName)`n`n" -ForegroundColor Yellow
            Exit-GSATool 1
        }

    }else{
        Write-Log -Message "Invalid input. Please enter a valid port number" -ForegroundColor Yellow
    }

    return $true
}

Function testGSAClientProfile{
    param (
        [string]$profileType
    )
    
    if ($profileType -eq 'm365'){
        $profileName = "Microsoft Traffic"
    }elseif ($profileType -eq 'private'){
        $profileName = "Private Access"
    }elseif ($profileType -eq 'internet'){
        $profileName = "Internet Access"
    }

    #Testing Forwarding Profile
    Write-Log -Message "Checking $($profileName) profile..." -ForegroundColor Yellow
    
    $path = "HKLM:\SOFTWARE\Microsoft\Global Secure Access Client"
    $name = "ForwardingProfile"
    $regForwardingPRofile = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
    if ($regForwardingPRofile){
        Write-Log -Message "Forwarding profile key exists" -ForegroundColor Green
    }else{
        Write-Log -Message "Test Failed: Forwarding profile key does not exists" -ForegroundColor Red -Level ERROR
        Write-Log -Message "`nRecommended action: Please ensure $($profileName) forwarding profile is enabled and user is assigned in Entra portal under Global Secure Access > Connect > Traffic forwarding`n`n" -ForegroundColor Yellow
        Exit-GSATool 1
    }
     if ((Get-ItemPropertyValue -Path $path -Name $name) -ne "") {
        Write-Log -Message "Forwarding profile value is not empty" -ForegroundColor Green
     }else{
        Write-Log -Message "Test Failed: forwarding profile value is empty" -ForegroundColor Red -Level ERROR
        Write-Log -Message "`nRecommended action: Restart 'GlobalSecureAccessPolicyRetrieverService' service to retreive forwarding provile configuration`n`n" -ForegroundColor Yellow
        Exit-GSATool 1
    }

    $jsonObject = $regForwardingPRofile.ForwardingProfile | ConvertFrom-Json
    $FPChannel = $jsonObject.policy.channels | Where-Object { $_.name -eq "$($profileType)" }
    if (!$FPChannel){
        Write-Log -Message "Test Failed: $($profileName) forwarding profile is not retrieved" -ForegroundColor Red -Level ERROR
        Write-Log -Message "`nRecommended action: Please ensure $($profileName) forwarding profile is enabled and user is assigned in Entra portal under Global Secure Access > Connect > Traffic forwarding`n`n" -ForegroundColor Yellow
        Exit-GSATool 1
    }
    Write-Log -Message "Test passed: $($profileName) forwarding profile configuration has retrieved`n" -ForegroundColor Green -Level SUCCESS

    #Testing connectivity to primary, secondary, diagnostic URLs
    $primaryEdges = $FPChannel.edgesSettings.primaryEdges[0].edgeAddress
    $primaryEdgePort = $FPChannel.edgesSettings.primaryEdges[0].edgePort
    $secondaryEdges = $FPChannel.edgesSettings.secondaryEdges[0].edgeAddress
    $secondaryEdgePort = $FPChannel.edgesSettings.primaryEdges[0].edgePort
    $diagnosticUri = $FPChannel.diagnosticUri

    Write-Log -Message "Checking connectivity to $($profileName) Edge..." -ForegroundColor Yellow
    if (!(Test-NetConnection -ComputerName $primaryEdges -Port $($primaryEdgePort) -InformationAction SilentlyContinue).TcpTestSucceeded){
        Write-Log -Message "Failed to connect to the primary $($profileName) edge, checking connectivity to the secondary edge..." -ForegroundColor Yellow
        if (!(Test-NetConnection -ComputerName $secondaryEdges -Port $($secondaryEdgePort) -InformationAction SilentlyContinue).TcpTestSucceeded){
            Write-Log -Message "Test Failed: unable to connect to $($profileName) edges" -ForegroundColor Red -Level ERROR
            Write-Log -Message "`nRecommended action: Please ensure that Internet connectivity to the following $($profileName) Edges is allowed:`n`t$($primaryEdges)`n`t$($secondaryEdges)`n`n" -ForegroundColor Yellow
            Exit-GSATool 1
        }else{
            Write-Log -Message "Test passed: connection to the $($profileName) Edge succeeded`n" -ForegroundColor Green -Level SUCCESS
        }

    }else{
        Write-Log -Message "Test passed: connection to the $($profileName) Edge succeeded`n" -ForegroundColor Green -Level SUCCESS
    }

    #Testing connectivity to diagnostic URLs
    Write-Log -Message "Checking connectivity to $($profileName) diagnostic endpoint..." -ForegroundColor Yellow
    $healthTest = Invoke-WebRequest -Uri $diagnosticUri
    if (!($healthTest.StatusCode -eq 200 -and $healthTest.Content -eq 'pong')){
        Write-Log -Message "Test Failed: unable to connect to $($profileName) diagnostic endpoint" -ForegroundColor Red -Level ERROR
        Write-Log -Message "`nRecommended action: Please ensure outbound traffic to $diagnosticUri is allowed`n`n" -ForegroundColor Yellow
        Exit-GSATool 1
    }else{
        Write-Log -Message "Test passed: connection to $($profileName) diagnostic endpoint succeeded`n" -ForegroundColor Green -Level SUCCESS
    }
    
    return $true
}

Function Test-IPorFQDN {
    param (
        [string]$FQDNorIP
    )

    # Regular expression for validating IP address
    $ipRegex = '^(([0-9]{1,3}\.){3}[0-9]{1,3})$'

    # Regular expression for validating FQDN
    $fqdnRegex = '^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$'

    if ($FQDNorIP -match $ipRegex) {
        # Check if each octet is between 0 and 255
        $octets = $FQDNorIP -split '\.'
        $isValidIP = $true
        foreach ($octet in $octets) {
            if ([int]$octet -lt 0 -or [int]$octet -gt 255) {
                $isValidIP = $false
                break
            }
        }
        if ($isValidIP) {
            Write-Output "IP"
        } else {
            Write-Output "false"
        }
    } elseif ($FQDNorIP -match $fqdnRegex) {
        Write-Output "FQDN"
    } else {
        Write-Output "false"
    }
}

Function Convert-DecimalToIP {
    param (
        [UInt32]$Decimal
    )
    
    # Convert decimal to IP address (big-endian)
    $bytes = [BitConverter]::GetBytes($Decimal)
    [Array]::Reverse($bytes)  # Ensure big-endian
    return [System.Net.IPAddress]::new($bytes).ToString()
}

Function Convert-IPToDecimal {
    param (
        [string]$IPAddress
    )
    
    $bytes = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()
    [Array]::Reverse($bytes)  # Convert to little-endian for UInt32
    return [BitConverter]::ToUInt32($bytes, 0)
}

Function Test-IPExists {
       param (
        [UInt32]$Start,
        [UInt32]$End,
        [string]$testIP
    ) 
    # convert IP 
    $firstIP = Convert-DecimalToIP -Decimal $Start
    $lastIP = Convert-DecimalToIP -Decimal $End
    $testIPInt = Convert-IPToDecimal -IPAddress $testIP
    # Check if the test IP is within the range
    if ($testIPInt -ge $Start -and $testIPInt -le $End) {
        #The IP address $testIP is within the range of $firstIP and $lastIP
        return $true
    } else {
        # The IP address $testIP is NOT within the range of $firstIP and $lastIP
        return $false
    }

}

Function Test-PortExists{
    param (
        $ports,
        $testPort
    ) 
    
    $portFound = $false
    foreach ($port in $ports){
        $portNumber = $testPort
        $StartPort = $port.start
        $EndPort = $port.end
        if ($portNumber -match "^\d+$") {
            $portNumber = [int]$portNumber
            if ($portNumber -ge $StartPort -and $portNumber -le $EndPort) {
                $portFound = $true
            }
        }
    }
    return $portFound
}

Function testPrivateAccessApp{
     param (
        $appID,
        $FQDNorIP,
        $Port,
        $Protocol
    )
    Write-Log -Message "`nChecking the Private Access Application configuration...`n" -ForegroundColor Yellow
    try{
        $GraphLink = "https://graph.microsoft.com/beta/applications?`$select=displayName,appId,id,tags,createdDateTime,createdDateTime,servicePrincipalNames&`$filter=appid eq '$($appID)'"
        $GraphResult = Invoke-GraphRequest -Uri $GraphLink
        if (!$GraphResult){ throw "404 Not Found" }
    }catch{
        Write-Log -Message "`nOperation aborted. Unable to connect to Microsoft Entra ID, please check you entered a correct credentials and you have the needed permissions`n`n" -ForegroundColor Red -Level ERROR
        Exit-GSATool 1
    }

    $forwardingProfiles = $GraphResult.value
    $PAPort = $Port
    $PAProtocol = $Protocol
    $PAAppObjID = $forwardingProfiles.id
    $PAappID = $appID
    $PappDisplayName = $forwardingProfiles.displayName
    
    Write-Log -Message "Checking the access with Global Secure Access client configuration..." -ForegroundColor Yellow
    $isGSAEnabled = $forwardingProfiles | Where-Object { $_.tags -match 'IsAccessibleViaZTNAClient' -or $_.tags -match 'NetworkAccessQuickAccessApplication' }
    if (!$isGSAEnabled){
        Write-Log -Message "`nTest Failed: GSA option is not enabled for Private Access application: $($PappDisplayName)`n" -ForegroundColor Red -Level ERROR
        Write-Log -Message "Recommended Action: Please ensure that the 'Enable access with Global Secure Access client' checkbox is selected under the 'Network Access Properties' blade for Private Access application: $($PappDisplayName).`n`n" -ForegroundColor Yellow
        Exit-GSATool 1
    }
    Write-Log -Message "Access with Global Secure Access client is enabled`n" -ForegroundColor Green -Level SUCCESS

    $testQAAppResult = $false
    $testPAAppResult = testPAApplication -PAappID $PAappID -PappDisplayName $PappDisplayName -PAAppObjID $PAAppObjID -portNumber $PAPort -PAProtocol $PAProtocol -FQDNorIP $FQDNorIP
    if (!$testPAAppResult){
        Exit-GSATool 1
    }else{
        # test tunnelling
        Write-Log -Message "`nChecking tunnel establishing..." -ForegroundColor Yellow
        if ($Protocol -eq 'udp'){
            Write-Log -Message "Could not test UDP port" -ForegroundColor Yellow
            return $true
            <#if (Test-Path -Path .\psping.exe){
                $IPandPort = "$($FQDNorIP):$($Port)"
                $r = .\psping.exe $IPandPort -u -n 1 -accepteula #-ErrorAction SilentlyContinue
                if ($r -cmatch '100% loss'){
                    Write-Log -Message "`nTest failed: Connection has not established to GSA Edge`n" -ForegroundColor Red -Level ERROR
                    Write-Log -Message "Recommended action: Please ensure outbound traffic is allowed for port number $($Port) and protocol $($Protocol) for $($FQDNorIP) `n`n" -ForegroundColor Yellow
                    Exit-GSATool 1
                }else{
                    #UDP port opened
                    $syntaticIP = ($r | Select-String -Pattern "TCP connect to (\d{1,3}\.){3}\d{1,3}" | ForEach-Object { ($_ -split " ")[3].TrimEnd(':') }) -replace ":\d+", ""
                }
            }else{
                Write-Log -Message "Could not test UDP port`n" -ForegroundColor Yellow
                Write-Log -Message "Recommended action: Please ensure outbound traffic is allowed for port number $($Port) and protocol $($Protocol) for $($FQDNorIP) `n`n" -ForegroundColor Yellow
                Write-Log -Message "All tests passed successfully. If you have an issue not addressed, please open a support request`n" -ForegroundColor Green -Level SUCCESS
                Exit-GSATool 1
            }#>
        }else{
        #TCP port
            $tunnelStatus = Test-NetConnection -ComputerName $FQDNorIP -Port $Port -InformationAction SilentlyContinue
            $syntaticIP = $tunnelStatus.RemoteAddress
            if(!$tunnelStatus.TcpTestSucceeded){
                Write-Log -Message "`nTest failed: Connection has not established to GSA Edge`n" -ForegroundColor Red -Level ERROR
                Write-Log -Message "Recommended action: Please ensure outbound traffic is allowed for port number $($Port) and protocol $($Protocol) for $($FQDNorIP) `n`n" -ForegroundColor Yellow
                Exit-GSATool 1
            }
        }

            $isFQDNorIP = Test-IPorFQDN -FQDNorIP $FQDNorIP
            if (($isFQDNorIP -eq "FQDN") -and (!($syntaticIP -like "6.6.*"))){
                Write-Log -Message "`nTest failed: Connection has not tunneled`n" -ForegroundColor Red -Level ERROR
                Write-Log -Message "Recommended action: Please ensure outbound traffic is allowed for port number $($Port) and protocol $($Protocol) `n`n" -ForegroundColor Yellow
                Exit-GSATool 1
            }

            Write-Log -Message "Test passed: Tunnel has established successfully to GSA Edge with the following details:" -ForegroundColor Green -Level SUCCESS
            if ($isFQDNorIP -eq "FQDN"){
                Write-Log -Message "`tFQDN: $($FQDNorIP)" -ForegroundColor Green
                Write-Log -Message "`tProtocol / Port: $($Protocol)/$($Port)" -ForegroundColor Green
                Write-Log -Message "`tSynthetic Address: $($syntaticIP)" -ForegroundColor Green

                $dnsResolve = Resolve-DnsName -Name $FQDNorIP -Server 6.6.255.254 -TcpOnly
                if ($dnsResolve){
                    Write-Log -Message "`tInternal Address : $($dnsResolve.IPAddress)" -ForegroundColor Green
                }else{
                    #dns does not resolve
                    Write-Log -Message "`nTest failed: could not resolve internal DNS name for $($FQDNorIP)`n" -ForegroundColor Red -Level ERROR
                    Write-Log -Message "Recommended action: Ensure you have entered a valid DNS record, configured Private DNS, and the Private Network Connector server is able to resolve the entered DNS name`n`n" -ForegroundColor Yellow
                    Exit-GSATool 1
                }
            }elseif ($isFQDNorIP -eq "ip"){
                Write-Log -Message "`tIP Address: $($FQDNorIP)" -ForegroundColor Green
                Write-Log -Message "`tPort Number: $($Port)" -ForegroundColor Green
                Write-Log -Message "`tProtocol: $($Protocol)" -ForegroundColor Green
            }
        
    }

    return $true
}

Function testPrivateAccessRules{
    param (
        $FQDNorIP,
        $Port,
        $Protocol
    ) 

    Write-Log -Message "Checking GSA client forwarding profile configuration..." -ForegroundColor Yellow
    $appID = ""
    if (!$FQDNorIP) { $FQDNorIP = Read-Host "Enter valid FQDN or IP address for the terget resource" }
    if (!$Port) { $Port = Read-Host "Enter valid port number" }
    if (!$Protocol) { $Protocol = Read-Host "Enter valid protocol (TCP/UDP)" }

    $path = "HKLM:\SOFTWARE\Microsoft\Global Secure Access Client"
    $name = "ForwardingProfile"
    $regForwardingPRofile = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
    $json = $regForwardingPRofile.ForwardingProfile | ConvertFrom-Json

    $input = Test-IPorFQDN -FQDNorIP $FQDNorIP
    if (!$input){
        Write-Log -Message "Invalid entry. Please ensure you enter a valid FQDN or valid IP address"
        Exit-GSATool 1

    }elseIf ($input -eq "IP"){
        $rulesWithIP = $json.policy.rules | Where-Object { $_.matchingCriteria.address.ips.Length -ge 1 }
        $IPExists = $false
        $PortExists = $false
        $ProtocolExists = $false
        foreach ($rule in $rulesWithIP){
            $audienceScope = $rule.appAuthorizationTokenContext.audienceScope
            if (Test-IPExists -Start ($rule.matchingCriteria.address.ips).start -End ($rule.matchingCriteria.address.ips).end -testIP $FQDNorIP){
                # IP exists, checking ports and protocols
                $IPExists = $true
                $appID = [regex]::Match($audienceScope, "api://([^/]+)").Groups[1].Value
                if (Test-PortExists -ports $rule.matchingCriteria.ports -testPort $Port){
                    # port exists, checking the protocol
                    $PortExists = $true
                    $appID = [regex]::Match($audienceScope, "api://([^/]+)").Groups[1].Value
                    if ($rule.matchingCriteria.protocol -eq $Protocol){
                        $ProtocolExists = $true
                        $appID = [regex]::Match($audienceScope, "api://([^/]+)").Groups[1].Value
                        Write-Log -Message "The forwarding profile is configured to allow traffic with the following settings:`n`tRule ID: $($rule.id)`n`tApp ID: $($appID)`n`tIP Address: $($FQDNorIP)`n`tPort Number: $Port`n`tProtocol: $($Protocol)`n" -ForegroundColor Green
                        break
                    }
                }
            }
        }



        If (!$IPExists){
            Write-Log -Message "Entered IP Address '$($FQDNorIP)' is not configured for any Private Access application`n" -ForegroundColor Red -Level ERROR
            Write-Log -Message "Recommended action: Ensure you enter a valid IP Address and its configured in an Private Access application`n`n" -ForegroundColor Yellow
            Exit-GSATool 1
        }

        If (!$PortExists){
            Write-Log -Message "$FQDNorIP found in Forwarding Profile configuration" -ForegroundColor Green
            Write-Log -Message "Port $Port is NOT configured for the Private Access application (App ID: $($appID))`n`n" -ForegroundColor Red -Level ERROR
            Write-Log -Message "Recommended action: Ensure you enter a correct port number and its configured in the Private Access Application (App ID: $($appID))`n`n" -ForegroundColor Yellow
            Exit-GSATool 1
        }

        If (!$ProtocolExists){
            Write-Log -Message "$FQDNorIP found in Forwarding Profile configuration" -ForegroundColor Green
            Write-Log -Message "$Port port found configured for $FQDNorIP in Forwarding Profile configuration" -ForegroundColor Green
            Write-Log -Message "$($Protocol) protocol is NOT configured for port number $($Port) for the Private Access application: (App ID: $($appID))`n" -ForegroundColor Red -Level ERROR
            Write-Log -Message "Recommended action: Ensure you enter a correct protocol and its configured in the Private Access Application (App ID: $($appID))`n`n" -ForegroundColor Yellow
            Exit-GSATool 1
        }
    
    }elseif ($input -eq "FQDN"){
        $rulesWithFQDN = $json.policy.rules | Where-Object { $_.matchingCriteria.address.fqdns.Length -ge 1 -and $_.appAuthorizationTokenContext.clientAppId.Length -ge 1}
        $FQDNExists = $false
        $PortExists = $false
        $ProtocolExists = $false
        foreach ($rule in $rulesWithFQDN){
            $audienceScope = $rule.appAuthorizationTokenContext.audienceScope
            #$appID = [regex]::Match($audienceScope, "api://([^/]+)").Groups[1].Value
            foreach ($FQDNregex in $rule.matchingCriteria.address.fqdns){
                #if ($FQDNorIP -match $FQDNregex){
                if ($FQDNorIP -match "^$FQDNregex$") {
                    # FQDN exists, checking ports and protocols
                    $FQDNExists = $true
                    $appID = [regex]::Match($audienceScope, "api://([^/]+)").Groups[1].Value
                    if (Test-PortExists -ports $rule.matchingCriteria.ports -testPort $Port){
                        # port exists, checking the protocol
                        $PortExists = $true
                        $appID = [regex]::Match($audienceScope, "api://([^/]+)").Groups[1].Value
                        if ($rule.matchingCriteria.protocol -eq $Protocol){
                            $ProtocolExists = $true
                            $appID = [regex]::Match($audienceScope, "api://([^/]+)").Groups[1].Value
                            Write-Log -Message "The forwarding profile is configured to allow traffic with the following settings:`n`tRule ID: $($rule.id)`n`tApp ID: $($appID)`n`tFQDN: $($FQDNorIP)`n`tPort Number: $Port`n`tProtocol: $($Protocol)`n" -ForegroundColor Green
                            break
                        }
                    }
                }
            }
            if ($ProtocolExists){break}
        }

        If (!$FQDNExists){
            Write-Log -Message "Entered FQDN '$($FQDNorIP)' is not configured for any Private Access application`n`n" -ForegroundColor Red -Level ERROR
            Write-Log -Message "Recommended action: Ensure you enter a valid FQDN and its configured in an Private Access application`n`n" -ForegroundColor Yellow
            Exit-GSATool 1
        }

        If (!$PortExists){
            Write-Log -Message "$FQDNorIP found in Forwarding Profile configuration" -ForegroundColor Green
            Write-Log -Message "Port $Port is NOT configured for the Private Access application (App ID: $($appID))`n`n" -ForegroundColor Red -Level ERROR
            Write-Log -Message "Recommended action: Ensure you enter a correct port number and its configured in the Private Access Application (App ID: $($appID))`n`n" -ForegroundColor Yellow
            Exit-GSATool 1
        }

        If (!$ProtocolExists){
            Write-Log -Message "$FQDNorIP found in Forwarding Profile configuration" -ForegroundColor Green
            Write-Log -Message "$Port port found configured for $FQDNorIP in Forwarding Profile configuration" -ForegroundColor Green
            Write-Log -Message "$($Protocol) protocol is NOT configured for port number $($Port) for the Private Access application: (App ID: $($appID))`n`n" -ForegroundColor Red -Level ERROR
            Write-Log -Message "Recommended action: Ensure you enter a correct protocol and its configured in the Private Access Application (App ID: $($appID))`n`n" -ForegroundColor Yellow
            Exit-GSATool 1
        }

    }else{
        Write-Log -Message "Entered FQDN '$($FQDNorIP)' is invalid FQDN or IP Address`n`n" -ForegroundColor Red -Level ERROR
        Write-Log -Message "Recommended action: Ensure you enter a correct FQDN or IP address`n`n" -ForegroundColor Yellow
        Exit-GSATool 1
    }

    if (!(testProfileConfig -UserUPN $UserUPN -profileType 'private')) {Exit-GSATool 1}

    if (!(testPrivateAccessApp -appID $appID -FQDNorIP $FQDNorIP -Port $Port -Protocol $Protocol)) {Exit-GSATool 1}

    return $true
}


Function EntraMicrosoft365{
    $ErrorActionPreference = 'SilentlyContinue'
    GSAToolStart
    if (!(testGSAServices)) {Exit-GSATool 1}
    if (!(testDeviceStatus)) {Exit-GSATool 1}
    if (!(testGSAClientProfile -profileType "m365")) {Exit-GSATool 1}
    if (!(testProfileConfig -UserUPN $UserUPN -profileType "m365")) {Exit-GSATool 1}
}

Function EntraPrivateAccess{
    $ErrorActionPreference = 'SilentlyContinue'
    GSAToolStart
    if (!(testGSAServices -isPATest $true)) {Exit-GSATool 1}
    if (!(testDeviceStatus)) {Exit-GSATool 1}
    if (!(testGSAClientProfile -profileType "private")) {Exit-GSATool 1}
    if (!(testPrivateAccessRules -FQDNorIP $FQDNorIP -Port $PortNumber -Protocol $Protocol)) {Exit-GSATool 1}
}

Function EntraInternetAccess{
    $ErrorActionPreference = 'SilentlyContinue'
    GSAToolStart
    if (!(testGSAServices)) {Exit-GSATool 1}
    if (!(testDeviceStatus)) {Exit-GSATool 1}
    if (!(testGSAClientProfile -profileType "internet")) {Exit-GSATool 1}
    if (!(testProfileConfig -UserUPN $UserUPN -profileType "internet")) {Exit-GSATool 1}
}

Function PrivateDNS{
    Write-Log -Message "This test isn't ready yet, we are working on it.`n" -ForegroundColor Yellow
    Exit-GSATool
}

Clear-Host
Write-Host "=======================================================" -ForegroundColor Green
Write-Host "`tGlobal Secure Access Troubleshooting Tool"  -ForegroundColor Green 
Write-Host "=======================================================`n" -ForegroundColor Green 
Write-Host "Please submit your feedback at aka.ms/GSAToolFeedback`n" -ForegroundColor Yellow
Write-Host "Enter (1) to troubleshoot Entra Microsoft Traffic`n" -ForegroundColor Green
Write-Host "Enter (2) to troubleshoot Microsoft Entra Internet Access`n" -ForegroundColor Green
Write-Host "Enter (3) to troubleshoot Microsoft Entra Private Access`n" -ForegroundColor Green
Write-Host "Enter (4) to troubleshoot Microsoft Entra Private DNS`n" -ForegroundColor Green
Write-Host "Enter (Q) to Quit`n" -ForegroundColor Green

Add-Content ".\GSATool.log" -Value "`n=======================================================================`n=======================================================================" -ErrorAction SilentlyContinue
if($Error[0].Exception.Message -ne $null){
    if($Error[0].Exception.Message.Contains('denied')){
        Write-Log -Message "Was not able to create log file.`n" -ForegroundColor Yellow
    }else{
        Write-Log -Message "The GSATool.log file has been created`n" -ForegroundColor Yellow
    }
}else{
    Write-Log -Message "The GSATool.log file has been created`n" -ForegroundColor Yellow
}

if (!$TestNumber -and !$TestMicrosoftTraffic -and !$TestPrivateAccess -and !$TestInternetAccess -and !$TestPrivateDNS){
    $TestNumber = Read-Host -Prompt "Please make a selection, and press Enter" 
    While(($TestNumber -ne '1') -AND ($TestNumber -ne '2') -AND ($TestNumber -ne '3') -AND ($TestNumber -ne '4') -AND ($TestNumber -ne 'Q')){
        $TestNumber = Read-Host -Prompt "Invalid input. Please make a correct selection from the above options, and press Enter" 
    }
}

if($TestNumber -eq '1' -or $TestMicrosoftTraffic){
    Write-Log -Message "`nTroubleshoot Entra Microsoft Traffic option has been chosen`n"
    EntraMicrosoft365
}elseif($TestNumber -eq '3' -or $TestPrivateAccess){
    Write-Log -Message "`nTroubleshoot Microsoft Entra Private Access option has been chosen`n"
    EntraPrivateAccess
}elseif($TestNumber -eq '2' -or $TestInternetAccess){
    Write-Log -Message "`nTroubleshoot Microsoft Entra Internet Access option has been chosen`n"
    EntraInternetAccess
}elseif($TestNumber -eq '4' -or $TestPrivateDNS){
    Write-Log -Message "`nTroubleshoot Entra Private DNS option has been chosen`n"
    PrivateDNS
}else{
    Write-Log -Message "`nQuit option has been chosen`n"
    Exit-GSATool
}

Write-Log -Message "`n`n✅ All tests passed successfully. If you have an issue not addressed, please open a support request`n" -ForegroundColor Green -Level SUCCESS
Show-FeedbackAndLog
Start-Process .\