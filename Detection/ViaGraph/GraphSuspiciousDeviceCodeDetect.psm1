<#
MIT License

Copyright (c) 2022 William Overweg. All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
#>


function Get-MsGraphAccessToken {
    Param(
        [Parameter(Mandatory = $True)]
        [System.String]$ClientId,
        [Parameter(Mandatory = $True)]
        [System.String]$ClientSecret,       
        [Parameter(Mandatory = $True)]
        [System.String]$TenantId            
    )

    $Body = @{client_id = $ClientID; client_secret = $ClientSecret; grant_type = "client_credentials"; resource = "https://graph.microsoft.com"; }
    $OAuthReq = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/token" -Body $Body
    $AccessToken = $OAuthReq.access_token
    If ($AccessToken) {
        $global:AccessToken = $AccessToken
    }
    If (!$AccessToken) { 
        Throw "Error retrieving Graph Access Token. Please validate parameter input for -ClientID, -ClientSecret and -TenantId and check API permissions of the (App Registration) client in AzureAD" 
    }
} 

function Get-MsGraphSuspiciousDeviceCodeSigninLogs {
    $URI = 'https://graph.microsoft.com/beta/auditLogs/signIns?$filter=' + "authenticationProtocol eq 'deviceCode' and ((appDisplayName eq 'Microsoft Office') or (appDisplayName eq 'Microsoft Azure PowerShell'))"
    $ReturnValue = Invoke-MsGraphGetRequest -URi $URI
    return $ReturnValue
}

function Invoke-MsGraphGetRequest {
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$URI
    )

    If (!($Global:AccessToken)) {
        Throw "No Access Token found. Please run Get-MsGraphAccessToken or Get-MsGraphAccessTokenInteractive before running this function."
    }
    Else {
        $AccessToken = $Global:AccessToken
    }
    
    If ($Global:DebugMode.Contains('G')) {
        Write-Host "++++++++++++++++++++++++++++++++++++++++++++++++ Debug Message ++++++++++++++++++++++++++++++++++++++++++++++++++++++++" -ForegroundColor Blue
        Write-Host "Invoke-MsGraphGetRequest" -ForegroundColor Blue
        Write-Host $URI -ForegroundColor Blue
    }

    $ReturnValue = $Null
    Try {
        $Result = Invoke-RestMethod -Method Get -Uri $URI -Headers @{"Authorization" = "Bearer $AccessToken" }
    }
    Catch {
        Throw $_
    }

    #Most get requests will return results in .value but not all.. grr... watch out.. having the propery .value doesn't mean it has a value
    if ($Result.PSobject.Properties.name -match "value") {
        $ReturnValue = $Result.value
    }
    else {
        $ReturnValue += $Result
    }

    #By default you only get 100 results... its paged
    While ($Result.'@odata.nextLink') {
        Try {
            $Result = Invoke-RestMethod -Method Get -Uri $Result.'@odata.nextLink' -Headers @{"Authorization" = "Bearer $AccessToken" }
        }
        Catch {
            Throw $_
        }
        $ReturnValue += $Result.value
    }

    return $ReturnValue
}


Export-ModuleMember -Function * -Alias *



























