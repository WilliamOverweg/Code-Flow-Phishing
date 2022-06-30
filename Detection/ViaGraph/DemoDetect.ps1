import-module .\Detection\ViaGraph\GraphSuspiciousDeviceCodeDetect.psm1 -force
$clientId = "yourclientid"
$clientSecret = "yourclientsecret"
$tenantId = "yourtenantid"

Get-MsGraphAccessToken -ClientId $clientId -ClientSecret $clientSecret -TenantId $tenantId  
$logs = Get-MsGraphSuspiciousDeviceCodeSigninLogs