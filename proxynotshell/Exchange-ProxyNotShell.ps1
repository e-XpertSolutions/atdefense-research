#@Author Simon Thoores for E-xpert Solutions SA

##TO Adapt : 
$IISRoot = "C:\inetpub\logs\LogFiles\"
$PerflogsRoot = "C:\PerfLogs"
$DefaultExchangeProxy="C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy"
$aspnet="C:\inetpub\wwwroot\aspnet_client"

Write-Host "#################################################################" -ForegroundColor Cyan
Write-Host "                       ProxyNotShell Checks" -ForegroundColor Cyan
Write-Host "#################################################################"-ForegroundColor Cyan
Write-Host "Review Output to find suspicious paths added in the configuration" -ForegroundColor Cyan

Write-Host "Display successfull attempt of ProxyNotShell Exploitation (302, 301 or 200)" -ForegroundColor Cyan
$match = Select-String -Path "$IISRoot\W3SVC*\*.log" -Pattern "/autodiscover/autodiscover.json" | where { $_ | Select-String -Pattern '(powershell|X-Rps-CAT)' }
if ($match -eq $null)
{
    Write-Host "Congratulations, no succesfull attempts found" -ForegroundColor Green
}Else {
    Foreach ($i in $match)
    {
        $array=$i.Line.Split(" ")
        if ($array[11] -eq "200" -Or $array[11] -eq "302" -Or $array[11] -eq "301")
        {
            $results = $array[0]+";"+$array[1]+";"+$array[4]+";"+$array[5]+";"+$array[8]+";"+$array[9]+";"+$array[11]
            Write-Output $results
            
        }
    }
    Write-Host "Issues detect, successfull exploitation attempt" -ForegroundColor red
}

Write-Host "List potential suspicious file Aspx Ashx (Rewrite under 15 days)" -ForegroundColor Cyan
$aspx=Get-ChildItem -Path "$DefaultExchangeProxy\owa\auth\*.aspx" -Recurse -Force | where-object {$_.lastwritetime -gt (get-date).addDays(-15) -and -not $_.PSIsContainer}
$ashx=Get-ChildItem -Path "$DefaultExchangeProxy\owa\auth\*.ashx" -Recurse -Force | where-object {$_.lastwritetime -gt (get-date).addDays(-15) -and -not $_.PSIsContainer}
Write-Host "Checking ASPX" -ForegroundColor Cyan
if ($aspx -eq $null)
{
    Write-Host "Congratulations, no rewrited aspx file found" -ForegroundColor Green
}Else {
        Write-Host $aspx -ForegroundColor Red
        Write-Host "Potential suspicious new Rewrite Aspx file, please review" -ForegroundColor Red
}
Write-Host "Checking ASHX" -ForegroundColor Cyan
if ($ashx -eq $null)
{
    Write-Host "Congratulations, no rewrited Ashx file found" -ForegroundColor Green
}Else {
        Write-Host $ashx -ForegroundColor Red
        Write-Host "Potential suspicious new Rewrite Ashx file, please review" -ForegroundColor Red
}

Write-Host "List potential suspicious binary or dll file under PerfLogs" -ForegroundColor Cyan
$perfExe=Get-ChildItem -Path "$PerflogsRoot\*.exe" -Recurse -Force
$perfDll=Get-ChildItem -Path "$PerflogsRoot\*.dll" -Recurse -Force

Write-Host "Checking EXE" -ForegroundColor Cyan
if ($perfExe -eq $null)
{
    Write-Host "Congratulations, No binary found under PerfLogs" -ForegroundColor Green
}Else {
        Write-Host $perfExe -ForegroundColor Red
        Write-Host "Binary found under PerfLogs folder, please Review" -ForegroundColor Red
}
Write-Host "Checking DLL" -ForegroundColor Cyan
if ($perfDll -eq $null)
{
    Write-Host "Congratulations, No DLL found under PerfLogs" -ForegroundColor Green
}Else {
        Write-Host $perfDll -ForegroundColor Red
        Write-Host "DLL found under PerfLogs folder, please Review" -ForegroundColor Red
}
Write-Host "Check if ashx file under apnet_client" -ForegroundColor Cyan
$aspnet_ashx=Get-ChildItem -Path "$aspnet\*.ashx" -Recurse -Force

if ($aspnet_ashx -eq $null)
{
    Write-Host "Congratulations, No ASHX found under aspnet_client" -ForegroundColor Green
}Else {
        Write-Host $aspnet_ashx -ForegroundColor Red
        Write-Host "ASHX found under aspnet_client folder, please Review" -ForegroundColor Red
}

Write-Host "#################################################################" -ForegroundColor Cyan
Write-Host  "                       ProxyNotShell Checks" -ForegroundColor Cyan
Write-Host "#################################################################" -ForegroundColor Cyan
