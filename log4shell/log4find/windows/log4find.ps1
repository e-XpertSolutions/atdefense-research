###########################################
# Log4j - Windows forensic script
# Must be run as Admin with Sysinternals tools installed 
#
# David Routin - 13.12.2021
#

$srv = hostname
$proc = "*java*"
$pattern_log4j = "log4j"
$pattern_forensic = "jndi:"
$pattern_logfiles = ".log"
$handle_exe_path = '\\READ_ONLY_SHARE\sysinternals\handle.exe'
# 0 = False, 1 = True
$deployment_with_gpo = 0
$centralized_unc = "\\WRITABLE_SHARE\$srv-log4jensic.txt"

# Test handle.exe is accessible
if ((Test-Path $handle_exe_path) -eq $false) {
    write-host "Handle.exe not accessible... Please download from sysinternals, leaving"
    exit
}


#Exit if deployment with gpo is selected and file already exists
if (($deployment_with_gpo -eq 1) -And ( Test-Path $centralized_unc)) {
    exit
}

if ($deployment_with_gpo -eq 1) {
    echo "Starting..." | Out-File -FilePath $centralized_unc
}

$Log4js = @()
$LogFiles = @()
$exploited = @()

# Check process name based on java pattern
$result_java_ids = Get-Process -Name $proc

If ($result_java_ids -ne $null) {

    Write-Host $result_java_ids.Length process JAVA found

    $result_java_ids | Foreach-Object { 

		$id_process = $_.Id
		$query = "SELECT CommandLine FROM Win32_Process WHERE ProcessID = "+ $id_process
		$CommandLines = (Get-WmiObject -Query $query).CommandLine -join "`r`n"

		### Getting handles for each PID and looking for log4j

        $command_handle = $handle_exe_path+" -accepteula -p " + $id_process
        $cmd_output = cmd /c $command_handle | Select-String -Pattern 'File .+?:'

        if ($cmd_output -match $pattern_log4j ) {
            Write-Host -Foregroundcolor red "`n[WARNING][LOG4J] Lib usage detected "
        } else {
            Write-Host -Foregroundcolor green "`n[INFO][JAVA] detected without log4j (unsure) "
            
        }
        
        Write-Host `t`tPID: $id_process - $CommandLines 

        foreach ($line in $cmd_output) {
            if ($line -match $pattern_log4j ) {
                    $log4j_temp = [regex]::match($line, "File.+?\s+(\S+)?\s+(?<filename>.+?)$").Groups["filename"].Value
                    
                    Write-Host -Foregroundcolor red `t`t[LOG4J_PATH] $log4j_temp

                    $Log4js += $log4j_temp
            }
            if ($line -match $pattern_logfiles ) {
                    $LogFile = [regex]::match($line, "File.+?\s+(\S+)?\s+(?<filename>.+?)$").Groups["filename"].Value
                    $LogFiles += $LogFile
                    $exploited_res = Get-Childitem -Path $LogFile| Select-String -pattern $pattern_forensic
                    $exploited += $exploited_res
                    Write-Host -Foregroundcolor green `t`t[OK] $LogFile
            }

        } 

    }

    
    if ( $deployment_with_gpo -eq 1 ) {
       if ($Log4js -ne $null) {
                    $Log4js = $Log4js | sort -unique
                    echo "[WARNING][Log4j] DETECTED in:" | Out-File -FilePath $centralized_unc -Append
                    $Log4js = $Log4js -join "`r`n"
                    echo $Log4js | Out-File -FilePath $centralized_unc -Append
       }
   
       if ($LogFiles -ne $null) {
                    $LogFiles = $LogFiles | sort -unique
                    echo "`n[INFO][Logfiles] Identified LogFiles:" | Out-File -FilePath $centralized_unc -Append
                    $LogFiles = $LogFiles -join "`r`n"
                    echo $LogFiles | Out-File -FilePath $centralized_unc -Append
       }

       #### Looking for track of exploitations in LogFiles

    }

    if ($exploited -ne $null) {
                $exploited = $exploited | sort -unique
                Write-Host -Foregroundcolor red "`n[CRITICAL][EXPLOIT] DETECTED in:" 
                $exploited = $exploited -join "`r`n"
                Write-Host $exploited 
                if ( $deployment_with_gpo -eq 1 ) {
                    echo "`n[CRITICAL][EXPLOIT] DETECTED in:"  | Out-File -FilePath $centralized_unc -Append
                    echo $exploited | Out-File -FilePath $centralized_unc -Append
                }
    }

} else {
    Write-Host -Foregroundcolor green "[INFO][JAVA] No process found"
}


