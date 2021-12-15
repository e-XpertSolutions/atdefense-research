###########################################
# Log4shell analysis script
# Must be run as Admin after having downloaded Sysinternals Handle.exe tool 
#
# David Routin
# Michael Molho
#

# Parse parameters
param($handlepath, $loggingdir)

# Config
$log4find_ver = "2.0"
$pattern_log4j = "log4j"
$pattern_forensic = "jndi:"
$pattern_logfiles = "\.log|\.txt"
$log4j_vuln_vers = "^(2\.[0-9]$)|(2\.1[01234]$)"

# Test handle.exe is accessible
if ( !$PSBoundParameters.ContainsKey('handlepath') ) {
	Write-Host "ERROR: Parameter -HandlePath is required"
	Write-Host "Download handle.exe from Sysinternal first (https://docs.microsoft.com/en-us/sysinternals/downloads/handle) and give this file path as parameter -HandlePath"
	Write-Host "Examples:"
	Write-Host "    .\log4find.ps1 -HandlePath C:\handle.exe"
	Write-Host "    .\log4find.ps1 -HandlePath \\fileserver\RO_share\handle.exe -LoggingDir \\fileserver\RW_share\"
	exit
}
if ( !(Test-Path $handlepath) ) {
    Write-Host "ERROR: File '$handlepath' cannot be read, please check the path is correct"
    exit
}

# Test loggingdir exists
if ( ($PSBoundParameters.ContainsKey('loggingdir')) -And !(Test-Path $loggingdir) ) {
	Write-Host "ERROR: Log directory '$loggingdir' does not exist"
	exit
}

# Build logging file path from hostname + loggingdir
$loggingpath = ""
if ( $PSBoundParameters.ContainsKey('loggingdir') ) {
    $hostname = hostname
    $loggingpath = "${loggingdir}\\${hostname}.log"
}

#Exit if centralized logging is enabled and log file already exists
if ( ($PSBoundParameters.ContainsKey('loggingdir')) -And (Test-Path $loggingpath) ) {
    Write-Host "The script has run already, exiting ..."
	exit
}

# Function for centralized logging
function Log-Central {
    param (
        [string]$msg,
		[string]$color,
		[string]$loggingpath
    )
	# Display console
	if ( $color ) {
		Write-Host -Foregroundcolor $color $msg
	} else {
		Write-Host $msg
	}
	
	# Central logging if enabled
	if ( $loggingpath ) {
		$timestamp = Get-Date -Format "MM/dd/yyyy HH:mm"
		echo "[${timestamp}] $msg"  | Out-File -FilePath $loggingpath -Append
	}
}

echo "                                                 ";
echo "    __                __ __  _______           __";
echo "   / /   ____  ____ _/ // / / ____(_)___  ____/ /";
echo "  / /   / __ \/ __ \`/ // /_/ /_  / / __ \/ __  / ";
echo " / /___/ /_/ / /_/ /__  __/ __/ / / / / / /_/ /  ";
echo "/_____/\____/\__, /  /_/ /_/   /_/_/ /_/\__,_/   ";
echo "            /____/                               ";
echo "                                                 ";
echo " ==> By e-Xpert Solutions  (David Routin/Michael Molho)";
echo " ==> Version: $log4find_ver                      ";
echo "                                                 ";

# Check process name based on java patterns
$result_java_ids = Get-Process "*java*", "*tomcat*", "*apache*"

If ($result_java_ids) {

    $nb_proc = $result_java_ids.Length
    Log-Central -LoggingPath $loggingpath -Msg "$nb_proc process JAVA found`n"

    $result_java_ids | Foreach-Object { 

        # Get process commandline from WMI
		$pid_process = $_.Id
		$query = "SELECT CommandLine FROM Win32_Process WHERE ProcessID = "+ $pid_process
		$CommandLine = (Get-WmiObject -Query $query).CommandLine 

		### Get files handles 
        $command_handles = $handlepath + " -accepteula -p " + $pid_process
        $handles_output = cmd /c $command_handles | Select-String -Pattern 'File .+?:'

        ### Detect log4 in handles or in commandline
        if ( ($handles_output -match $pattern_log4j) -or ($CommandLine -match $pattern_log4j) ) {
            Log-Central -LoggingPath $loggingpath -Color yellow -Msg "[PID:$pid_process] *WARNING* log4j lib usage detected"
        } else {
            Log-Central -LoggingPath $loggingpath -Color green -Msg "[PID:$pid_process] log4j does not seem to be used here"
        }
        
		# Display process commandline
        Log-Central -LoggingPath $loggingpath -Msg "  [*] Process details:"
		Log-Central -LoggingPath $loggingpath -Msg "    $CommandLine"

        # Loop through all file handles looking for log4j
		Log-Central -LoggingPath $loggingpath -Msg "  [*] log4j jar files in use:"
        foreach ($line in $handles_output) {
            if ($line -match $pattern_log4j ) {
                    $log4j_path = [regex]::match($line, "File.+?\s+(\S+)?\s+(?<filename>.+?)$").Groups["filename"].Value
					# Try to detect lib4j version from filename
					$log4j_fname = Split-Path $log4j_path -leaf
					$log4j_vers_match = [regex]::match($log4j_fname, "\-([0-9]+\.[0-9]+)")
					if ( $log4j_vers_match.Success ) {
						$log4j_vers = $log4j_vers_match.Groups[1].Value
						# Detect vulnerable version
						if ( $log4j_vers -match $log4j_vuln_vers ) {
						    Log-Central -LoggingPath $loggingpath -Color red -Msg "    [${log4j_vers}:VULN] $log4j_path"
					    } else {
							Log-Central -LoggingPath $loggingpath -Color green -Msg "    [${log4j_vers}:OK] $log4j_path"
						}
					} else {
                        Log-Central -LoggingPath $loggingpath -Color yellow -Msg "    [???:TOCHECK] $log4j_path"
					}
            }
        } 
		
		# Loop through all file handles looking for log files / exploitation traces
		Log-Central -LoggingPath $loggingpath -Msg "  [*] Looking for potential previous exploitation in open files:"
		foreach ($line in $handles_output) {
            if ($line -match $pattern_logfiles ) {
				    $LogFile = [regex]::match($line, "File.+?\s+(\S+)?\s+(?<filename>.+?)$").Groups["filename"].Value
                    $exploited = Get-Childitem -Path $LogFile | Select-String -pattern $pattern_forensic
					if ( $exploited ) {
                        Log-Central -LoggingPath $loggingpath -Color red -Msg "    [EXPLOIT] $LogFile"
				    } else {
						Log-Central -LoggingPath $loggingpath -Color green -Msg "    [OK] $LogFile"
					}
            }
        }

    }

} else {
    Log-Central -LoggingPath $loggingpath -Color green -Msg "No java' process found. This one is safe  ;-) `n"
}


