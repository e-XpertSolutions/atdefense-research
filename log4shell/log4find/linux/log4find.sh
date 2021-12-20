#!/bin/sh

LOG4FIND_VER="2.1"
PROCESS_NAME="java"
LIB="log4j.+\.jar"
LIBNAME="log4j"
VULN_VERS_RCE="^(2\.[0-9]$)|(2\.1[01234]$)"
VULN_VERS_DOS="^(2\.1[56]$)"
EXPLOIT='${jndi:'

display_cmd () {
    # Extract process command line
    PID=$1
    CMD=$(ps -p $PID -o 'cmd' | tail -n 1)
    echo "    [*] Process details:"
    echo "      $CMD"
}

forensic_logs() {
    # Search log files in process file descriptors
    PID=$1
    for l in $(ls -al /proc/$PID/fd | grep -i -o -E ' [^ ]+\.log[^ ]*$' | tr -d ' ')
    do
        # Search exploitation pattern
        grep -i "$EXPLOIT" $l > /dev/null
        if [ $? -eq 0 ]; then
            printf "\033[91m      [EXPLOIT] '$l' \033[0m \n"
        else
            printf "\033[32m      [OK] '$l' \033[0m \n"
        fi
    done
}

echo "                                                 ";
echo "    __                __ __  _______           __";
echo "   / /   ____  ____ _/ // / / ____(_)___  ____/ /";
echo "  / /   / __ \/ __ \`/ // /_/ /_  / / __ \/ __  / ";
echo " / /___/ /_/ / /_/ /__  __/ __/ / / / / / /_/ /  ";
echo "/_____/\____/\__, /  /_/ /_/   /_/_/ /_/\__,_/   ";
echo "            /____/                               ";
echo "                                                 ";
echo " ==> By e-Xpert Solutions  (Michael Molho)       ";
echo " ==> Version: $LOG4FIND_VER                      ";
echo "                                                 ";

# Search for Java processes
NB_FOUND=$(ps -C "$PROCESS_NAME" -o pid | grep -v PID | wc -l)
if [ $NB_FOUND -eq 0 ]; then
    printf "\n\033[32m  No $PROCESS_NAME process found. This one is safe  ;-) \033[0m \n\n"
    exit
fi

# Inspect each Java process to search for log4j lib
printf "\n  $NB_FOUND process $PROCESS_NAME found, inspecting ... \n"
for PID in $(ps -C "$PROCESS_NAME" -o pid | grep -v PID)
do
    # Search for matching jars in process file descriptors
    FOUND_FD=$(ls -l /proc/$PID/fd | grep -E -i "$LIB" | wc -l)
    # Search for log4j trace in commandline
    FOUND_CMD=$(ps -p $PID -o 'cmd' | tail -n 1 | grep -E -i "$LIBNAME" | wc -l)
    if [ $FOUND_FD -gt 0 -o $FOUND_CMD -gt 0 ]; then
        printf "\n \033[33m [PID:$PID] *WARNING* log4j lib usage detected \033[0m \n"
        display_cmd $PID
        # Display log4j lib files in use
        echo "    [*] log4j jar files in use: "
        for f in $(ls -l /proc/$PID/fd | grep -E -i "$LIB" | grep -o -E '/.+$')
        do
            # Try to extract version from file name
            LOG4J_VERS=$(basename "$f" | grep -E -o '\-[0-9]+\.[0-9]+' | tr -d '\-')
            # Version extraction failed
            if [ -z "$LOG4J_VERS" ]; then
                printf "\033[33m      - [???:TOCHECK] $f \033[0m \n"
            # Detect vulnerable versions
            else
                # Versions vulnerable to RCE
                echo "$LOG4J_VERS" | grep -E "$VULN_VERS_RCE" > /dev/null
                if [ $? -eq 0 ]; then
                    printf "\033[91m      - [$LOG4J_VERS:VULN-RCE] $f \033[0m \n"
                else
                    # Versions vulnerable to Deny of Service
                    echo "$LOG4J_VERS" | grep -E "$VULN_VERS_DOS" > /dev/null
                    if [ $? -eq 0 ]; then
                        printf "\033[91m      - [$LOG4J_VERS:VULN-DOS] $f \033[0m \n"
                    else
                        # Not vulnerable version
                        printf "\033[32m      - [$LOG4J_VERS:OK] $f \033[0m \n"
                    fi
                fi
            fi
        done
        echo "    [*] Looking for potential previous exploitation in open files:"
        forensic_logs $PID
    else
        # log4find does not look to be used, check for log files anyways ..
        printf "\n \033[32m [PID:$PID] log4j does not seem to be used here \033[0m \n"
        display_cmd $PID
        echo "    [*] Looking for potential previous exploitation in open files:"
        forensic_logs $PID
    fi
done

printf "\n\n This program is distributed for free without any warranty, use at your own risk \n\n"

