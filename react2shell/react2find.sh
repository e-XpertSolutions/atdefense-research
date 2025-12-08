#!/bin/sh

# Searches vulnerable nextjs / react-server versions

# Attention : grep -E = ERE POSIX -> pas de (?: ... ), juste (...)
NEXT_VULN_VERS='^(15\.0\.[0-4]|15\.1\.[0-8]|15\.2\.[0-5]|15\.3\.[0-5]|15\.4\.[0-7]|15\.5\.[0-6]|16\.0\.[0-6]|14\.[3-9]\.[0-9]-canary\.(7[7-9]|[8-9][0-9]|[1-9][0-9]{2,}))$'
REACT_VULN_VERS='^(19\.0\.0|19\.1\.0|19\.1\.1|19\.2\.0)$'

cat << "EOF"

  _____  ______          _____ _______ ___  ______ _____ _   _ _____
|  __ \|  ____|   /\   / ____|__   __|__ \|  ____|_   _| \ | |  __ \
| |__) | |__     /  \ | |       | |     ) | |__    | | |  \| | |  | |
|  _  /|  __|   / /\ \| |       | |    / /|  __|   | | | . ` | |  | |
| | \ \| |____ / ____ \ |____   | |   / /_| |     _| |_| |\  | |__| |
|_|  \_\______/_/    \_\_____|  |_|  |____|_|    |_____|_| \_|_____/


A quick Linux-based NPM package dependency checker
EOF

printf "\n Looking for package listing files..."

# Search for package-lock.json files (silence permission errors)
FOUND=$(find / -name "package-lock.json" 2>/dev/null)

# Validate files were found
if [ -z "$FOUND" ]; then
    printf "\n\033[32m  No npm package-lock.json found, meaning no Next.js vulnerability exposition ! \033[0m \n\n"
    exit 0
else
    printf "\n\033[33m  At least one package-lock.json file was found \033[0m \n\n"
fi

# Count files (approx, paths with spaces will break, same limitation as avant)
NUMSPACE=$(echo $FOUND | tr -cd ' ' | wc -c)
NUMFILE=$(echo "$NUMSPACE + 1" | bc)
printf "\n  $NUMFILE package-lock.json found, inspecting to check dependencies... \n"

# Variable to keep a global report of vulnerable apps
VULN_REPORT=""

for JSONPATH in $FOUND
do
    printf "\n\033[34mInspecting: $JSONPATH\033[0m\n"

    APP_DIR=$(dirname "$JSONPATH")
    APP_NAME=""

    # Try to get application name from package.json in the same directory
    if [ -f "$APP_DIR/package.json" ]; then
        APP_NAME=$(grep '"name"' "$APP_DIR/package.json" 2>/dev/null \
            | head -n1 \
            | sed -E 's/.*"name"[[:space:]]*:[[:space:]]*"(.*?)".*/\1/')
    fi
    [ -z "$APP_NAME" ] && APP_NAME="(unknown app name)"

    # Per-file vulnerable dependencies (for summary)
    FILE_VULN_DEPS=""

    #########################
    # Extract versions from package-lock.json
    # On prend la PREMIÈRE occurrence uniquement (-m1 / head -n1)
    #########################

    NEXTJS_VER=$(grep -m1 '"next"' "$JSONPATH" 2>/dev/null \
        | sed -E 's/.*"next"[[:space:]]*:[[:space:]]*"(.*?)".*/\1/')

    REACTDOM_TURBO_VER=$(grep -m1 '"react-server-dom-turbopack"' "$JSONPATH" 2>/dev/null \
        | sed -E 's/.*"react-server-dom-turbopack"[[:space:]]*:[[:space:]]*"(.*?)".*/\1/')

    REACTDOM_WEBPACK_VER=$(grep -m1 '"react-server-dom-webpack"' "$JSONPATH" 2>/dev/null \
        | sed -E 's/.*"react-server-dom-webpack"[[:space:]]*:[[:space:]]*"(.*?)".*/\1/')

    REACTDOM_PARCEL_VER=$(grep -m1 '"react-server-dom-parcel"' "$JSONPATH" 2>/dev/null \
        | sed -E 's/.*"react-server-dom-parcel"[[:space:]]*:[[:space:]]*"(.*?)".*/\1/')

    # Nettoyage éventuel des ^ ou ~ si ça venait d'un package.json ou lock exotique
    NEXTJS_VER=${NEXTJS_VER#^}
    NEXTJS_VER=${NEXTJS_VER#~}
    REACTDOM_TURBO_VER=${REACTDOM_TURBO_VER#^}
    REACTDOM_TURBO_VER=${REACTDOM_TURBO_VER#~}
    REACTDOM_WEBPACK_VER=${REACTDOM_WEBPACK_VER#^}
    REACTDOM_WEBPACK_VER=${REACTDOM_WEBPACK_VER#~}
    REACTDOM_PARCEL_VER=${REACTDOM_PARCEL_VER#^}
    REACTDOM_PARCEL_VER=${REACTDOM_PARCEL_VER#~}

    #########################
    # Check NEXTJS
    #########################
    if [ -n "$NEXTJS_VER" ]; then
        printf "\033[33m Dependency to next found in $JSONPATH (app: $APP_NAME), checking if version is vulnerable... \033[0m \n"
        printf "        detected version: %s\n" "$NEXTJS_VER"

        echo "$NEXTJS_VER" | grep -E "$NEXT_VULN_VERS" >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            printf "\033[91m      - [next@$NEXTJS_VER: VULNERABLE] \033[0m \n"
            FILE_VULN_DEPS="$FILE_VULN_DEPS\n    - next@$NEXTJS_VER"
        else
            printf "\033[32m      - [next@$NEXTJS_VER: OK] \033[0m \n"
        fi
    fi

    #########################
    # Check react-server-dom-turbopack
    #########################
    if [ -n "$REACTDOM_TURBO_VER" ]; then
        printf "\033[33m Dependency to react-server-dom-turbopack found in $JSONPATH (app: $APP_NAME), checking if version is vulnerable... \033[0m \n"
        printf "        detected version: %s\n" "$REACTDOM_TURBO_VER"

        echo "$REACTDOM_TURBO_VER" | grep -E "$REACT_VULN_VERS" >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            printf "\033[91m      - [react-server-dom-turbopack@$REACTDOM_TURBO_VER: VULNERABLE] \033[0m \n"
            FILE_VULN_DEPS="$FILE_VULN_DEPS\n    - react-server-dom-turbopack@$REACTDOM_TURBO_VER"
        else
            printf "\033[32m      - [react-server-dom-turbopack@$REACTDOM_TURBO_VER: OK] \033[0m \n"
        fi
    fi

    #########################
    # Check react-server-dom-webpack
    #########################
    if [ -n "$REACTDOM_WEBPACK_VER" ]; then
        printf "\033[33m Dependency to react-server-dom-webpack found in $JSONPATH (app: $APP_NAME), checking if version is vulnerable... \033[0m \n"
        printf "        detected version: %s\n" "$REACTDOM_WEBPACK_VER"

        echo "$REACTDOM_WEBPACK_VER" | grep -E "$REACT_VULN_VERS" >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            printf "\033[91m      - [react-server-dom-webpack@$REACTDOM_WEBPACK_VER: VULNERABLE] \033[0m \n"
            FILE_VULN_DEPS="$FILE_VULN_DEPS\n    - react-server-dom-webpack@$REACTDOM_WEBPACK_VER"
        else
            printf "\033[32m      - [react-server-dom-webpack@$REACTDOM_WEBPACK_VER: OK] \033[0m \n"
        fi
    fi

    #########################
    # Check react-server-dom-parcel
    #########################
    if [ -n "$REACTDOM_PARCEL_VER" ]; then
        printf "\033[33m Dependency to react-server-dom-parcel found in $JSONPATH (app: $APP_NAME), checking if version is vulnerable... \033[0m \n"
        printf "        detected version: %s\n" "$REACTDOM_PARCEL_VER"

        echo "$REACTDOM_PARCEL_VER" | grep -E "$REACT_VULN_VERS" >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            printf "\033[91m      - [react-server-dom-parcel@$REACTDOM_PARCEL_VER: VULNERABLE] \033[0m \n"
            FILE_VULN_DEPS="$FILE_VULN_DEPS\n    - react-server-dom-parcel@$REACTDOM_PARCEL_VER"
        else
            printf "\033[32m      - [react-server-dom-parcel@$REACTDOM_PARCEL_VER: OK] \033[0m \n"
        fi
    fi

    # If at least one vulnerable dep in this file, add to global report
    if [ -n "$FILE_VULN_DEPS" ]; then
        VULN_REPORT="$VULN_REPORT\n\n[APP] $APP_NAME\n[LOCKFILE] $JSONPATH\n[VULNERABLE DEPS]$FILE_VULN_DEPS"
    fi

done

# Final summary
if [ -n "$VULN_REPORT" ]; then
    printf "\n\n\033[91mSummary of vulnerable applications:\033[0m\n"
    # %b => interprète les \n comme des retours à la ligne
    printf "%b\n" "$VULN_REPORT"
else
    printf "\n\n\033[32mNo vulnerable dependencies found in any package-lock.json.\033[0m\n"
fi
printf "\n\n This program is distributed for free without any warranty or support, use at your own risk \n\n"
