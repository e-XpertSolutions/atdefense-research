## Log4Find

Log4Find is a simple scanning tool to detect vulnerable and/or compromised systems to  Log4Shell vulnerability (CVE-2021-44228).

## Usage

There are two binaries : one for **Linux** systems and another one for **Windows** systems. Please refer to the doc in the proper folders "windows" and "linux" inside this project for more information.

## Detection logic

The main idea with Log4Find is to discover potential vulnerable/exploited Java processes **running** on a machine. For that, Log4Find looks at the processes command line and the file descriptors of each running Java processes to discover JAR files loaded as well as log files opened.

From there, it tries to detect log4j version from JAR files names and alert if a vulnerable version is found to be used.

Finally, Log4Find looks at the open log files in order to detect exploitation patterns to confirm possible machine compromission.

## Limitation

Log4Find relies on scanning command lines and file descriptors of running Java processes to discover log4j usage and log files.

This approach has been tested on many systems and has been seen to be quite reliable. It also has the advantages to be simple, independant from the Java applications and to be highly portable accross Linux distributions and Windows.

**HOWEVER**: there is no garantee that Log4Find will not miss a vulnerable Java service.

There might be few cases where this approach will not work, such as :
- Java process not running when starting Log4Find
- Nested JAR
- Log4j lib renammed to a random name

Also, Log4Find can report a vulnerable Java application which is actually not due to specific configuration or context.

Keep in mind that this tool is not perfect but is a good starting point for your investigation.

## Possible improvements

- Migrate the detection logic to osquery ??
- Detect log4j in nested Jars
- Search for exploitation pattern in logs directory + search in compressed files
- Extract log4j version also from command line arguments

## Authors

- [eXpert Solutions] Michael Molho (research/Linux/Windows)
- [eXpert Solutions] David Routin (Windows)

## Contribution

These scripts have been developped quickly ! We know there are tons of possible improvements. Please feel free to contribute by submitting PR. Just keep in mind that these scripts must remain as standard as possible (100% POSIX shell script for Linux, standard Powershell for Windows) 



