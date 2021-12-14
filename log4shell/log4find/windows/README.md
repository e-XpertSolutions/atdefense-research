

## Requirements

 - Run on potentially any Windows based system using Powershell
 - Tested successfully on Windows 2012 Server and Windows 2016
 - Administrator rights
 - Presence of "handle.exe" from Microsoft Sysinternals ([Handle - Windows Sysinternals | Microsoft Docs])(https://docs.microsoft.com/en-us/sysinternals/downloads/handle)
 - One READ_ONLY network share to host the "handle.exe" binary, with "Domain Users" and "Domain Computers" included (both on network share and file system security properties). **Pay attention to the fact that allowing write in this share may represent a high security risk as it may allow any attacker to modify this file and run arbitrary command as SYSTEM on all your environment.**

## Usage

Before use, please read the "***Configuration***" part bellow

Local usage from a CMD shell as Administrator (default):

`powershell -ExecutionPolicy Bypass -File log4find.ps1`
    
Deployed on a whole domain usage : Follow the "***Configuration***" part and the section "**For large scale deployment (on a whole domain for example)**"

## Configuration

You must configure different variables for the script to run properly.

**In any case:**
 - The following variable is the UNC path to your "handle.exe" binary. This UNC path must be configured with the following requirements (READ_ONLY for "Domain Users" and "Domain Computers")
 
`$handle_exe_path = '\\READ_ONLY_SHARE\sysinternals\handle.exe -accepteula'`

**For large scale deployment (on a whole domain for example):**
You must configure an additional network share to host outputs from your machines. In such a case, this network share must have READ and WRITE permissions for both "Domain Users" and "Domain Computers" at network share security level and file system level. In this situation you must set the following variables:

    $deployment_with_gpo = 1
    $centralized_unc = "\\WRITABLE_SHARE\$srv-log4jensic.txt"

Then you have to copy the log4find.ps1 

The easiest deployment process can be performed using Scheduled Task (GPO). For this you can follow the procedure below (extracted from https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-endpoints-gp?view=o365-worldwide and modified)

1.  **Copy "log4find.ps1" in the READ_ONLY share** you created at first (not the READ/WRITE one) 
2. To create a new GPO, open the  [Group Policy Management Console](https://docs.microsoft.com/en-us/internet-explorer/ie11-deploy-guide/group-policy-and-group-policy-mgmt-console-ie11)  (GPMC), right-click  **Group Policy Objects**  you want to configure and click  **New**. Enter the name of the new GPO in the dialogue box that is displayed and click  **OK**.
    
3.  Open the  [Group Policy Management Console](https://docs.microsoft.com/en-us/internet-explorer/ie11-deploy-guide/group-policy-and-group-policy-mgmt-console-ie11)  (GPMC), right-click the Group Policy Object (GPO) you want to configure and click  **Edit**.
    
4.  In the  **Group Policy Management Editor**, go to  **Computer configuration**, then  **Preferences**, and then  **Control panel settings**.
    
5.  Right-click  **Scheduled tasks**, point to  **New**, and then click  **Immediate Task (At least Windows 7)**.
    
6.  In the  **Task**  window that opens, go to the  **General**  tab. Under  **Security options**  click  **Change User or Group**  and type SYSTEM and then click  **Check Names**  then  **OK**. NT AUTHORITY\SYSTEM appears as the user account the task will run as.
    
7.  Select  **Run whether user is logged on or not**  and check the  **Run with highest privileges**  check box.
    
8.  In the Name field, type an appropriate name for the scheduled task (for example, **Log4jfind**).
    
9.  Go to the  **Actions**  tab and select  **New...**  Ensure that  **Start a program**  is selected in the  **Action**  field. Enter the following in the  

 "Program/script:" 

    powershell.exe 

 "Add arguments:" 

    -ExecutionPolicy Bypass -File \\READ_ONLY_SHARE\log4find.ps1

    
11.  Select  **OK**  and close any open GPMC windows.
    
12.  To link the GPO to an Organization Unit (OU), right-click and select  **Link an existing GPO**. In the dialogue box that is displayed, select the Group Policy Object that you wish to link. Click  **OK**.

