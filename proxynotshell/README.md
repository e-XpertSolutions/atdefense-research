## At-Defense ProxyNotShell
*(Author Simon Thoores)*

![KevinBeaumont Logo](https://miro.medium.com/max/1400/1*6Ay_Mt1ikoTKAHgHTJcfMQ.png)
This repository contains a Threat Hunting tool related to ProxyNotShell vulnerabilities (CVE-2022-41040 (SSRF) & CVE-2022-41082 (RCE)).

This tool is provided for free for anyone to use without any guarantee and is based on the current information we were able to analze and extract from various ressources.

# The tool will perform the following actions :

- Review IIS logs and look for the following pattern : "/autodiscover/autodiscover.json"  with "PowerShell" and "X-Rps-CAT"
- Check for ASPX and ASHX file modified during the last 15 days under "C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\ and siblings
- Check for EXE or DLL under "C:\PerfLogs\"
- Check for ASHX file under C:\inetpub\wwwroot\aspnet_client\

** Before running the tool be sure to review the code and align Path with your setup and installation.**

## Ressources and sources :
[GTSC Official realease](https://www.gteltsc.vn/blog/warning-new-attack-campaign-utilized-a-new-0day-rce-vulnerability-on-microsoft-exchange-server-12715.html)
[Microsoft](https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/)
[Kevin Beaumont](https://doublepulsar.com/proxynotshell-the-story-of-the-claimed-zero-day-in-microsoft-exchange-5c63d963a9e9)
[Huntress Lab](https://www.huntress.com/blog/new-0-day-vulnerabilities-found-in-microsoft-exchange)

