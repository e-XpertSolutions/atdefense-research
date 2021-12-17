
## Log4j Suricata rules

Suricata rules to detect successful exploitation of Log4Shell vulnerability (CVE-2021-44228)

### Detection logic

Instead of trying to detect the exploitation initial payload ("${jndi: ...}"), these rules target the 2nd stage of the attack, where the compromised system will fetch malicious payload through LDAP/RMI/IIOP from Internet. Indeed, detecting the initial payload will flood you with noise from Internet since this attack is actively exploited worldwide. Instead, these signatures focus not on the initial exploitation attempt but on the traffic generated while the vulnerability has triggered on a system. Basically these rules detect LDAP bind/unbind/search traffic from internal network to Internet as well as RMI call and IIOP request. 

### False Positives 

These rules does not include specific malicious payload, they match any LDAP/RMI/IIOP traffic from an internal network to Internet (even on non standard ports). Therefore, they can lead to false positives in case you have internal servers doing such queries through Internet. However, once you excluded such servers, any others matches should alert you about a possible successful exploitation of Log4Shell. 

### Requirements 

- Suricata IDS 
- The variables HOME_NET and EXTERNAL_NET must be set up properly to ensure accuracy and lower false positive ration.

### Limitations

These rules detect the LDAP/RMI/IIOP 2nd stage. Log4Shell can also be potentially exploited through LDAPS and others protocols. These rules wont detect these cases. However, from our current observation, so far LDAP/RMI is used at > 90%.

### Authors 

-   [eXpert Solutions] David Routin (@rewt_1)
-   [eXpert Solutions] Marc Gayraud (@mgasecu)
-   [eXpert Solutions] Michael Molho (@peacand)
