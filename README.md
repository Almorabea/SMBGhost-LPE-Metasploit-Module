# SMBGhost-LPE-Metasploit-Module
This is an implementation of the CVE-2020-0796 aka SMBGhost vulnerability, compatible with the Metasploit Framework

# Notes:
- This module made to be used when you have a valid shell to escalate your privileges.
- You can change the payload, if you want to have your custom dll shellcode or if you want to encode it in some way.
- The exe file is edited to evade detection and made it applicable to run and inject the dll shellcode.

# Demo 
![](demo.gif)

# Credits
- Credits for exploit authers {Daniel García Gutiérrez,Manuel Blanco Parajón}.
- Credits also for Spencer McIntyre for his greate code too.

# References
- https://github.com/danigargu/CVE-2020-0796
- https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/adv200005
- https://github.com/Almorabea/SMBGhost-WorkaroundApplier
