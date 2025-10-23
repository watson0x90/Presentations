## SaintCon 2025
### Password!AtTheDisco

- [Project](https://github.com/watson0x90/PasswordAtTheDisco)
- [Slides](./saintcon_2025/20251025_SaintCon_PasswordAtTheDisco.pdf)

#### Description

"Password! At The Disco" is a detailed presentation aimed at security professionals and penetration testers. It combines educational content about NTLM authentication vulnerabilities with practical demonstrations of the Password! At The Disco auditing tool. The presentation consists of 60 slides, that guide attendees through the evolution of NTLM from its origins in 1993. It explains why NTLM remains prevalent in modern Windows environments despite its known weaknesses and demonstrates practical password-cracking techniques using Hashcat.

The primary value of this presentation lies in introducing the Password! At The Disco tool as a solution to a critical gap in traditional password auditing workflows. Instead of merely providing statistics on cracked passwords, the tool integrates with BloodHound Community Edition to automatically query privilege information for each compromised account. It calculates risk scores based on both password weaknesses and Active Directory privileges. This context-aware approach transforms raw cracking results into actionable intelligence by identifying which weak passwords present the greatest threat based on Domain Admin paths, object control counts, and group memberships.

## BSides SLC 2025
### Dirtly Little .NET Hooker 

- [Slides](./bsides_slc_2025/2025BSides_Dirty_Little_DotNet_Hooker.pdf)
- [Demo Code](./bsides_slc_2025/demo_code/)

#### Description

In this presentation, we will delve into the powerful capabilities of Frida, an open-source dynamic instrumentation toolkit. We will specifically focus on its application in hooking .NET applications from a red team perspective. Attendees will learn about the architecture of .NET applications and the challenges associated with reverse engineering and exploitation.

We will demonstrate how to set up Frida to manipulate .NET applications in real time, showcasing techniques for intercepting API calls, modifying application behavior, and extracting sensitive data. The presentation will cover practical use cases, including bypassing security measures, analyzing application flow, and uncovering vulnerabilities.
