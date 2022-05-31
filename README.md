# BeatRev

![](BeatRev.gif)

## TLDR
The first time the malware runs on a victim it AES encrypts the actual payload using environmental data from that victim.  Each subsequent time the malware is ran it gathers that same environmental info, AES decrypts the payload stored in an alternate data stream of the malware, runs the payload, and then re-encrypts the payload.  If it fails to decrypt/the payload fails to run, the malware deletes itself.  Protection against reverse engineers and malware analysts.

## Introduction
About 6 months ago it occured to me that while I had learned and done a lot with malware concerning AV/EDR evasion, I had spent very little time concerned with trying to evade or defeat reverse engineering/malware analysis.  This was for a few good reasons:

1) I don't know anything about malware analysis or reverse engineering
2) When you are talking about legal, sanctioned Red Team work there isn't really a need to try and frustrate or defeat a reverse engineer because the activity should have been deconflicted long before it reaches that stage. 

Nonetheless it was an interesting thought experiment and I had a few colleagues who DO know about malware analysis that I could bounce ideas off of. It seemed a challenge of a whole different magnitude compared to AV/EDR evasion and one I decided to take a stab at.

### Disclaimer/Liability
The work that follows is a POC to enable malware to "key" itself to a particular victim in order to frustrate efforts of malware analysts.  

I assume no responsibility for malicious use of any ideas or code contained within this project.  I provide this research to further educate infosec professionals and provide additional training/food for thought for Malware Analysts, Reverse Engineers, and Blue Teamers at large. 

## Premise

My initial premise was that the malware, on the first time of being ran, would somehow "key" itself to that victim machine; any subsequent attempts to run it would evaluate something in the target environment and compare it for a match in the malware.  If those two factors matched, it executes as expected.  If they do not (as in the case where the sample had been transfered to a malware analysts sandbox), the malware deletes itself (Once again heavily leaning on the work of [LloydLabs](https://twitter.com/LloydLabs) and his [delete-self-poc](https://github.com/LloydLabs/delete-self-poc)). 

This "key" must be something "unique" to the victim computer.  Ideally it will be a combination of several pieces of information, and then further obfuscated. As an example, we could gather the hostname of the computer as well as the amount of RAM installed; these two values can then be concatenated (e.g. Client018192MB) and then hashed using a user-defined function to produce a number (e.g. 5343823956).  

There are a ton of choices in what information to gather, but thought should be given as to what values a Blue Teamer could easily spoof; a MAC address for example may seem like an attractive "unique" identifier for a victim, however MAC addresses can easily be set manually in order for a Reverse Engineer to match their sandbox to the original victim.  Ideally the values chosen and enumerated will be one that are difficult for a reverse engineer to replicate in their environment. 

With some self-deletion magic, the malware could read itself into a buffer, locate a placeholder variable and replace it with this number, delete itself, and then write the modified malware back to disk in the same location.  Combined with an if/else statement in Main, the next time the malware runs it will detect that it has been ran previously and then go gather the hostname and amount of RAM again in order to produce the hashed number. This would then be evaluated against the number stored in the malware during the first run (5343823956).  If it matches (as is the case if the malware is running on the same machine as it originally did), it executes as expected however if a different value is returned it will again call the self-delete function in order to remove itself from disk and protect the author from the malware analyst.

This seemed like a fine idea in theory until I spoke with a colleague who has real malware analysis and reverse engineering experience.  I was told that a reverse engineer would be able to observe the conditional statement in the malware (if ValueFromFirstRun != GetHostnameAndRAM()), and seeing as the expected value is hard-coded on one side of the conditional statement, simply modify the registers to contain the expected value thus completely bypassing the entire protection mechanism.  
  
This new knowledge completely derailed the thought experiment and seeing as I didn't really have a use for a capability like this in the first place, this is where the project stopped for ~6 months. 
  
## Overview

This project resurfaced a few times over the intervening 6 months but each time was little more than a passing thought, as I had gained no new knowledge of reversing/malware analysis and again had no need for such a capability.  A few days ago the idea rose again and while still neither of those factors have really changed, I guess I had a little bit more knowledge under my belt and couldn't let go of the idea this time.

With the aforementioned problem regarding hard-coding values in mind, I ultimately decided to go for a multi-stage design. I will refer to them as Stage0, Stage1, and Stage2. 

**Stage0**: Setup. Ran on initial infection and deleted afterwards

**Stage1**: Runner.  Ran each subsequent time the malware executes

**Stage2**: Payload. The malware you care about protecting.  Spawns a process and injects shellcode in order to return a Beacon.
  
## Lifecycle

### Stage0

Stage0 is the fresh executable delivered to target by the attacker.  It contains Stage1 and Stage2 as [AES](https://github.com/kokke/tiny-AES-c) encrypted byte arrays; this is done to protect the malware in transit, or should a defender somehow get their hands on a copy of Stage0 (which *shouldn't* happen).  The AES Key and IV are contained within Stage0 so in reality this won't protect Stage1 or Stage2 from a competent Blue Teamer.   

**Stage0** performs the following actions:

1) Sandbox evasion.
2) Delete itself from disk.  It is still running in memory.
3) Decrypts Stage1 using stored AES Key/IV and writes to disk in place of Stage0.
4) Gathers the processor name and the Microsoft ProductID.
5) Hashes this value and then pads it to fit a 16 byte AES key length.  This value reversed serves as the AES IV. 
6) Decrypts Stage2 using stored AES Key/IV.
7) Encrypts Stage2 using new victim-specific AES Key/IV.
8) Writes Stage2 to disk as an alternate data stream of Stage1.

At the conclusion of this sequence of events, Stage0 exits.  Because it was deleted from disk in step 2 and is no longer running in memory, Stage0 is effectively gone; Without prior knowledge of this technique the rest of the malware lifecycle will be a whole lot more confusing than it already is.

In step 4 the processor name and Microsoft ProductID are gathered; the ProductID is retreived from the Registry, and this value can be manually modified which presents and easy opportunity for a Blue Teamer to match their sandbox to the target environment.  Depending on what environmental information is gathered this can become easier or more difficult.

### Stage1

Stage1 was dropped by Stage0 and exists in the same exact location as Stage0 did (to include the name).  Stage2 is stored as an ADS of Stage1.  When the attacker/persistence subsequently executes the malware, they are executing Stage1.

**Stage1** performs the following actions:

1) Sandbox evasion.
2) Gathers the processor name and the Microsoft ProductID.
3) Hashes this value and then pads it to fit a 16 byte AES key length.  This value reversed serves as the AES IV. 
4) Reads Stage2 from Stage1's ADS into memory.
5) Decrypts Stage2 using the victim-specific AES Key/IV.
6) Checks first two bytes of decryted Stage2 buffer; if not MZ (unsuccessful decryption), delete Stage1/Stage2, exit.
7) Writes decrypted Stage2 back to disk as ADS of Stage1
8) Calls CreateProcess on Stage2.  If this fails (unsuccessful decryption), delete Stage1/Stage2, exit.
9) Sleeps 5 seconds to allow Stage2 to execute + exit so it can be overwritten.
10) Encrypts Stage2 using victim-specific AES Key/IV
11) Writes encrypted Stage2 back to disk as ADS of Stage1.

Note that Stage2 MUST exit in order for it to be overwritten; the self-deletion trick does not appear to work on files that are already ADS's, as the self-deletion technique relies on renaming the primary data stream of the executable.  Stage2 will ideally be an inject or spawn+inject executable.

There are two points that Stage1 could detect that it is not being ran from the same victim and delete itself/Stage2 in order to protect the threat actor.  The first is the check for the executable header after decrypting Stage2 using the gathered environmental information; in theory this step could be bypassed by a reverse engineer, but it is a first good check.  The second protection point is the result of the CreateProcess call- if it fails because Stage2 was not properly decrypted, the malware is similiary deleted.  The result of this call could also be modified to prevent deletion by the reverse engineer, however this doesn't change the fact that Stage2 is encrypted and inaccessible.

### Stage2 

Stage2 is the meat and potatoes of the malware chain; It is a fully fledged shellcode runner/piece of malware itself.  By encrypting and protecting it in the way that we have, the actions of the end state malware are much better obfuscated and protected from reverse engineers and malware analysts. During development I used one of my existing shellcode runners containing CobaltStrike shellcode, but this could be anything the attacker wants to run and protect.

## Impact, Mitigation, and Further Work

So what is actually accomplished with a malware lifecycle like this?  There are a few interesting quirks to talk about.

Alternate data streams are a feature unique to NTFS file systems; this means that most ways of transfering the malware after initial infection will strip and lose Stage2 because it is an ADS of Stage1.  Special care would have to be given in order to transfer the sample in order to preserve Stage2, as without it a lot of reverse engineers and malware analysts are going to be very confused as to what is happening.  RAR archives are able to preserve ADS's and tools like 7Z and Peazip can extract files and their ADS's.  

As previously mentioned, by the time malware using this lifecycle hits a Blue Teamer it should be at Stage1; Stage0 has come and gone, and Stage2 is already encrypted with the environmental information gathered by stage 0.  Not knowing that Stage0 even existed will add considerable uncertainty to understanding the lifecycle and decrypting Stage2. 

In theory (because again I have no reversing experience), Stage1 should be able to be reversed (after the Blue Teamers rolls through a few copies of it because it keeps deleting itself) and the information that Stage1 gathers from the target system should be able to be identified.  Provided a well-orchestrated response, Blue Team should be able to identify the victim that the malware came from and go and gather that information from it and feed it into the program so that it may be transformed appropriately into the AES Key/IV that decrypts Stage2. There are a lot "ifs" in there however related to the relative skill of the reverse engineer as well as the victim machine being available for that information to be recovered. 

Application Whitelisting would significantly frustrate this lifecycle.  Stage0/Stage1 may be able to be side loaded as a DLL, however I suspect that Stage2 as an ADS would present some issues.  I do not have an environment to test malware against AWL nor have I bothered porting this all to DLL format so I cannot say.  I am sure there are creative ways around these issues.

I am also fairly confident that there are smarter ways to run Stage2 than dropping to disk and calling CreateProcess; Either manually mapping the executable or using a tool like [Donut](https://github.com/TheWover/donut) to turn it into shellcode seem like reasonable ideas. 

## Code and binary

During development I created a Builder application that Stage1 and Stage2 may be fed to in order to produce a functional Stage0; this will not be provided however I will be providing *most* of the source code for stage1 as it is the piece that would be most visible to a Blue Teamer. Stage0 will be excluded as an exercise for the reader, and stage2 is whatever standalone executable you want to run+protect. This POC may be further researched at the effort and discretion of able readers. 

I will be providing a compiled copy of this malware as Dropper64.exe.  Dropper64.exe is compiled for x64.  Dropper64.exe is Stage0; it contains Stage1 and Stage2. On execution, Stage1 and Stage2 will drop to disk but will NOT automatically execute, you must run Dropper64.exe(now Stage1) again.  Stage2 is an x64 version of calc.exe.  I am including this for any Blue Teamers who want to take a look at this, but keep in mind in an incident response scenario 99& of the time you will be getting Stage1/Stage2, Stage0 will be gone. 

## Conclusion

This was an interesting pet project that ate up a long weekend.  I'm sure it would be a lot more advanced/more complete if I had experience in a debugger and disassembler, but you do the best with what you have.  I am eager to hear from Blue Teamers and other Malware Devs what they think.  I am sure I have over-complicatedly re-invented the wheel here given what actual APT's are doing, but I learned a few things along the way.  Thank you for reading! 

