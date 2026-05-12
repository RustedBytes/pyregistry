rule MAL_Information_Collector_May26 {
   meta:
      description = "Detects reconaissance payload used in the DAEMON Tools supplychain compromise. The tools collects detailed information about the infected system like hardware, installed software, running processes etc. all data is exfilled to an attacker controlled server."
      author = "MalGamy, Jonathan Peters (cod3nym)"
      date = "2026-05-05"
      reference = "https://securelist.com/tr/daemon-tools-backdoor/119654/"
      hash = "a916e56121212613d17932e124b68752c9312e73bde8f2351054bd64394257df"
      score = 80
   strings:
      $x1 = ": InfoCollector.exe <" wide

      $s1 = "CollectInstalledSoftwareSemicolon" ascii
      $s2 = "GetRc4KeyFromUrl" ascii
      $s3 = "InfoGatherer" ascii

      $op1 = { 09 7E ?? ?? ?? 04 28 ?? ?? ?? 0A 28 ?? ?? ?? 0A 13 ?? 11 ?? 16 36 3A 11 ?? 1E 35 ?? 1E 8D ?? ?? ?? 01 13 ?? 09 7E ?? ?? ?? 04 28 ?? ?? ?? 0A 11 ?? 16 11 ?? 28 ?? ?? ?? 0A }
      $op2 = { 02 73 ?? ?? ?? 0A 6F ?? ?? ?? 0A 0A 06 2D ?? 72 ?? ?? ?? 70 0B DE ?? 06 6F ?? ?? ?? 0A 0A 06 72 ?? ?? ?? 70 7E ?? ?? ?? 0A 6F ?? ?? ?? 0A 0A 06 6F ?? ?? ?? 0A 2D ?? 72 ?? ?? ?? 70 0B DE ?? 06 0B DE }
   condition:
      uint16(0) == 0x5a4d
      and filesize < 50KB
      and (
         $x1
         or all of ($op*)
         or all of ($s*)
      )
}

rule MAL_DAEMON_Tools_Lite_Compromised_May26 {
   meta:
      description = "Detects compromised DAEMON Tools Lite versions deployed in a supplychain compromise campaign affected versions include: 12.5.0.2421 up to 12.5.0.2434 The infected binaries drop Quic RAT and various custom data exfiltration payloads."
      author = "Jonathan Peters (cod3nym)"
      date = "2026-05-05"
      reference = "https://securelist.com/tr/daemon-tools-backdoor/119654/"
      hash = "12edcaafab7703d0819b1395f45c35e3083dd83fb8b128292cb11033453fb6e8"
      hash = "0066ed9b9de2b8e251f7bcf73edcb549218179398cf90124a221958fedce6212"
      hash = "d2a5c9cbb73849cc0667987c33a9bf3822718e1528faef005f1628de3348ffb0"
      score = 80
   strings:
      $sa1 = { 31 03 35 55 e4 c4 32 2d a9 e0 b3 81 6d 14 38 4e }  // certificate serial number
      $sa2 = "AVB Disc Soft, SIA" ascii
      $sa3 = "DAEMON Tools Lite" ascii wide

      $re = /12\.5\.0\.24(21|22|23|24|25|26|27|28|29|30|31|33|34)/ ascii wide
   condition:
      uint16(0) == 0x5a4d
      and all of ($sa*)
      and $re
}

rule MAL_Backdoor_May26 {
   meta:
      description = "Detects a backdoor smuggled into signed DAEMON Tools binaries via supply-chain compromise, receives encrypted commands over HTTPS to execute arbitrary shell commands and drop files on victim hosts."
      author = "MalGamy"
      date = "2026-05-05"
      reference = "https://securelist.com/tr/daemon-tools-backdoor/119654/"
      hash = "5d581534b48d09855ac045aaf9b196ca26396a6c08616213f9f9afc656849c2f"
      score = 80
   strings:
      $op1 = { 48 8D 8D ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? F3 0F 7F 7D ?? C7 45 ?? ?? ?? ?? ?? F3 0F 7F 75 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 66 C7 45 ?? ?? ?? C6 45 ?? ?? FF 15 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8D 8D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8D 95 }
      $op2 = { 4D 8D 40 ?? 99 41 FF C1 41 F7 FB 48 63 C2 0F B6 8C 05 ?? ?? ?? ?? 41 30 48 ?? 49 83 EA }
   condition:
      all of them
}

rule MAL_Minimalistic_Backdoor_May26 {
   meta:
      description = "Detects minimalistic backdoor deployment where a shellcode loader downloads an encrypted payload and executes it in memory after RC4 decryption using a command-line provided key"
      author = "MalGamy"
      date = "2026-05-05"
      reference = "https://securelist.com/tr/daemon-tools-backdoor/119654/"
      hash = "395ec7acd475a8acd358adc75c4615cf41737aed8a96c4f2dd792c8a6af4140c"
      score = 80
   strings:
      $x1 = "Note: if multiple processes load the DLL," wide
      $x2 = "Inject (shellcode file is RC4 ciphertext; key is a UTF-8 string" wide

      $s1 = "Error: VirtualAllocEx failed, Win" wide
      $s2 = "Try running as administrator; " wide
      $s3 = ", shellcode size: " wide
      $s4 = "input file path cannot be empty." wide
   condition:
      uint16(0) == 0x5a4d
      and filesize < 50KB
      and (
         1 of ($x*)
         or all of ($s*)
      )
}
