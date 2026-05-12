rule EXPL_HKTL_LNX_DirtyFragLPE_May26 {
   meta:
      description = "Detects dirtyfrag, a local privilege escalation exploit for Linux."
      author = "Pezier Pierre-Henri (Nextron Systems)"
      date = "2026-05-07"
      score = 80
      hash = "c35594d42f7a5d5d2895164147ee1bc62bb8e294c8468093b7d6fcaab0b174c8"
      reference = "https://github.com/V4bel/dirtyfrag/tree/master"
   strings:
      // Indicators of exploitation attempts
      $x1 = "gained CAP_NET_RAW within netn" ascii
      $x2 = "DIRTYFRAG_VERBOSE" ascii

      $s1 = { 15 7C 4A 7F B9 79 37 9E }  // fc_splitmix64
      $s2 = "/proc/self/setgroups" ascii fullword
      $s3 = "pcbc(fcrypt)" ascii fullword
      $s4 = { 17 bb c7 f3 3f 36 ba 71 8e 97 65 60 69 b6 f6 e6 }
   condition:
      filesize < 100KB
      and uint32be(0) == 0x7f454c46
      and (
         1 of ($x*)
         or 3 of ($s*)
      )
}

rule EXPL_HKTL_LNX_DirtyFragShellcode_May26 {
   meta:
      description = "Detects a shellcode observed in dirtyfrag, a local privilege escalation exploit for Linux."
      reference = "https://github.com/V4bel/dirtyfrag/tree/master"
      author = "Pezier Pierre-Henri (Nextron Systems)"
      date = "2026-05-07"
      score = 80
      hash = "a02ea2ba8108a9b7a997faa8808cfc55bb69af54e69178fa5aa1785681cf0ced"
   strings:
      $op1 = {
         31 ff     // xor     edi, edi
         31 f6     // xor     esi, esi
         31 c0     // xor     eax, eax
         b0 6a     // mov     al, 6Ah ; 'j'
         0f 05     // syscall; LINUX - sys_setgid
         b0 69     // mov     al, 69h ; 'i'
         0f 05     // syscall; LINUX - sys_setuid
         b0 74     // mov     al, 74h ; 't'
         0f 05     // syscall; LINUX - sys_setgroups
         6a 00     // push    0
         48 [6]    // lea     rax, aTermXterm; "TERM=xterm"
         50        // push    rax
         48 89 e2  // mov     rdx, rsp
         48 [6]    // lea     rdi, aBinSh; "/bin/sh"
         31 f6     // xor     esi, esi
         6a 3b     // push    3Bh ; ';'
         58        // pop     rax
         0f 05     // syscall; LINUX - sys_execve
      }
   condition:
      $op1
}

rule EXPL_LNX_DirtyFrag_ForensicArtefacts_May26 {
   meta:
      description = "Detects DirtyFrag exploit code POC usage in Linux environments"
      author = "Florian Roth"
      reference = "https://github.com/V4bel/dirtyfrag/tree/master"
      date = "2026-05-08"
      score = 75
   strings:
      $xa1 = "/V4bel/dirtyfrag.git" ascii
      $xa2 = "static const uint8_t shell_elf[PAYLOAD_LEN] = {" ascii
      $xa3 = "/usr/bin/su page-cache patched (entry 0x%x = shellcode)" ascii
   condition:
      filesize < 800KB
      and 1 of ($xa*)
}
