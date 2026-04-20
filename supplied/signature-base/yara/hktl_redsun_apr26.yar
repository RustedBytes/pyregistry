rule HKTL_RedSun_Privilege_Escalation_Apr26 {
   meta:
      description = "Detects RedSun hacktool used for privilege escalation through Microsoft Defender."
      author = "Jonathan Peters (cod3nym)"
      date = "2026-04-16"
      reference = "https://github.com/Nightmare-Eclipse/RedSun"
      hash = "57a70c383feb9af60b64ab6768a1ca1b3f7394b8c5ffdbfafc8e988d63935120"
      score = 80
   strings:
      $x1 = "\\??\\pipe\\REDSUN" wide
      $x2 = "The red sun shall prevail.\n" ascii fullword
      $x3 = "\\RedSun.pdb" ascii

      $s1 = "\\System32\\TieringEngineService.exe" wide
      $s2 = "SERIOUSLYMSFT" wide
      $s3 = "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X" ascii
   condition:
      uint16(0) == 0x5a4d
      and (
         1 of ($x*)
         or 2 of ($s*)
      )
      or 3 of them
}
