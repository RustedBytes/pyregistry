
rule MAL_RANSOM_Gentlemen_Jun26_1 {
   meta:
      description = "Detects The Gentlemen ransomware Windows locker (Storm-2697), a self-propagating Go-based encryptor"
      author = "Aryu-RU"
      reference = "https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/"
      date = "2026-06-16"
      hash1 = "22b38dad7da097ea03aa28d0614164cd25fafeb1383dbc15047e34c8050f6f67"
      hash2 = "f918535f974591ef031bd0f30a8171e3da27a6754e6426a8ba095f83195661c8"
      score = 80
      id = "e93ade6d-c558-426c-b8b5-c6034baf6693"
   strings:
      $x1 = "README-GENTLEMEN.txt" ascii      /* ransom note dropped into each encrypted directory */
      $x2 = "gentlemen.bmp" ascii             /* wallpaper dropped to %TEMP% and set as desktop background */
      $x3 = "gentlemen_system" ascii          /* scheduled task created for privilege escalation */

      $s1 = "[+] Encryption started" ascii    /* locker console output */
      $s2 = "Encrypt only mapped" ascii       /* '--shares' run option */
      $s3 = "Silent mode" ascii               /* '--silent' run option */
   condition:
      uint16(0) == 0x5A4D and filesize < 30MB
      and (
         2 of ($x*)
         or ( 1 of ($x*) and 2 of ($s*) )
      )
}
