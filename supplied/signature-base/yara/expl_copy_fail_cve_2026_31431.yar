rule EXPL_LNX_Copy_Fail_Artefacts_CVE_2026_31431_Apr26 {
   meta:
      description = "Detects forensic artifacts related to public Copy Fail (CVE-2026-31431) exploit PoCs, including known tiny ELF shell payloads, Python exploit code fragments, AF_ALG/authencesn/splice usage patterns, public PoC URLs, and other indicators observed in online proof-of-concept material."
      author = "Florian Roth"
      reference = "https://copy.fail"
      reference_2 = "https://github.com/tgies/copy-fail-c"
      reference_3 = "https://github.com/theori-io/copy-fail-CVE-2026-31431"
      reference_4 = "https://hackerspace.pl/~q3k/alpine.py"
      reference_5 = "https://github.com/badsectorlabs/copyfail-go"
      reference_6 = "https://github.com/iss4cf0ng/CVE-2026-31431-Linux-Copy-Fail"
      date = "2026-04-30"
      score = 75
   strings:
      // Network indicators (e.g. in bash history, logs, etc.)
      $xn1 = "curl https://copy.fail/exp" ascii

      // Code fragments from public PoCs
      $xs1 = "| python3 && su"
      $xs2 = "g.open(\"/usr/bin/su\",0);i=0;"
      $xs3 = "[-] page-cache mutation failed"
      $xs4 = "[+] /etc/passwd page cache mutated"
      $xs5 = "bind(AF_ALG: authencesn(hmac(sha256),cbc(aes)))"
      $xs6 = "/tmp/.cve_test"

      // Indicator Combo
      $sa1 = "authencesn(hmac(sha256),cbc(aes))" ascii

      $sb1 = { 08 00 01 00 00 00 00 10 }
      $sb2 = "0800010000000010" ascii

      // Base64 encoded payloads
      $xe1 = "authencesn(hmac(sha256),cbc(aes))" base64

      // Tiny x86-64 ELF shell payload: setuid(0) -> execve("/bin/sh") -> exit(0)
      $xc1 = { 7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 02 00 3e 00 01 00 00 00 78 00 40 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 38 00 01 00 00 00 00 00 00 00 01 00 00 00 05 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 00 00 00 40 00 00 00 00 00 00 9e 00 00 00 00 00 00 00 9e 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 31 c0 31 ff b0 69 0f 05 48 8d 3d 0f 00 00 00 31 f6 6a 3b 58 99 0f 05 31 ff 6a 3c 58 0f 05 2f 62 69 6e 2f 73 68 00 00 00 }
      // Tiny AArch64 Linux ELF shell payload: setuid(0) -> execve("/bin/sh") -> exit(0)
      $xc2 = { 7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 02 00 b7 00 01 00 00 00 78 00 40 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 38 00 01 00 00 00 00 00 00 00 01 00 00 00 05 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 40 00 00 00 00 00 00 ac 00 00 00 00 00 00 00 ac 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00 00 00 80 d2 48 12 80 d2 01 00 00 d4 00 01 00 10 01 00 80 d2 02 00 80 d2 a8 1b 80 d2 01 00 00 d4 00 00 80 d2 a8 0b 80 d2 01 00 00 d4 2f 62 69 6e 2f 73 68 00 }

      // Payloads used in the Go version
      $xg1 = "789cab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c00111d10d3"
      $xg2 = "789cab77f57163646464800126066606102fa48185c38401014c18141860aae0aa816a40b806c80461569098000383e101c3db1bae9e6d303c1090a1af5f9c91a19f9499d7f93820b8f361e7a10ddc4089db598c11671b0038b31858"
      $xg3 = "78daab77f5716362646480012686ed0c205e05830398efc080091c182c18603a40342b9a2c32bd06ca5b039787e96cb8e421d47009c8bb0214126004f29980788534540cc4e686b0f59332f3f48b3318003ff61578"
      $xg4 = "789cab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e02e5c1680601086578c0f0ff864c7e568fee1a1501c36f59d61133f9590dff67d944f0b3020082b00eaf"
      $xg5 = "789cab77f57163646464800126066606102fa48185c38401014c18141860aae0aa816a40381fc80461569098000383e101c3db1bae9e6de88e51e1303c99c51d31f36c83e1ed2cc688b30d001bf41180"
      $xg6 = "789cab77f5716362646480012686ed0c205e05830398efc080091c182c18603a40342b9a2c32bd04ca5b029787e96cb8e421d47009c8bbf280dbe1272390cf04c42ba4216220f915dc103600d72b1509"

      $xge1 = { 78 9c ab 77 f5 71 63 62 64 64 80 01 26 06 3b 06 10 af 82 c1 01 cc 77 60 c0 04 0e 0c 16 0c 30 1d 20 9a 15 4d 16 99 9e 07 e5 c1 68 06 01 08 65 78 c0 f0 ff 86 4c 7e 56 8f 5e 5b 7e 10 f7 5b 96 75 c4 4c 7e 56 c3 ff 59 36 11 fc ac fa 49 99 79 fa c5 19 0c 00 11 1d 10 d3 }
      $xge2 = { 78 9c ab 77 f5 71 63 64 64 64 80 01 26 06 66 06 10 2f a4 81 85 c3 84 01 01 4c 18 14 18 60 aa e0 aa 81 6a 40 b8 06 c8 04 61 56 90 98 00 03 83 e1 01 c3 db 1b ae 9e 6d 30 3c 10 90 a1 af 5f 9c 91 a1 9f 94 99 d7 f9 38 20 b8 f3 61 e7 a1 0d dc 40 89 db 59 8c 11 67 1b 00 38 b3 18 58 }
      $xge3 = { 78 da ab 77 f5 71 63 62 64 64 80 01 26 86 ed 0c 20 5e 05 83 03 98 ef c0 80 09 1c 18 2c 18 60 3a 40 34 2b 9a 2c 32 bd 06 ca 5b 03 97 87 e9 6c b8 e4 21 d4 70 09 c8 bb 02 14 12 60 04 f2 99 80 78 85 34 54 0c c4 e6 86 b0 f5 93 32 f3 f4 8b 33 18 00 3f f6 15 78 }
      $xge4 = { 78 9c ab 77 f5 71 63 62 64 64 80 01 26 06 3b 06 10 af 82 c1 01 cc 77 60 c0 04 0e 0c 16 0c 30 1d 20 9a 15 4d 16 99 9e 02 e5 c1 68 06 01 08 65 78 c0 f0 ff 86 4c 7e 56 8f ee 1a 15 01 c3 6f 59 d6 11 33 f9 59 0d ff 67 d9 44 f0 b3 02 00 82 b0 0e af }
      $xge5 = { 78 9c ab 77 f5 71 63 64 64 64 80 01 26 06 66 06 10 2f a4 81 85 c3 84 01 01 4c 18 14 18 60 aa e0 aa 81 6a 40 38 1f c8 04 61 56 90 98 00 03 83 e1 01 c3 db 1b ae 9e 6d e8 8e 51 e1 30 3c 99 c5 1d 31 f3 6c 83 e1 ed 2c c6 88 b3 0d 00 1b f4 11 80 }
      $xge6 = { 78 9c ab 77 f5 71 63 62 64 64 80 01 26 86 ed 0c 20 5e 05 83 03 98 ef c0 80 09 1c 18 2c 18 60 3a 40 34 2b 9a 2c 32 bd 04 ca 5b 02 97 87 e9 6c b8 e4 21 d4 70 09 c8 bb f2 80 db e1 27 23 90 cf 04 c4 2b a4 21 62 20 f9 15 dc 10 36 00 d7 2b 15 09 }
   condition:
      1 of ($x*)
      or ($sa1 and 1 of ($sb*))
}
