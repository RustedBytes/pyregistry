rule HKTL_NET_Edge_Saved_Passwords_Dumper_May26 {
   meta:
      description = "Detects an .NET based tool used to dump saved passwords from Microsoft Edge browser processes"
      author = "Florian Roth"
      reference = "https://github.com/L1v1ng0ffTh3L4N/Proof-of-Concepts/tree/main/EdgeSavedPasswordsDumper"
      date = "2026-05-05"
      score = 80
   strings:
      $x1 = "SELECT ProcessId, Name, ParentProcessId FROM Win32_Process WHERE Name='msedge.exe'" wide
      $x2 = "Scanning process PID: " wide

      $s1 = "NSC\\t1_" wide
      $s2 = "\\*\\(\\)_\\-\\+=\\{\\}\\[\\]:;<>\\?/~\\s]{6,40})\\x20\\x00" wide
   condition:
      2 of them
}
