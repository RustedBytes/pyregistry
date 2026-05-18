
rule APT_SAP_NetWeaver_Exploitation_Activity_Apr25_1 : SCRIPT {
   meta:
      description = "Detects forensic artefacts related to exploitation activity of SAP NetWeaver CVE-2025-31324"
      reference = "https://reliaquest.com/blog/threat-spotlight-reliaquest-uncovers-vulnerability-behind-sap-netweaver-compromise/"
      author = "Florian Roth"
      date = "2025-04-25"
      score = 70
      id = "1ad16960-f059-57cd-97ba-58f2be6ca3f8"
   strings:
      $x01 = "/helper.jsp?cmd=" ascii wide
      $x02 = "/cache.jsp?cmd=" ascii wide
   condition:
      filesize < 20MB and 1 of them
}

rule APT_SAP_NetWeaver_Exploitation_Activity_Apr25_2 : SCRIPT {
   meta:
      description = "Detects forensic artefacts related to exploitation activity of SAP NetWeaver CVE-2025-31324"
      reference = "https://reliaquest.com/blog/threat-spotlight-reliaquest-uncovers-vulnerability-behind-sap-netweaver-compromise/"
      author = "Florian Roth"
      date = "2025-04-25"
      score = 70
      id = "3b7d3f94-88a9-5686-8a23-ac4040c0e6c1"
   strings:
      $x03 = "MSBuild.exe c:\\programdata\\" ascii wide
   condition:
      filesize < 20MB and 1 of them
}

rule SUSP_WEBSHELL_Cmd_Indicator_Apr25 {
   meta:
      description = "Detects a pattern which is often related to web shell activity"
      reference = "https://regex101.com/r/N6oZ2h/2"
      author = "Florian Roth"
      date = "2025-04-25"
      modified = "2025-05-07"
      score = 60
      id = "eeeebfbc-9418-5ff4-b45f-8d96a9e7e4a8"
   strings:
      $xr01 = /\.(asp|aspx|jsp|php)\?cmd=[a-z0-9%+\-\/\.]{3,20} HTTP\/1\.[01]["']? 200/
   condition:
      1 of them
}
