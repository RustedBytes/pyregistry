rule EXPL_WSUS_Exploitation_Indicators_Oct25 {
   meta:
      description = "Detects indicators related to the exploitation of the Windows Server Update Services (WSUS) Remote Code Execution Vulnerability (CVE-2025-59287)"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/exploitation-of-windows-server-update-services-remote-code-execution-vulnerability"
      date = "2025-10-25"
      score = 75
      id = "9a118d85-fbcd-5476-acd8-6bf66f660368"
   strings:
      // Error traceback found in C:\Program Files\Update Services\Logfiles\SoftwareDistribution.log
      $sl1 = "at System.Data.DataSet.DeserializeDataSetSchema(SerializationInfo info, StreamingContext context" ascii wide
      $sl2 = "at System.Runtime.Serialization.ObjectManager.DoFixups()" ascii wide
      $sl3 = "at System.Runtime.Serialization.ObjectManager.CompleteISerializableObject" ascii wide
      $sl4 = "System.Reflection.TargetInvocationException: Exception has been thrown by the target of an invocation." ascii wide
      $sl5 = "ErrorWsusService.9HmtWebServices.CheckReportingWebServiceReporting WebService WebException:System.Net.WebException: Unable to connect to the remote server" ascii wide

      // Encoded PowerShell command observed in exploitation attempts
      $se1 = "powershell -ec try{$r= (&{echo https://" ascii wide base64 base64wide
      $se2 = ":8531; net user /domain; ipconfig " ascii wide base64 base64wide

      // Commands observed in follow-up activity
      $sa1 = "whoami;net user /domain" ascii wide base64 base64wide
      $sa2 = "net user /domain; ipconfig /all" ascii wide base64 base64wide
   condition:
      all of ($sl*)
      or 1 of ($se*)
      or all of ($sa*)
}

rule HKTL_EXPL_WSUS_Exploitation_POC_Oct25 {
   meta:
      description = "Detects POC for the exploitation of the Windows Server Update Services (WSUS) Remote Code Execution Vulnerability (CVE-2025-59287)"
      author = "Florian Roth"
      reference = "https://github.com/jiansiting/CVE-2025-59287/"
      date = "2025-10-26"
      score = 75
      id = "3f566bda-c217-55c9-bc21-26dd26b271f5"
   strings:
      $sa1 = "/SimpleAuthWebService/SimpleAuth.asmx"
      $sa2 = "/ReportingWebService/ReportingWebService.asmx"
      $sa3 = "/ClientWebService/Client.asmx"
      $sa4 = "/ReportingWebService/ReportingWebService.asmx"

      $sb1 = "xsi:type=\"SOAP-ENC:base64\">"
   condition:
      filesize < 20MB
      and all of ($sa*)
      and $sb1
}
