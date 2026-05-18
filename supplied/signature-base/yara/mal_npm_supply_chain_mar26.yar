rule MAL_NPM_SupplyChain_Attack_Mar26 {
   meta:
      description = "Detects package.json which include the malicious plain-crypto-js package as dependency"
      author = "Marius Benthin"
      date = "2026-03-31"
      reference = "https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan"
      hash = "5e3e89c7351f385e36bb70286866a62957cc1aaab195539edb8c7bb62968a137"
      score = 80
      id = "88e7af97-f7c1-591e-960c-d5296da94066"
   strings:
      $s1 = "\"dependencies\":"
      // This is the specific malicious package that was added to the npm registry, which is a typo-squatting of the popular crypto-js package
      $s2 = { 22 70 6C 61 69 6E 2D 63 72 79 70 74 6F 2D 6A 73 22 3A [0-3] 22 [0-2] 34 2E 32 2E }  // "plain-crypto-js": "^4.2."
   condition:
      filesize < 10KB
      and all of them
}

rule SUSP_JS_Dropper_Mar26 {
   meta:
      description = "Detects suspicious JavaScript dropper used in plain-crypto-js supply chain attacks"
      author = "Marius Benthin"
      date = "2026-03-31"
      reference = "https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan"
      hash = "e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09"
      score = 70
      id = "456a52c2-9cbf-572f-9a5b-b8d74183e3f4"
   strings:
      $sa1 = "Buffer.from("
      $sa2 = "FileSync("
      $sa3 = ".replaceAll("

      $sb1 = ".arch()"
      $sb2 = ".platform()"
      $sb3 = ".release()"
      $sb4 = ".type()"
   condition:
      filesize < 10KB
      and all of ($sa*)
      and 2 of ($sb*)
}
