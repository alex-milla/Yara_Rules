rule G_Backdoor_BRICKSTEAL_1 {
	meta:
		author = "Google Threat Intelligence Group (GTIG)"
	strings:
		$str1 = "comvmware"
		$str2 = "abcdABCD1234!@#$"
		$str3 = "ads.png"
		$str4 = "User-Agent"
		$str5 = "com/vmware/"
	condition:
		all of them and filesize < 10KB
}
