rule G_APT_BackdoorWebshell_SLAYSTYLE_1 {
	meta:
		author = "Google Threat Intelligence Group (GTIG)"
	strings:
		$str1 = /String \w{1,10}=request\.getParameter\(\"\w{1,15}\"\);/ ascii wide nocase
		$str2 = "=new String(java.util.Base64.getDecoder().decode(" ascii wide nocase
		$str21 = /String\[\]\s\w{1,10}=\{\"\/bin\/sh\",\"-c\",\w{1,10}\+\"\s2>&1\"\};/ ascii wide nocase
		$str3 = "= Runtime.getRuntime().exec(" ascii wide nocase
		$str4 = "java.io.InputStream" ascii wide nocase
		$str5 = "java.util.Base64.getEncoder().encodeToString(org.apache.commons.io.IOUtils.toByteArray(" ascii wide nocase
	condition:
		filesize < 5MB and all of them
}
