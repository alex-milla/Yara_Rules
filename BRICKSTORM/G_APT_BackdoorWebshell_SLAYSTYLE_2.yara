rule G_APT_BackdoorWebshell_SLAYSTYLE_2 {
	meta:
		author = "Google Threat Intelligence Group (GTIG)"
	strings:
		$str1 = "request.getParameter" nocase
		$str2 = "/bin/sh"
		$str3 = "java.io.InputStream" nocase
		$str4 = "Runtime.getRuntime().exec(" nocase
		$str5 = "2>&1"
	condition:
		(uint16(0) != 0x5A4D and uint32(0) != 0x464C457F) and filesize < 7KB and all of them and @str4 > @str2
}
