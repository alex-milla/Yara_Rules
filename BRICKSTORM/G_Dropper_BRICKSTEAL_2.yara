rule G_Dropper_BRICKSTEAL_2 {
	meta:
		author = "Google Threat Intelligence Group (GTIG)"
	strings:
		$str1 = /\(Class<\?>\)\smethod\.invoke\(\w{1,20},\s\w{1,20},\s0,\s\w{1,20}\.length\);/i ascii wide
		$str2 = "(\"yv66vg" ascii wide
		$str3 = "request.getSession().getServletContext" ascii wide
		$str4 = ".getClass().getDeclaredField(" ascii wide
		$str5 = "new FilterDef();" ascii wide
		$str6 = "new FilterMap();" ascii wide
	condition:
		all of them
}
