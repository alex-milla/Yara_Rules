rule G_Dropper_BRICKSTEAL_1 {
	meta:
		author = "Google Threat Intelligence Group (GTIG)"
	strings:
		$str1 = "Base64.getDecoder().decode"
		$str2 = "Thread.currentThread().getContextClassLoader()"
		$str3 = ".class.getDeclaredMethod"
		$str4 = "byte[].class"
		$str5 = "method.invoke"
		$str6 = "filterClass.newInstance()"
		$str7 = "/websso/SAML2/SSO/*"
	condition:
		all of them
}
