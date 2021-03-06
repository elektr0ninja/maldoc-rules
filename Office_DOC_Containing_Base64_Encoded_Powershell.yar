/*
    This Yara ruleset is under the GNU-GPLv3 license (http://www.gnu.org/licenses/gpl-3.0.html) and open to any user or organization, as long as you use it under this license.

*/


rule Office_DOC_Containing_Base64_Encoded_Powershell
{
	meta:
		author = "elektr0ninja"
		description = "Office document with base64 encoded powershell payload"
		date = "2019-06-04"
		filetype = "Office documents"

	strings:
		$officemagic = { D0 CF 11 E0 A1 B1 1A E1 }

		$97str1 = { 00 23 00 00 00 4A 41 42 } 

	condition:
		($officemagic at 0 and $97str1) 
}
