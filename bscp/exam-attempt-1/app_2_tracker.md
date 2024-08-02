1. Checked boxes means that the vulnerability has been checked and is not present.
2. make space below the checkboxes to add in screenshots for proof (only successful attempts?)
# SCANNING (Enumeration)
## Focus Scanning
- use *Scan selected insertion points* after selecting values 
	- add to the same task to not have too many tasks
		- be wary that it will queue up and may take longer
## Non-Standard Data Structures Scanning
- scan cleartext only if the value has a mix of cleartext and tokens/encoding
# STAGE 1: FOOTHOLD
- [x] Content Discovery?
	- `ffuz`, `robots.txt`
- [x] [XSS?](../notes/client-side/Cross-Site%20Scripting%20(XSS).md)
	- [ ] [](../notes/client-side/Cross-Site%20Scripting%20(XSS).md#DOM-Based%20XSS|DOM%20XXS?)
- [x] [Web Cache Poisoning?](../notes/advanced-topics/Web%20Cache%20Poisoning.md)
- [x] [HTTP Host Header Attack?](../notes/advanced-topics/HTTP%20Host%20Header%20Attacks.md)
- [x] [Request Smuggling?](../notes/advanced-topics/HTTP%20Request%20Smuggling.md)
- [ ] [](../notes/server-side/Authentication.md#Brute-Force%20Attacks|Brute-Force%20Authentication?)
- [x] Others?
	- [ ] 
# STAGE 2: PRIVILEGE ESCALATION
- [x] [[Cross-Site Request Forgery (CSRF)]|CSRF?]
- [x] Password Reset
	- multiple different types, check all
- [x] [SQLi?](../notes/server-side/SQL%20Injection.md)
- [x] JWT?
- [x] [Access Control?](../notes/server-side/Access%20Control.md)
- [ ] [[Cross-Origin Resource Sharing (CORS)]CORS?]
- [x] Others?
	- [ ] 
# STAGE 3: DATA EXFILTRATION
- [x] [XXE?](../notes/server-side/XML%20External%20Entity%20Injection%20(XXE).md)
- [x] [SSRF?](../notes/server-side/Server-Side%20Request%20Forgery%20(SSRF).md)
- [x] [SSTI?](../notes/advanced-topics/Server-Side%20Template%20Injection%20(SSTI).md)
- [x] [Path Traversal?](../notes/server-side/Path%20Traversal.md)
- [ ] [File Upload?](../notes/server-side/File%20Upload.md)
- [x] [Insecure Deserialization?](../notes/advanced-topics/Insecure%20Deserialization.md)
- [x] [Command Injection?](../notes/server-side/OS%20Command%20Injection.md)
- [x] Others?
	- [ ] 