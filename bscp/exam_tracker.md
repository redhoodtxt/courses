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
- [ ] Content Discovery?
	- `ffuz`, `robots.txt`
- [ ] [XSS?](notes/client-side/Cross-Site%20Scripting%20(XSS).md)
	- [ ] [](notes/client-side/Cross-Site%20Scripting%20(XSS).md#DOM-Based%20XSS|DOM%20XXS?)
- [ ] [Web Cache Poisoning?](notes/advanced-topics/Web%20Cache%20Poisoning.md)
- [ ] [HTTP Host Header Attack?](notes/advanced-topics/HTTP%20Host%20Header%20Attacks.md)
- [ ] [Request Smuggling?](notes/advanced-topics/HTTP%20Request%20Smuggling.md)
- [ ] [](notes/server-side/Authentication.md#Brute-Force%20Attacks|Brute-Force%20Authentication?)
- [ ] Others?
# STAGE 2: PRIVILEGE ESCALATION
- [ ] [[Cross-Site Request Forgery (CSRF)]|CSRF?]
- [ ] Password Reset
	- multiple different types, check all
- [ ] [SQLi?](notes/server-side/SQL%20Injection.md)
- [ ] JWT?
- [ ] [Access Control?](notes/server-side/Access%20Control.md)
- [ ] [[Cross-Origin Resource Sharing (CORS)]CORS?]

# STAGE 3: DATA EXFILTRATION
- [ ] [XXE?](notes/server-side/XML%20External%20Entity%20Injection%20(XXE).md)
- [ ] [SSRF?](notes/server-side/Server-Side%20Request%20Forgery%20(SSRF).md)
- [ ] [SSTI?](notes/advanced-topics/Server-Side%20Template%20Injection%20(SSTI).md)
- [ ] [Path Traversal?](notes/server-side/Path%20Traversal.md)
- [ ] [File Upload?](notes/server-side/File%20Upload.md)
- [ ] [Insecure Deserialization?](notes/advanced-topics/Insecure%20Deserialization.md)
- [ ] [Command Injection?](notes/server-side/OS%20Command%20Injection.md)
