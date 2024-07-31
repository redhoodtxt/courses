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
- [ ] [[Cross-Site Scripting (XSS)|XSS?]]
	- [ ] [[Cross-Site Scripting (XSS)#DOM-Based XSS|DOM XXS?]]
	- tags is not allowed (signature)
	- HTML encoding for symbols (sanitizing)
	- backslash and single quotes escaped
- [x] [[Web Cache Poisoning|Web Cache Poisoning?]]
- [ ] [[HTTP Host Header Attacks|HTTP Host Header Attack?]]
- [x] [[HTTP Request Smuggling|Request Smuggling?]]
- [x] [[Authentication#Brute-Force Attacks|Brute-Force Authentication?]]
- [x] Others?
	- [ ] 
# STAGE 2: PRIVILEGE ESCALATION
- [x] [[Cross-Site Request Forgery (CSRF)]|CSRF?]
- [x] Password Reset [[Basic password reset poisoning]]
	- multiple different types, check all
- [ ] [[SQL Injection|SQLi?]]
- [x] JWT?
- [x] [[Access Control|Access Control?]]
- [x] [[Cross-Origin Resource Sharing (CORS)]CORS?]
- [x] Others?
	- [ ] 
# STAGE 3: DATA EXFILTRATION
- [ ] [[XML External Entity Injection (XXE)|XXE?]]
- [x] [[Server-Side Request Forgery (SSRF)|SSRF?]]
- [x] [[Server-Side Template Injection (SSTI)|SSTI?]]
- [x] [[Path Traversal|Path Traversal?]]
- [x] [[File Upload|File Upload?]]
- [x] [[Insecure Deserialization|Insecure Deserialization?]]
- [x] [[OS Command Injection|Command Injection?]]
- [x] Others?
	- [ ] 