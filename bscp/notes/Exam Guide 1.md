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
- [ ] [[Web Cache Poisoning|Web Cache Poisoning?]]
- [ ] [[HTTP Host Header Attacks|HTTP Host Header Attack?]]
- [ ] [[HTTP Request Smuggling|Request Smuggling?]]
- [ ] [[Authentication#Brute-Force Attacks|Brute-Force Authentication?]]
- [ ] Others?
# STAGE 2: PRIVILEGE ESCALATION
- [ ] [[Cross-Site Request Forgery (CSRF)|CSRF?]]
- [ ] Password Reset
	- multiple different types, check all
- [ ] [[SQL Injection|SQLi?]]
- [ ] JWT?
- [ ] [[Access Control|Access Control?]]
- [ ] [[Cross-Origin Resource Sharing (CORS)]CORS?]

# STAGE 3: DATA EXFILTRATION
- [ ] [[XML External Entity Injection (XXE)|XXE?]]
- [ ] [[Server-Side Request Forgery (SSRF)|SSRF?]]
- [ ] [[Server-Side Template Injection (SSTI)|SSTI?]]
- [ ] [[Path Traversal|Path Traversal?]]
- [ ] [[File Upload|File Upload?]]
- [ ] [[Insecure Deserialization|Insecure Deserialization?]]
- [ ] [[OS Command Injection|Command Injection?]]
