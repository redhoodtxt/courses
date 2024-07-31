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
		- `disallow /`
- [x] [[Cross-Site Scripting (XSS)|XSS?]]
	- [x] [[Cross-Site Scripting (XSS)#DOM-Based XSS|DOM XXS?]]
- [x] [[Web Cache Poisoning|Web Cache Poisoning?]]
- [x] [[HTTP Host Header Attacks|HTTP Host Header Attack?]]
- [x] [[HTTP Request Smuggling|Request Smuggling?]]
- [ ] [[Authentication#Brute-Force Attacks|Brute-Force Authentication?]] 
- [x] Others?
# STAGE 2: PRIVILEGE ESCALATION
- [x] [[Cross-Site Request Forgery (CSRF)]|CSRF?]
- [x] Password Reset
	- multiple different types, check all
- [x] [[SQL Injection|SQLi?]]
- [x] JWT?
- [ ] [[Access Control|Access Control?]]
- [x] [[Cross-Origin Resource Sharing (CORS)]CORS?]

# STAGE 3: DATA EXFILTRATION
- [ ] [[XML External Entity Injection (XXE)|XXE?]]
	```xml 
	<?xml version="1.0" encoding="UTF-8"?>
	  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///home/carlos/flag.txt">]>
	  <users>
	  <user>
	    <username>Guest 1</username>
	    <email>&xxe;</email>
	  </user>
	  <user>
	    <username>Guest 2</username>
	    <email>email2@email.com</email>
	  </user>
	</users>
	```
- [x] [[Server-Side Request Forgery (SSRF)|SSRF?]]
- [x] [[Server-Side Template Injection (SSTI)|SSTI?]]
- [x] [[Path Traversal|Path Traversal?]]
- [x] [[File Upload|File Upload?]]
- [x] [[Insecure Deserialization|Insecure Deserialization?]]
- [x] [[OS Command Injection|Command Injection?]]
