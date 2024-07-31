- when an attacker is able to use native template syntax to inject a malicious payload into a template, which is then executed server-side
- when user input is concatenated directly into a template, rather than passed in as data
	- this allows attackers to inject arbitrary template directives in order to manipulate the template engine, often enabling them to take complete control of the server
1. the following is a vulnerable code snippet using Jinja, a popular template engine:
	`output = template.render(name=request.args.get('name'))`
1. attacker can take advantage of this with the following:
	`http://vulnerable-website.com/?name={{bad-stuff-here}}`
1. the payload `{{bad-stuff-here}}` can contain Jinja template directives that enable attackers to execute unauthorized code or manipulate the template engine
# Constructing SSTI
![[Pasted image 20240531164528.png]]
## Detect
- fuzz the template 
	- inject a sequence of special characters (`${{<%[%'"}}%\`) into the template and analyze the differences in the server's response to regular data vs this special payload
- this polyglot will trigger an error in presence of a SSTI vulnerability:
	- `${{<%[%'"}}%\.`
- if fuzzing successful or unsuccessful, find the context
### Plaintext Context
- distinguish from XSS by checking if the server evaluates template expressions (e.g., `{{7*7}}`, `${7*7}`).
eg. if the vulnerable code is `render('Hello ' + username)` and the attacker injects `http://vulnerable-website.com/?username=${7*7}` and the resulting output is `Hello 49`, this shows that the mathematical operation is being evaluated server-side
### Code Context
1. example vulnerable code would be as such:
	```
	greeting = getQueryParameter('greeting')
	engine.render("Hello {{"+greeting+"}}", data)
	```
2. On the website, the resulting URL would be something like:
	`http://vulnerable-website.com/?greeting=data.username`
3. this would be rendered in the output to `Hello Carlos`, for example
4. this context is easily missed during assessment because it doesn't result in obvious XSS and is almost indistinguishable from a simple hashmap lookup. One method of testing for server-side template injection in this context is to first establish that the parameter doesn't contain a direct XSS vulnerability by injecting arbitrary HTML into the value:
	`http://vulnerable-website.com/?greeting=data.username<tag>`
5. in the absence of XSS, this will usually either result in a blank entry in the output (just Hello with no username), encoded tags, or an error message. The next step is to try and break out of the statement using common templating syntax and attempt to inject arbitrary HTML after it:
	`http://vulnerable-website.com/?greeting=data.username}}<tag>`
6. if this again results in an error or blank output, you have either used syntax from the wrong templating language or, if no template-style syntax appears to be valid, server-side template injection is not possible. Alternatively, if the output is rendered correctly, along with the arbitrary HTML, this is a key indication that a server-side template injection vulnerability is present:
	`Hello Carlos<tag>`
### Identify
### Tools 
1. [TInjA](https://github.com/Hackmanit/TInjA)
	- an efficient SSTI + CSTI scanner which utilizes novel polyglots
		```
		tinja url -u "http://example.com/?name=Kirlia" -H "Authentication: Bearer ey..."
		tinja url -u "http://example.com/" -d "username=Kirlia"  -c "PHPSESSID=ABC123..."
		```
2. [SSTImap](https://github.com/vladko312/sstimap)
	```
	python3 sstimap.py -i -l 5
	python3 sstimap.py -u "http://example.com/" --crawl 5 --forms
	python3 sstimap.py -u "https://example.com/page?name=John" -s
	```
3. [Tplmap](https://github.com/epinna/tplmap)
	```
	python2.7 ./tplmap.py -u 'http://www.target.com/page?name=John*' --os-shell
	python2.7 ./tplmap.py -u "http://192.168.56.101:3000/ti?user=*&comment=supercomment&link"
	python2.7 ./tplmap.py -u "http://192.168.56.101:3000/ti?user=InjectHere*&comment=A&link" --level 5 -e jade
	```
4. [Template Injection Table](https://github.com/Hackmanit/template-injection-table)
	- an interactive table containing the most efficient template injection polyglots along with the expected responses of the 44 most important template engines.
### Manual Identification
![[Pasted image 20240531172317.png]]
## Exploit 
### Reading 
- read documentation 
	- learn basic syntax 
Labs:
[[Basic Server-Side Template Injection]]
[[Basic server-side template injection (code context)]]
### Security Documentation
- read security section in documentation 
	- if no security section, there might be warnings about built-in objects or functions
Lab: [[Server-side template injection in an unknown language with a documented exploit]]
### Explore 
- many template engines expose a "self" or "environment" object of some kind, which acts like a namespace containing all objects, methods, and attributes that are supported by the template engine 
	- if such an object exists, you can potentially use it to generate a list of objects that are in scope
- in java templating languages, can list all variables with the following:'
	`${T(java.lang.System).getenv()}`
- can use Burp Intruder to brute-force variable names
### Developer-Supplied Objects 
- websites can contain custom, site-specific objects supplied by the web developer
	- these objects likely contain sensitive information 