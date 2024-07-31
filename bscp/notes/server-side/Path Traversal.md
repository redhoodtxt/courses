USE FUZZING - PATH TRAVERSAL PREDEFINED PAYLOADS 
- enable attacker to access files and directories that are stored outside the root folder
- By manipulating variables that reference files with “dot-dot-slash (../)” sequences and its variations or by using absolute file paths, it may be possible to access arbitrary files and directories stored on file system, eg.
	- application source code or configuration 
	- critical system files
	- credentials for back-end systems
- imagine a shopping application that displays images of items for sale. This might load an image using the following HTML:
	```
	<img src="/loadImage?filename=218.png">
	```
- `loadImage` URL takes a `filename` parameter and returns the contents of the specified file. The image files are stored on disk in the location `/var/www/images/`. 
- To return an image, the application reads from the following file path:
	`/var/www/images/218.png`
- ==insecure: this application implements no defenses against path traversal attacks. As a result, an attacker can request the following URL to retrieve the /etc/passwd file from the server's filesystem:==
	`https://insecure-website.com/loadImage?filename=../../../etc/passwd`
	- This causes the application to read from the following file path:
		`/var/www/images/../../../etc/passwd`
		- The three consecutive ../ sequences step up from `/var/www/images/` to the filesystem root, and so the file that is actually read is:
			`/etc/passwd`
- if an application strips or blocks path traversal from user inputs, can be bypass with diff techniques
	- eg. using absolute path to reference to a sensitive file
Lab: [[File Path Traversal, Traversal Sequences Blocked With Absolute Path Bypass]]
# Nested Traversal Sequences
- if an application uses stripping of path traversal (stripping `../` we can bypass this by using nested path traversal:
	- `....//` - when application strips 1 there is still another 
	- `....\/` - when you don't know whether the application strips forward or backwards
# URL Encoding Traversal Sequences
- URL-encode the traversal sequences 
	- use *fuzzing - path traversal* in Burp 
# Prefix 
- application may require that the base folder is present `/var/www/images`
	`filename=/var/www/images/../../../etc/passwd`
# File Extension 
- application may require the parameter value to end with an expected file extension 
	- use null bytes to bypass 
		`filename=../../../etc/passwd%00.png`