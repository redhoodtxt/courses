- information leakage - when website unintentionally reveals sensitive information to users
    - Revealing the names of hidden directories, their structure, and their contents via a robots.txt file or directory listing
    - Providing access to source code files via temporary backups
    - Explicitly mentioning database table or column names in error messages
    - Unnecessarily exposing highly sensitive information, such as credit card details
    - Hard-coding API keys, IP addresses, database credentials, and so on in the source code
    - Hinting at the existence or absence of resources, usernames, and so on via subtle differences in application behaviour
- main focus should be on the impact and exploitability of the information disclosure
# Detecting Information Disclosure Vulnerabilities
## Fuzzing 
- add  payload positions and use pre-built wordlists
- use grep matching rules for `error`, `invalid`, `SELECT` etc.
- use grep extraction 
## Burp Scanner
- live scanning feature
- right click any HTTP message - *Engagement tools*
## Burp Engagement Tools
- *Search*
- *Find comments*
- *Discover content*
## Engineering Informative Responses
- manipulate website to extract arbitrary data via error message
# Common Sources Of Information Disclosure
## Files For Web Crawlers 
- `/robots.txt`
- `sitemap.xml`
## Directory Listings
- web servers can be configured to list contents of directories that do not have a page present
	- can aid attacker to quickly identify resources at a given path
## Developer Comments
- inline HTML comments 
## Error Messages
- verbose error messages 
Lab: [[Information Disclosure In Error Messages]]
## Debugging Data 
- custom error messages that contain a lot of information for the purpose of debugging
	- eg. 
		- Values for key session variables that can be manipulated via user input
		- Hostnames and credentials for back-end components
		- File and directory names on the server
		- Keys used to encrypt data transmitted via the client
- view source and look for comments that can lead to configs, such as `phpinfo.php`
## User Account Pages 
- user profile will contain:
	- user's email address, phone number, API key, and so on
- `GET /user/personal-info?user=carlos`
- check if can change the user parameter
## Source Code Disclosure From Backup Files
- API keys and credentials can be hard coded into the source code
- identify open-source technology
- trick servers into display eg.`.php` files as text instead of executing them
	- different file extension (.txt) or appending `~` to the filename
Lab: [[Source Code Disclosure Via Backup Files]]
## Insecure Configuration 
- when developers use 3rd party technologies with many configuration options
	- misconfiguration from not knowing how to use the options 
- use HTTP `TRACE` method to banner grab information - echos the request in the response body to see what changes are made
	- can lead to information disclosure
		- eg. internal authentication headers may be appended to requests by reverse proxies
Lab: [[Authentication Bypass Via Information Disclosure]]
## Version Control History
- all websites' version control data stored in `.git` folder
	- append `./git` the url and `wget -r` to download to desktop
		- use git commands  to read committed changes or logs etc.
			- will give access to some snippets of source code