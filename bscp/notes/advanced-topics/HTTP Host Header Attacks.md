# HTTP Host Headers & HTTP Host Header Attacks
## HTTP Host Headers
- mandatory request header as of HTTP/1.1
	- specifies the domain name that the client wants to access
## Host Header Attacks 
- aka host header injections 
- exploit vulnerable websites that handle the value of `Host` header if a server implicitly trust the `Host` header without proper validation or escaping it 
- arises because `Host` header is user controllable, but assumed to not be as such
	- can perform a variety of attacks like 
		- web cache poisoning
		- logic flaws 
		- routing based SSRF 
		- server side vulnerabilities like SQLi
# HTTP Host Header Attack Methodology 
## 1. Supply Arbitrary Host Header
- make sure to use Burp when doing this so that it separates the `Host` header from the target IP address
- if you are still able to access the application after supplying arbitrary domain, it is likely that the application is vulnerable to host header injections
	- this can happen because some applications use a default option which contains the domain for loading the application 
		- if the `Host` header value is one that they do not recognize, then they will use the default option
- if the application is not configured with a default option, then may receive `Invalid Host header` error
	- likely if target is accessed via a CDN 
## 2. Check For Flawed Validation 
- instead of receiving an `Invalid Host header` response, the request is blocked as a result of some security measure 
	- eg. some websites will validate whether the `Host` header matches the SNI from the TLS handshake
- understand how the website parses `Host` header
eg. parsing algorithms will only validate the domain name in `Host` header
### Non-Numeric Port
- if you are able to pass in a non-numeric port, can inject a payload via the port to reach the target application 
	```
	GET /example HTTP/1.1
	Host: vulnerable-website.com:bad-stuff-here
	```
### Matching Logic
- can pass in a arbitrary domain name with the same number sequence of characters as the whitelisted one
	```
	GET /example HTTP/1.1
	Host: notvulnerable-website.com
	```
### Using Less Secure Compromised Domain
- inject a less-secure subdomain that you have compromised
	```
	GET /example HTTP/1.1
	Host: hacked-subdomain.vulnerable-website.com
	```
## 3. Send Ambiguous Requests
- the code that validates the host and the code that does something vulnerable with it often reside in different application components or even on separate servers
	- may be able to issue an ambiguous request that appears to have a different host depending on which system is looking at it
### Inject Duplicate Host Headers
- while uncommon, still can be done as developers might not anticipate this scenario as a browser is unlikely to send such a request 
- common for one of the 2 headers to be given precedence over the other one
- if the front end and back end disagree about which header is the correct one, can lead to discrepancies that can be exploited 
	- eg. front end prefers the first header instance, the second header prefer second instance
		- can use the first header to route to the intended target and second header to pass payload to the back end
			```
			GET /example HTTP/1.1
			Host: vulnerable-website.com
			Host: bad-stuff-here
			```
### Supply An Absolute URL
- although request lines typically specifies a relative path on the requested domain, many servers are also configured to understand the requests for absolute URLs
- ambiguity caused by supplying both an absolute URL and `Host` header can lead to discrepancies be systems 
	- usually request line is given precedence but this is not always the case
	- can exploit this 
		```
		GET https://vulnerable-website.com/ HTTP/1.1
		Host: bad-stuff-here
		```
	- may have to experiment with different protocols (HTTP vs HTTPS)
### Add Line Wrapping 
- can indent HTTP headers with a space character
	- some servers will interpret the indented header as part of the preceding values error, which can cause discrepancies
		```
		GET /example HTTP/1.1
		    Host: bad-stuff-here
		Host: vulnerable-website.com
		```
	- if the front end ignores the indented header, the request will be processed as an ordinary for `vulnerable-website.com` where it gives precedence to the second instance of `Host` header
	- if the back end ignores the leading space in the first instance of the `Host` header, it will prefer the first instance of the `Host` header
		- this can allow s to pass arbitrary values via the wrapped `Host` header
## 4. Inject Host Override Headers
- use other headers designed for the same purpose to inject payload
	```
	GET /example HTTP/1.1
	Host: vulnerable-website.com
	X-Forwarded-Host: bad-stuff-here
	```
- there are sometimes intermediary systems between the front-end and back-end (load balancers, reverse proxies etc.).
	- the `Host` header that the back-end receives may contain the domain name for one of these intermediary systems.
		- to solve this issue, front-end may inject the `X-Forwarded-Host` to contain the original `Host` header value.
			- hence when this header is present, many frameworks will refer to this
			- can use other headers like 
				```
				X-Host
				X-Forwarded-Server
				X-HTTP-Host-Override
				Forwarded
				```
			- use Param Miner to check for supported headers
# Exploiting HTTP Host Headers
## Password Reset Poisoning 
- attacker manipulates website into generating password reset link that gets sent to a domain under their control
### How It Works
1. The user enters their username or email address and submits a password reset request.
2. The website checks that this user exists and then generates a temporary, unique, high-entropy token, which it associates with the user's account on the back-end.
3. The website sends an email to the user that contains a link for resetting their password. The user's unique reset token is included as a query parameter in the corresponding URL:
4. https://normal-website.com/reset?token=0a1b2c3d4e5f6g7h8i9j
5. When the user visits this URL, the website checks whether the provided token is valid and uses it to determine which account is being reset. If everything is as expected, the user is given the option to enter a new password. Finally, the token is destroyed.
### Constructing Password Reset Poisoning Attack
1. The attacker obtains the victim's email address or username, as required, and submits a password reset request on their behalf. When submitting the form, they intercept the resulting HTTP request and modify the Host header so that it points to a domain that they control. For this example, we'll use evil-user.net.
2. The victim receives a genuine password reset email directly from the website. This seems to contain an ordinary link to reset their password and, crucially, contains a valid password reset token that is associated with their account. However, the domain name in the URL points to the attacker's server:
3. https://evil-user.net/reset?token=0a1b2c3d4e5f6g7h8i9j
4. If the victim clicks this link (or it is fetched in some other way, for example, by an antivirus scanner) the password reset token will be delivered to the attacker's server (access log)
5. The attacker can now visit the real URL for the vulnerable website and supply the victim's stolen token via the corresponding parameter. They will then be able to reset the user's password to whatever they like and subsequently log in to their account.
Lab: [[Basic password reset poisoning]]
## Web Cache Poisoning Via Host Headers
- using `Host` header to reflect XSS is useless without if the target does not use a web cache
	- can use the cache to serve a poisoned response
- can use ambiguous requests
Lab: [[Web cache poisoning via ambiguous requests]]
## Accessing Restricted Functionality 
- some websites make flawed assumptions about a user's access control
	- can be bypassed by modifying the `Host` header
Lab: [[Host header authentication bypass]]
## Accessing Internal Websites With Virtual Host Brute-Forcing
- sometimes companies host publicly accessible websites and private, internal sites on the same server
	- servers usually have public and private IP address, therefore scenario cannot always be detected simply by looking at DNS records, or the internal site might not even have a public DNS record associated with it
		- attacker can typically access any virtual host on any server if they can guess the hostnames, found the hostnames through other means like information disclosure, using Burp to brute-force virtual hosts
## Routing-Based SSRF
- use `Host` header to launch SSRF attacks
1. use Burp Collaborator 
	- supply domain of the Collaborator server in the `Host` header
	- if can receive DNS lookup from the target server or another in-path system, indicates that can route requests 
2. exploit internal systems
	- identify private IP addresses used in the target's internal network
		- see if iP addresses are leaked by the application 
		- can also scan hostnames belonging to company to see if they resolve to a private IP address
		- can also brute-forcing standard private IP ranges, like `192.168.0.0/16`
			- remember to uncheck the *Update host headers to match target* option
### CIDR
`<8 bits>.<8 bits>.<8 bits>.<8 bits>`
in `192.168.0.0/24`, it indicates that the first 24 bits (`192.168.0`) are all fixed and does not change. hence the range is for the last 8 bits or the last digit in the IP 
Labs: 
[[Routing-based SSRF]]
[[SSRF via flawed request parsing]]

## Connection State Attacks 
- many websites reuse connections for multiple request/response cycles with the same client
- sometimes servers assume that `Host` headers are identical for all HTTP/1.1 requests sent over the same connection
	- server may perform validation on the first request they receive over a new connection and not check repeated ones
	- can send the first connection with the expected `Host` header, then use *Repeater* to send the request with the malicious payload down the same connection 
### Connection State Attack Method
1. send the plain request to the *Repeater*(request #1)
2. duplicate request #1 and modify it such that it has the target internal IP and the target request line (request #2)
3. right click each request and add both requests to a tab group
4. select *Send group in sequence(single connection)* to place these 2 requests in one HTTP connection ``
5. change the `Connection` in both requests to `keep-alive`.
Reference: [Connection state attacks](https://infosecwriteups.com/connect-state-attack-first-request-validation-2bea8e42a647)
Lab: [[Host validation bypass via connection state attack]]