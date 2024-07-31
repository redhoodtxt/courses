Vulnerability that allows an attacker to cause a server-side application to make connections to unintended locations, such as 
	- internal only services 
	- arbitrary external systems 
- In an SSRF attack against the server, the attacker causes the application to make an HTTP request back to the server that is hosting the application, via its loopback network interface
	 - This typically involves supplying a URL with a hostname like 127.0.0.1 (a reserved IP address that points to the loopback adapter) or localhost (a commonly used name for the same adapter).
# SSRF Against Back-End Systems
occasionally, a server is able to interact with other back-end systems that cannot be reached by users. 
	- These are located within the internal network of the organization, with non-routable IP addresses
		- 3 main types of IP : 
			- 10.x.x.x (usually Docker)
			- 172.x.x.x
			- 192.x.x.x
				- do a brute-force to obtain the IP address of the internal IP if it is not given 
- if the IP of the back-end system(eg. administrative interface) in the internal network is obtained, for example 192.168.0.68, An attacker can submit the following request to exploit the SSRF vulnerability, and access the administrative interface:
Labs:
[[Basic SSRF Against the Local Server]]
[[Basic SSRF Against Another Back-End System]]
# SSRF With Blacklist-Based Input Filters
- some applications block input containing hostnames like `127.0.0.1` and `localhost`, or sensitive URLs like `/admin`
- circumvention techniques:
	1. Use an alternative IP representation of 127.0.0.1, such as 2130706433, 017700000001, or 127.1.
    2. Register your own domain name that resolves to 127.0.0.1. You can use spoofed.burpcollaborator.net for this purpose.
    3. Obfuscate blocked strings using URL encoding or case variation.
    4. Provide a URL that you control, which redirects to the target URL. Try using different redirect codes, as well as different protocols for the target URL. For example, switching from an http: to https: URL during the redirect has been shown to bypass some anti-SSRF filters.
	    `http://trusted-website.com/redirect?url=http://127.0.0.1`
Lab: [[SSRF with blacklist-based input filter]]
# SSRF With Whitelist-Based Input Filters
 - some applications only allow inputs that match, a whitelist of permitted values. The filter may look for a match at the beginning of the input, or contained within in it. You may be able to bypass this filter by exploiting inconsistencies in URL parsing.
- the URL specification contains a number of features that are likely to be overlooked when URLs implement ad-hoc parsing and validation using this method:
    - you can embed credentials in a URL before the hostname, using the @ character. For example:
	    `https://expected-host:fakepassword@evil-host`
	- you can use the # character to indicate a URL fragment. For example:
    `https://evil-host#expected-host`
	- you can leverage the DNS naming hierarchy to place required input into a fully-qualified DNS name that you control. For example:
   `https://expected-host.evil-host`
    - you can URL-encode characters to confuse the URL-parsing code. This is particularly useful if the code that implements the filter handles URL-encoded characters differently than the code that performs the back-end HTTP request. You can also try double-encoding characters; some servers recursively URL-decode the input they receive, which can lead to further discrepancies.
    - you can use combinations of these techniques together.
# Bypassing SSRF Via Open Redirection
- use the following:
	`stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin`
# Blind SSRF Vulnerabilities
- occur if you can cause an application to issue a back-end HTTP request to a supplied URL, but the response from the back-end request is not returned in the application's front-end response
- use OAST techniques
	- use Burp Collaborator
# Other Vectors 
- `Referer` headers, URLs in data formats, partial URL in requests