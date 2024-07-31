USE *AUTORIZE* BAPP
- It is applying constraints on who is authorised to perform actions or access resources. 
- Depends on authentication and session management
1. Authentication 
	- verifies that the user is who they say they are
2. Session Management
	- Keeps track of the subsequent HTTP requests that the user makes 
3. Access Control 
	- determines whether the user is allowed to carry out the action or access resources that they are attempting to do 
- Broken access controls are common and a high risk vulnerability.
# Vertical Privilege Escalation
	- When a user can gain access to functions that they are not allowed to access
	- non-admin gain access to admin page
## Unprotected Functionality 
- a non-admin user may be able to access the admin functionalities by browsing to the admin URL, if the functionality and the URL is not protected
- For example, a website might host sensitive functionality at the following URL:
	```url 
	https://insecure-website.com/admin
	```
- can also be hosted in `robots.txt` or any other directory that an attacker can use a wordlist to brute-force into
Lab: [[Unprotected Admin Functionality]]
### Unprotected Functionality - Obfuscated URL 
- may invoke 'security by obscurity', where random characters are added to the URL: 
`https://insecure-website.com/administrator-panel-yb556`
- the full URL may still be included in the code as such : 
	```html
	<script>
		var isAdmin = false;
		if (isAdmin) {
			...
			var adminPanelTag = document.createElement('a');
			adminPanelTag.setAttribute('https://insecure-website.com/administrator-panel-yb556');
			adminPanelTag.innerText = 'Admin panel';
			...
		}
	</script>
	```
- Attacker is still able to access the URL.
Lab: [[Unprotected Admin Functionality With Unpredictable URL]]
## Parameter Based Access Controls
 Some applications determine the user's access rights or role at login, and then store this information in a user-controllable location. This could be:
 - A hidden field.
 - A cookie.
 - A preset query string parameter.

The application makes access control decisions based on the submitted value. For example:
	```
	https://insecure-website.com/login/home.jsp?admin=true
	https://insecure-website.com/login/home.jsp?role=1
	```
This is a preset query string parameter. A user can modify the values in the parameter to gain access to the admin functions.

Lab : [[User Role Controlled By Request Parameter]]
# Horizontal Privilege Escalation
- An attacker gains access to another user's resources who has the same level of authorization
- For example, a user might access their own account page using the following URL:
	```URL
	https://insecure-website.com/myaccount?id=123
	```

- If an attacker modifies the id parameter value to that of another user, they might gain access to another user's account page, and the associated data and functions. 
- Common with IDORs
- Sometimes the parameter may not be a predictable value, can use GUIDs instead of incrementing numbers 
	- GUIDs can still be disclosed elsewhere in the application 
Lab: [[User ID Controlled by Request Parameter, With Unpredictable User IDs]]
# Horizontal To Vertical Privilege Escalation
- Compromising a more privileged user 
	- if the target user is a administrator
- techniques used is the same as in horizontal privilege escalation
# Broken access control resulting from platform misconfiguration
- Some applications enforce access controls at the platform layer. they do this by restricting access to specific URLs and HTTP methods based on the user's role. For example, an application might configure a rule as follows:
	`DENY: POST, /admin/deleteUser, managers`
- This rule denies access to the POST method on the URL /admin/deleteUser, for users in the managers group. Various things can go wrong in this situation, leading to access control bypasses.
- Some application frameworks support various non-standard HTTP headers that can be used to override the URL in the original request, such as X-Original-URL and X-Rewrite-URL. If a website uses rigorous front-end controls to restrict access based on the URL, but the application allows the URL to be overridden via a request header, then it might be possible to bypass the access controls using a request like the following:
	```
	POST / HTTP/1.1
	X-Original-URL: /admin/deleteUser
	...
	```
Lab: [[URL-based Access Control Can Be Circumvented]]