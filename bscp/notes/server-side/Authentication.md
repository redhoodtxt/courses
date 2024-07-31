# Vulnerabilities In Password-Based Login 
## Username Enumeration 
- observing changes in the website behaviour to identify if given username is valid
- example of changes in website behaviour are what the website displays, such as: 
	- login pages - 'Valid username but incorrect password'
	- registration forms - 'Username is already taken'
- can hence create a shorter list of usernames for bruteforcing
## Brute-Force Attacks 
- bypass differs from brute-force :
	1. bypass : do not need to login and hence brute-force
	2. brute-force : need credentials to access
- use *Burp Intruder* for brute-force attacks on usernames and passwords
- *** brute-force username first, then password - much faster this way
- when brute-forcing, pay attention to : 
	1. HTTP status codes 
		- if configured well, status codes would be the same. if not, status code could be different, giving strong hint that the username is correct
	2. error messages
		- if not configured well, error messages could be different depending on whether username incorrect, password incorrect or both incorrect
	3. response times
		- if most requests handled with similiar response times, any deviation indicates that one of the credentials is correct
			- eg. the application will return a short response time when the username is wrong as it immediately recognizes that the username is not in the database and will hence not check the password
			- if the username is in the database, it will then check the password. This will take a longer time to check, creating a longer response time
				- inject excessively long password to purposefully decrease the response time
				- use the following string to inject as a long password : 
				  `very-long-strings-so-very-long-string-so-very-long-string-so-very-long-string-so-very-long-string-so-very-long-string-so-very-long-string-so-very-long-string-so-very-long-string-so-very-long-string-so-very-long-string-so-very-long-strings@dontwannacry.com.exploit-0afe007b03a34169c10b8fc501510091.exploit-server.net`
- if there is a IP ban for eg. 30 mins due to too many login attempts when brute-forcing:
	1. add the following header in the request: 
		- `X-Forwarded-For: 12.13.14.§15§` 
	2. use the *Pitchfork* attack and set the second defined point/payload to be the value of the username
		![[Pasted image 20240503155213.png]]12.13.14.
		
Labs: 
[[Username Enumeration Via Different Responses]]
[[Username Enumeration Via Response Timing]]
[[Broken Brute-Force Protection, IP Block]]
## Account Locking 
- when using the same username, too many incorrect logins (wrong passwords)
- use a max 3 passwords(if that is the limit) for each username and move on to the next to prevent account locking
- credential stuffing (using valid credentials from a data leaks) effective against account locking as it only tests each username once and passwords are usually reused. 
## User Rate Limiting 
- IP block after making too many login requests within a certain period of time
	- change IP using `X-Forwarded-For: 12.13.14.§15§` 
## HTTP Authentication 
- in HTTP basic authentication, the client receives an authentication token from the server, which is constructed by ==concatenating the username and password, and encoding it in Base64.== 
- this token is stored and managed by the browser, which automatically adds it to the ==Authorization header of every subsequent request as follows:==
	`Authorization: Basic base64(username:password)`
- vulnerable to brute-force 
# Vulnerabilities in Multi-Factor Authentication
- 2FA
## 2FA Authentication Tokens
- SMS, email, online banking tokens, RSA etc. 
## Bypassing 2FA 
- if the user is prompted to enter a verification code on a separate after entering a password, the user is in a "logged in" state before they have enter the verification code. 
- test to see if you can skip to the logged in page
Lab: [[2FA Simple Bypass]]
### Flawed 2FA Verification Logic 
- 2 step login process, one for password, another for verification code
- an attacker could log in using their own credentials but then change the value of the account cookie to any arbitrary username when submitting the verification code. 
1. user log in with their normal credentials 
	```
	POST /login-steps/first HTTP/1.1
	Host: vulnerable-website.com
	...
	username=carlos&password=qwerty
	```
1. Assigned a cookie for their account, before being brought to the verification code page
	```
	HTTP/1.1 200 OK
	Set-Cookie: account=carlos
	
	GET /login-steps/second HTTP/1.1
	Cookie: account=carlos
	```
1. When submitting the verification code, the request uses this cookie to determine which account the user is trying to access
2. IN THIS STEP (BEFORE SUBMITTING COOKIE, AT THE VERIFICATION CODE PAGE), attacker submit a request with the modified cookie as shown: 
	```
	POST /login-steps/second HTTP/1.1
	Host: vulnerable-website.com
	Cookie: account=victim-user
	...
	verification-code=123456
	```
# Vulnerabilities In Other Authentication Mechanisms
- vulnerabilities when changing or resetting their passwords
## Keeping Users Logged In 
- simple check box such as "Remember me"
	- uses a remember me token which is stored in a persistent cookie
	- this cookie allows you to bypass the whole login process
	- sometime can brute-force this cookie as it uses static values, eg. username and timestamp concatenated
	- sometimes the cookie is hashed without salt or encoded in base64, which offers no protection
- Note**: Use payloads processing to set the predefined points to a encoding or encryption if needed when bruteforcing the cookie, if you know the encoding or the encryption of the logged in cookie
Labs: 
[[Brute-forcing a stay-logged-in cookie]]
[[Offline Password Cracking (FINISH UP - XSS VULNERABILITY)]]
## Resetting User Passwords
### Reset By Email
- usually newly generated passwords that either expire after awhile or require immediate change sent over email
	- persistent passwords avoided
- not secure 
### Reset By URL 
- more robust 
- send users to password reset page
	- ==insecure: will have easily guessable parameters in the URL==:
		- `http://vulnerable-website.com/reset-password?user=victim-user`
			- can change the `user=` parameter to any valid username and change password
	- secure: high entropy, hard to guess token as parameter, used to create the reset URL
		- validation process - when user visits URL:
			1. system checks whether token exists on the back-end (validation)
			2. if it does exist, check which user's password it is supposed to reset 
			3. token validated again when reset form is submitted
			4. token should expire and be destroyed immediately after the password has been reset 
		1. ==insecure: sometimes, websites fail to validate token again when the reset form is submitted==
			- attacker will:
				1. visit the reset form with their own credentials
				2. delete the reset token and modify the user to be a victim username 
				3. submit the reset form to change the victim's password
Lab: [[Password Reset Broken Logic]]
- ==insecure: if the reset URL is generated dynamically, this is vulnerable to password reset poisoning==
	- attacker can steal another user's token and use it to change their password
### Password Reset Poisoning
- use `X-Forwarded-Host:<exploit_server>` to send the password reset page to your own server to exploit
	- `X-Forwarded-Host` header is used to preserve the original host information in HTTP requests that pass through proxy servers or load balancers, allowing servers to accurately determine the original host requested by the client
		- do not need to include `https://`
[[Password reset poisoning via middleware]]
## Password Change 
- changing password requires entering current password and new password twice
	- same process for checking username and password
- Password change functionality can be particularly dangerous if it allows an attacker to access it directly without being logged in as the victim user. 
	- For example, if the username is provided in a hidden field, an attacker might be able to edit this value in the request to target arbitrary users. This can potentially be exploited to enumerate usernames and brute-force passwords. 
- check for change in behaviour between the new passwords (*New Passwords Do Not Match* etc.)
	- brute-force the current password while searching for the error response
		![[Screenshot 2024-05-07 at 3.45.38 PM.png]]
# Persistence After Cookie-Stealing
![[Screenshot 2024-06-19 at 5.35.59 PM.png]]
- replace your cookie with the victim user cookie such that it always uses the victim user's cookie
