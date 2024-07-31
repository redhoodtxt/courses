# ROE
- stage #1 - access any user account
- stage #2 - use user account to access the admin interface "/admin" by elevating your privileges or compromising the administrator's account
- stage #3 - Use the admin interface to read the contents of "/home/carlos/flag.txt" from the server's filesystem, and submit it.


While exploiting the web application, you will gain access to powerful functionalities. If you use this to delete your own account or a core system component, you may make your exam impossible to complete.

There is usually an administrator account with the username "admin" or "administrator" and a lower-privileged account called "carlos" most of the time. If you have identified a user enumeration vulnerability, you may be able to break into a low-privileged account using this username list and password list. In some rare cases where you have to or enumerate undiscovered endpoints or crack hashes, you may be required to use the standard directory or "rockyou.txt" wordlist from the standard Kali Linux distributions.

You can expect the three stages to be completed in order. This means that if you are in an application, attempting to break into the admin interface is a waste of time if you haven't yet got access to a user account. Likewise, we do not recommend attempting to read files if you don't have access to an administrator's account.

## Scope
A vulnerable website will be generated for you to attack and exploit. The vulnerable website will be hosted under the "jubilian.com" domain. Please refrain from launching DDoS attacks against the website as there are limited resources. Additionally, do not attack the platform website or assessment portal (web.jubilian.io).

## Progression
To progress through stages, you will not only need to identify multiple vulnerabilities, but also exploit them. For example, if you identified an XSS vulnerability, triggering "alert" execution won't be enough to get access to the next stage: you need to actually exploit it against one of the simulated users and steal their session. Likewise, for SQL Injection vulnerabilities, you need to extract credentials from the database and use them to access the target account. You don't need to worry about tedious dumping of all database content though: all tables, columns, and local files are easily guessable and require just a couple of minutes to manually extract the required password or token. In the event where you identify a SSRF vulnerability for the third stage, you can use it to read files by accessing an internal-only service, running on localhost at port 6566.
## Tools
During your assessment, there might be tools that will be made available to help you exploit the vulnerable web application. An exploit server, a log server and an email server will be provided for you during your exploitation whenever it's needed. Other tools such as ysoserial, sqlmap, hashcat, dirbuster or fuff might also prove helpful for you.

For the easy and normal challenges, using Burp Suite Professional alone should suffice. However, you are likely required to utilize tools outside of Burp Suite Professional for the hard challenges as the hard challenges assesses on knowledge and understanding beyond the basics of using Burp Suite Professional.

## Techniques
Scanning selected pages and insertion points with Burp Suite Professional will often help you quickly progress through faster. Attempting to run a full scan will not be feasible within the time frame. Some vulnerabilities are are very challenging to detect using only manual testing. If you get stuck, it is highly recommend that you use Burp Scanner to help you tackle the problem.

## Simulated User Activities
Each application has up to two active users, who will be logged in either as a normal user or an administrator. You can assume that they will visit various pages of the site with Google Chrome every few minutes and click on any link or content you send them. You can use the exploit server's "Deliver" functionality to exploit them with reflected vulnerabilities.
## Integrity & Professionalism
Do not cheat or share your answers with others. You may discuss the techniques involved but you are not allowed to share solutions with each other as that defeats the whole purpose of this challenge. If you are guilty of cheating, your account and IP might be permanently banned.
## Difficulty
On a scale of 1 to 10, easy challenges range from 1 to 5, normal challenges from 5 to 7, and hard challenges from 6 to 10. The difficulty of the Burp Suite Certified Practitioner (BSCP) Certification assessment falls within the range of 4 to 7
Feedback / Reporting

If you discover any vulnerabilities or encounter any issues with this website or your challenges, please don't hesitate to contact the Administrator & Developer: Jubilian Ho.
