- **Serialization:** method of converting an object into a format that can be preserved, with the intent of either storing the object or transmitting it as part of a communication process
- **Deserialization:** involves taking data that has been structured in a specific format and reconstructing it back into an object
	- can manipulate serialized data to execute harmful code
![Pasted image 20240530101427](../../../../writeups/portswigger/images/Pasted%20image%2020240530101427.png)
- **Insecure Deserialization:** user-controllable data is deserialized by a website
# Identifying Insecure Deserialization 
- tip: use Burp Scanner to automatically flag out HTTP messages that appear to contain serialized objects
## PHP Serialization
1. following `User` object:
	````php
	$user->name = "carlos";
	$user->isLoggedIn = true;
	````
2. will look like this when serialized:
	`O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}`
3. interpreted as the following:
	`O:4:"User"` - An object with the 4-character class name "User"
	`2` - the object has 2 attributes
	`s:4:"name"` - The key of the first attribute is the 4-character string "name"
	`s:6:"carlos"` - The value of the first attribute is the 6-character string "carlos"
	`s:10:"isLoggedIn"` - The key of the second attribute is the 10-character string "isLoggedIn"
	`b:1` - The value of the second attribute is the boolean value true
	- native methods are `serialize()` and `unserialize()`
		- look for `unserialize()` anywhere in the source code
# Java Serialization
- serialized Java objects always begin with the same bytes, which are encoded as `ac ed` in hexadecimal and `ro0` in base64
- any class that implements the interface `java.io.Serializable` can be serialized and deserialized. 
- if have source code access, take note of code that uses `readObject` method
	- `readObject`: used to read and deserialize data from an `InputStream`
# Manipulating Serialized Objects 
- study the serialized data to identify and edit interesting attribute value
	- either edit the object directly in its byte stream form or write a short script in the corresponding language to create and serialize the new object yourself
		- latter easier
## Modifying Object Attributes
1. consider a website that uses a **serialized `User` object to store data about a user's session in a cookie**
2. if an attacker spotted this serialized object in an HTTP request, they might decode it to find the following byte stream:
	`O:4:"User":2:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:0;}`
3. the `isAdmin` attribute is an obvious point of interest. An attacker could simply change the boolean value of the attribute to 1 (true), re-encode the object, and overwrite their current cookie with this modified value. In isolation, this has no effect. However, let's say the website uses this cookie to check whether the current user has access to certain administrative functionality:
	```php
	$user = unserialize($_COOKIE);
	if ($user->isAdmin === true) {
	// allow access to admin interface
	}
	```
4. this vulnerable code would instantiate a User object based on the data from the cookie, including the attacker-modified isAdmin attribute. At no point is the authenticity of the serialized object checked. This data is then passed into the conditional statement and, in this case, would allow for an easy privilege escalation. 
Lab:[Modifying serialized objects](../../../../writeups/portswigger/Modifying%20serialized%20objects.md)
## Modifying Data Types
- PHP vulnerable to this due its loose comparison operator `==`
	- `5 == "5"` evaluates to `true`
	- `5 == "5 of something"` evaluates to `true` because PHP processes it as `5 == 5`, as long as it starts with a number
		- works for all alphanumeric strings
	- `0 == "Example string"` evaluates to `true`
		- because there is no numbers (0 numerals) hence it evaluates to true 
- attacker can manipulate this logic flaw
	```php
	$login = unserialize($_COOKIE)
	if ($login['password'] == $password) {
	// log in successfully
	}
	```
1. let's say an attacker modified the password attribute so that it contained the integer 0 instead of the expected string. As long as the stored password does not start with a number, the condition would always return true, enabling an authentication bypass. 
2. this is possible because deserialization preserves a data type
3. if the code fetched the password directly from the request, the 0 will be converted to a string and the condition will evaluate to a `false`
Lab: [Modifying serialized data types](../../../../writeups/portswigger/Modifying%20serialized%20data%20types.md)
**NOTE:** take note that when encoding the cookie after modifying it, the padding (`=`) must be correct if the encoding is base64. padding can be 0,1 or 2 `=` characters
# Using Application Functionality
- as part of a website's "Delete user" functionality, the user's profile picture is deleted by accessing the file path in the `$user->image_location` attribute. 
- if this `$user` was created from a serialized object, an attacker could exploit this by passing in a modified object with the `image_location` set to an arbitrary file path. Deleting their own user account would then delete this arbitrary file as well. 
Lab:[Using application functionality to exploit insecure deserialization](../../../../writeups/portswigger/Using%20application%20functionality%20to%20exploit%20insecure%20deserialization.md)
# Magic Methods
- invoked whenever a particular event occurs
	- indicated by prefixing or surrounding the method name with `__`
- some magic methods for PHP:
	- `__sleep`: Invoked when an object is being serialized. This method should return an array of the names of all properties of the object that should be serialized. It's commonly used to commit pending data or perform similar cleanup tasks.
	- `__wakeup`: Called when an object is being deserialized. It's used to reestablish any database connections that may have been lost during serialization and perform other reinitialization tasks.
	- `__unserialize`: This method is called instead of `__wakeup` (if it exists) when an object is being deserialized. It gives more control over the deserialization process compared to `__wakeup`.
	- `__destruct`: This method is called when an object is about to be destroyed or when the script ends. It's typically used for cleanup tasks, like closing file handles or database connections.
	- `__toString`: This method allows an object to be treated as a string. It can be used for reading a file or other tasks based on the function calls within it, effectively providing a textual representation of the object.
		```php
		class test {
		    public $s = "This is a test";
		    public function displaystring(){
		        echo $this->s.'<br />';
		    }
		    public function __toString()
		    {
		        echo '__toString method called';
		    }
		    public function __construct(){
		        echo "__construct method called";
		    }
		    public function __destruct(){
		        echo "__destruct method called";
		    }
		    public function __wakeup(){
		        echo "__wakeup method called";
		    }
		    public function __sleep(){
		        echo "__sleep method called";
		        return array("s"); #The "s" makes references to the public attribute
		    }
		}
		$o = new test();
		$o->displaystring();
		$ser=serialize($o);
		echo $ser;
		$unser=unserialize($ser);
		$unser->displaystring();
		
		/*
		php > $o = new test();
		__construct method called
		__destruct method called
		php > $o->displaystring();
		This is a test<br />
		
		php > $ser=serialize($o);
		__sleep method called
		
		php > echo $ser;
		O:4:"test":1:{s:1:"s";s:14:"This is a test";}
		
		php > $unser=unserialize($ser);
		__wakeup method called
		__destruct method called
		
		php > $unser->displaystring();
		This is a test<br />
		*/
		```
- in java, same applies to `ObjectInputStream.readObject()` method, which reads data from the initial byte stream and essentially acts like a constructor for "re-initializing" a serialized object
	- however, `Serializable` classes can also declare their own `readObject()` method as follows:
	```java
	private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException
	{
	    // implementation
	}
	```
# Injecting Arbitrary Objects
- if an attacker can manipulate which class of object is being passed in as serialized data, they can influence what code is executed after, and even during, deserialization. 
- you can pass in objects of any serializable class that is available to the website, and the object will be deserialized.
	- this effectively allows an attacker to create instances of arbitrary classes
Resources: https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection
# Gadget Chains
- **Gadget:** a snippet of code in the application that can help an attacker to achieve a particular goal 
	- attacker may just want to invoke a method that will pass their input into another gadget
	- by chaining multiple gadgets together(gadget chain), an attacker can potentially pass their input into a dangerous "sink gadget"
## Pre-Built Gadget Chains 
- use tools to identify and exploit insecure deserialization vulnerabilities
	- tools provide a range of pre-discovered chains that have been exploited on other websites 
### `ysoserial` - Tool For Java Deserialization
- this lets you choose one of the provided gadget chains for a library that you think the target application is using, then pass in a command that you want to execute
- it then creates an appropriate serialized object based on the selected chain
- ==use Java versions 15 and below!!==
	```console
	java -jar ysoserial-all.jar 
	   [payload] '[command]'
	```
- The above works for `jdk 15` and below
Lab: [Exploiting Java deserialization with Apache Commons](../../../../writeups/portswigger/Exploiting%20Java%20deserialization%20with%20Apache%20Commons.md)
### `PHPGGC` - Tool For PHP Deserialization (PHP Generic Gadget Chains)
- `ysoserial` for php
Lab: [Exploiting PHP deserialization with a pre-built gadget chain](../../../../writeups/portswigger/Exploiting%20PHP%20deserialization%20with%20a%20pre-built%20gadget%20chain.md)
### Working With Documented Gadget Chains
- look online to see if there are any documented exploits if there is no tool for a framework or language