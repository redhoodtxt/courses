application logic flaws
- different types, depends on the context
# Excessive Trust In Client-Side Controls
- assumes that user only interacts with the web interface and not the backend
	- hence there is extensive controls on the client side but no validation of input from the server side
	- attackers can manipulate the input that is passed to the server side
		- renders client side controls useless
Labs:
[[2FA Broken Logic]]
[[Excessive Trust In Client-Side Controls]]
# Allowing Unconventional Input 
```php
$transferAmount = $_POST['amount'];
$currentBalance = $user->getBalance();

if ($transferAmount <= $currentBalance) {
    // Complete the transfer
} else {
    // Block the transfer: insufficient funds
}
```
- in the above code for transferring money, as long as the transfer amount is less than the available amount of the attacker, it will facilitate a transfer 
	- this means that you can also supply a negative amount as a transfer (if there is this flaw)
	- this will be interpreted as receiving money from the victim instead of sending money
	- as negative amount for transfer is still less than the available balance, the transfer will go through
- use Burp to send unconventional values 
	- note that the maximum possible integer value will be 2,147,483,647
Labs: 
[[Low-Level Logic Flaw]]
[[Inconsistent handling of exceptional input]]

# Flawed Assumptions About User Behaviour
## Trusted User Won't Always Remain Trustworthy
Lab: [[Inconsistent security controls]]
## User Won't Supply Mandatory Input
- remove one parameter at a time and see application response
	- delete the name of the parameter and the value
- follow multi-stage processes through completion 
- applies to both `URL` and `POST` parameters
	- remember to check cookies too
Lab: 
[[Weak isolation on dual-use endpoint]]
[[Password Reset Broken Logic]]
## User Will Not Follow Intended Sequence
- use repeater to perform forced browsing to submit requests in an unintended sequence
	- skip steps, access a single step more than once, return to earlier steps
		- take note of how different steps are accessed
- this type of testing will cause exceptions because expected variables have null or uninitialised values
	- play close attention to any error messages or debug info 
Lab: [[2FA Simple Bypass]]
# Domain-Specific Flaws
- logic flaws specific to the domain of or the purpose of the site
## Flaw In Discounting Functionality
- business logic could fail to check if an order was changed after the discount was applied 
	- attacker could simply add items to hit the threshold for discount, apply the discount and then remove the items 
- manipulate such that the applied adjustments take in effect even after the original criteria is not satisfied
### Tips
- use Burp *Macro* to automate a series of requests.
	- Burp Macros: https://akshita-infosec.medium.com/burp-macros-what-why-how-151df8901641
Labs:
[[Flawed enforcement of business rules]]
[[Infinite money logic flaw]]
# Providing An Encryption Oracle
- encryption oracle: user-controllable input is encrypted and the resulting ciphertext is then made available to the user in some way
	- An attacker can use this input to encrypt arbitrary data using the correct algorithm and asymmetric key. 
- dangerous when there are other user-controllable inputs in the application that expect data encrypted with the same algorithm
- an attacker could potentially use the encryption oracle to generate valid, encrypted input and then pass it into other sensitive functions
-  issue can be compounded if there is another user-controllable input on the site that provides the reverse function
	-  enable the attacker to decrypt other data to identify the expected structure. 
Lab: [[Authentication bypass via encryption oracle]]
