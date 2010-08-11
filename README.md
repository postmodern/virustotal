ruby-virustotal
===

ruby-virustotal is [virustotal](http://www.virustotal.org) hash and file submitter, to automate the process

The current version is 1.4b.

Requirements
---

* ruby
* rubygems
* choice
* json
* rest-client

* public api key from virustotal.com

Usage
---

### Searching a file of hashes

	% ./virustotal.rb -f <filewithhashesoneperline>

### Seaching a single hash

	% ./virustotal.rb -s FD287794107630FA3116800E617466A9
 
### Searching a file of hashes and outputing to XML
	% ./virustotal.rb -f <filewithhashesoneperline> -x

### Upload a file to Virustotal and wait for analysis
	% ./virustotal.rb -u </path/to/file>

### Search for a single url 
	% ./virustotal.rb -w "http://www.google.com"

Contact
---

You can reach me at jacob[dot]hammack[at]hammackj[dot]com.
