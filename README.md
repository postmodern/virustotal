ruby-virustotal
===

ruby-virustotal is [virustotal](http://www.virustotal.com) automation and convenience tool for hash, file and URL submission.

The current version is 1.5.

Requirements
---

* ruby
* rubygems
* choice
* json
* rest-client

* public api key from virustotal.com

Installation
---

	% sudo gem install virustotal
	% virustotal [options]

Usage
---

### Searching a file of hashes

	% ./virustotal.rb -f <filewithhashesoneperline>

### Searching a single hash

	% ./virustotal.rb -s FD287794107630FA3116800E617466A9
 
### Searching a file of hashes and outputting to XML
	% ./virustotal.rb -f <filewithhashesoneperline> -x

### Upload a file to Virustotal and wait for analysis
	% ./virustotal.rb -u </path/to/file>

### Search for a single URL 
	% ./virustotal.rb -w "http://www.google.com"

Contact
---

You can reach me at Jacob[dot]Hammack[at]hammackj[dot]com or http://www.hammackj.com
