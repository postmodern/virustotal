# ruby-virustotal

ruby-virustotal is [virustotal](http://www.virustotal.com) automation and convenience tool for hash, file and URL submission.

The current version is 2.0.

## Requirements

* ruby
* rubygems
* json
* rest-client

* public api key from [virustotal.com](http://www.virustotal.com)

## Installation

	% gem install virustotal
	% virustotal [options]

## Usage

### Searching a file of hashes

	% virustotal -f <file_with_hashes_one_per_line>

### Searching a single hash

	% virustotal -h FD287794107630FA3116800E617466A9
 
### Searching a file of hashes and outputting to XML
	% virustotal -f <file_with_hashes_one_per_line> -x

### Upload a file to Virustotal and wait for analysis
	% virustotal -u </path/to/file>

### Search for a single URL 
	% virustotal -s "http://www.google.com"

## Contact

You can reach me at Jacob[dot]Hammack[at]hammackj[dot]com or http://www.hammackj.com
