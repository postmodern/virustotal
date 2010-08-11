#!/usr/bin/env ruby

#Jacob Hammack
#jacob.hammack@hammackj.com
#http://www.hammackj.com

#01-31-2010: JPH - Updated a output bug on the usage statement. Thanks to smithj for finding it.
#06-10-2010: JPH - Added debug output
#06-10-2010: JPH - Added a check for the invalid hash error that seems to happen on some MD5 hashes
#06-10-2010: JPH - Added a timer between hash lookups from files
#08-10-2010: JPH - Modified to use the new virustotal api, the code has been simplified.
#08-11-2010: JPH - Added file upload option -u, so that files can be uploaded and waits for results
#08-11-2010: JPH - Added a url scan option -w, so that urls can be scanned using the new api

require 'rubygems'
require 'json' 					#sudo gem install json
require 'optparse'
#require "net/http"
#require "net/https"
#require "uri"

require "rest_client" 	#sudo gem install rest-client


$options = {}
$options["xml"] = false
$version = "1.4b"
$timeout = 16

$api_key = "<INSERT KEY HERE>"

files = Array.new
hashes = Array.new
uploads = Array.new
sites = Array.new

# Displays the results of the virustotal query
#
def display_output (results)
    results.each { |res|
      if $options["xml"] == true
        printf "\t<result>\n"
        printf "\t\t<hash>%s</hash>\n", res["hash"]
        printf "\t\t<scanner>%s</scanner>\n", res["scanner"]
        printf "\t\t<scandate>%s</scandate>\n", res["date"]
        printf "\t\t<scannerresult>%s</scannerresult>\n", res["result"]
        printf "\t</result>\n"
      else
        printf "%s: Scanner: %s Result: %s\n", res['hash'], res['scanner'], res['result']        
      end
    }
end

# Fetches results from virustotal using a input file
#
def fetch_results_from_file(file)
  inputHashes = File.open(file, 'r')
  
  inputHashes.each { |line|
      line.chomp!
      result = fetch_results_from_hash(line)   
      display_output(result)
			sleep $timeout #So we do not DOS virustotal.com we wait 5 seconds between each query
    }
end

# Fetches a hash or vt timestamped hash results from vt
#
def rest_fetch_results_from_hash(hash)
	results = Array.new
	hash = hash.chomp
	
	if hash.include?('-')
		hash = hash.split('-')[0]
	end
	
	begin
		puts "[*] Querying hash #{hash}"  unless $options["debug"] != true
		
		response = RestClient.post 'https://www.virustotal.com/api/get_file_report.json', { :resource => hash, :key => $api_key }

		result = JSON.parse(response)
		
		if result["result"] == 0
			fres = Hash.new
			fres['hash'] = hash
			fres['scanner'] = '-'
			fres['version'] = '-'
			fres['date'] = '-'
			fres['result'] = "Hash Not Found"
			
			results.push fres
		else		
			result["report"][1].each do |scanner, res|
				if res != ''
					fres = Hash.new
					fres['hash'] = hash
					fres['scanner'] = scanner
					fres['version'] = '-'
					fres['date'] = '-'
					fres['result'] = res
					
					results.push fres
				end
			end
		end
	rescue Exception => e		
		puts e.message
		STDERR.puts "[!] An error has occured. Retrying #{hash}\n"
		sleep $timeout #So we do not DOS virustotal.com we wait 5 seconds between each query
		retry
	end

	if results.length == 0
			fres = Hash.new
			fres['hash'] = hash
			fres['scanner'] = '-'
			fres['version'] = '-'
			fres['date'] = '-'
			fres['result'] = "No Antivirus Results"
			
			results.push fres	
	end
	
	return results
end


# Fetches a hash or vt timestamped hash results from vt
#
def rest_fetch_results_from_url(url)
	results = Array.new
	url = url.chomp
	
	begin
		puts "[*] Querying url #{url}"  unless $options["debug"] != true
		
		response = RestClient.post 'https://www.virustotal.com/api/get_url_report.json', { :resource => url, :key => $api_key }
		result = JSON.parse(response)

		if result["result"] == 0
			fres = Hash.new
			fres['hash'] = url
			fres['scanner'] = '-'
			fres['version'] = '-'
			fres['date'] = '-'
			fres['result'] = "Url Not Found"
			
			results.push fres
		else		
			result["report"][1].each do |scanner, res|
				if res != ''
					fres = Hash.new
					fres['hash'] = url
					fres['scanner'] = scanner
					fres['version'] = '-'
					fres['date'] = '-'
					fres['result'] = res
					
					results.push fres
				end
			end
		end
	rescue Exception => e		
		puts e.message
		STDERR.puts "[!] An error has occured. Retrying #{url}\n"
		sleep $timeout #So we do not DOS virustotal.com we wait 5 seconds between each query
		retry
	end

	if results.length == 0
			fres = Hash.new
			fres['hash'] = hash
			fres['scanner'] = '-'
			fres['version'] = '-'
			fres['date'] = '-'
			fres['result'] = "No Scanner Results"
			
			results.push fres	
	end

	return results
end

# Fetch results from virustotal using a specific hash
#
def rest_upload_and_fetch_results_from_file(file)
	results = Array.new
	file = file.chomp
	
	begin
		puts "[*] Attempting to upload file #{file}"  unless $options["debug"] != true
		
		response = RestClient.post 'https://www.virustotal.com/api/scan_file.json', { :key => $api_key, :file => File.new(file, 'rb') }
		result = JSON.parse(response)

		puts "[*] File #{file} uploaded, waiting for results this could take several minutes..."  unless $options["debug"] != true

		if result['result']	== 1
			results = rest_fetch_results_from_hash(result['scan_id'])

			while results[0]['result'] == "Hash Not Found"
				puts "[*] File has not been analyized yet, waiting 60 seconds to try again"  unless $options["debug"] != true
				sleep 60				
				results = rest_fetch_results_from_hash(result['scan_id'])
			end
		elsif result['result'] == -2
			puts "[!] Virustotal limits exceeded, ***do not edit the time out values.***"
		else
			fres = Hash.new
			fres['hash'] = file
			fres['scanner'] = '-'
			fres['version'] = '-'
			fres['date'] = '-'
			fres['result'] = "File failed to upload"
			
			results.push fres
		end
	rescue Exception => e		
		puts e.message
		STDERR.puts "[!] An error has occured. Retrying #{file}\n"
		sleep $timeout #So we do not DOS virustotal.com we wait 5 seconds between each query
		retry
	end
	
	return results
end

# Setup the option parsing for command line arguments
opt = OptionParser.new { |opt|
  opt.banner =  "virustotal.rb v#{$version}\nJacob Hammack\nhttp://www.hammackj.com\n\n"
  opt.banner << "[*] Usage: #{$0} [mode] <options> [targets]"
  opt.separator('')
  opt.separator('Modes:')

  opt.on('-x', '--xml-output', 'Print results as xml to stdout') {  
    $options["xml"] = true
  } 

  opt.on('-f FILE', '--search-file FILE', 'Searches a file of hashes on virus total') { |file| 
    if File.exist?(file)
    	puts "[+] Adding hash #{file}" unless $options["debug"] != true
      files.push(file)
    else
      printf "[!] %s does not exist, please check your input!\n", file
    end
  }
  
  opt.on('-s HASH', '--search-hash HASH', 'Searches a single hash on virus total') { |hash| 
    hashes.push(hash)
  }

  opt.on('-u FILE', '--upload-file FILE', 'Uploads a file and waits for results') { |file| 
    uploads.push(file)
  }  

  opt.on('-w SITE', '--web-site SITE', 'Searches for a single url on virustotal') { |site| 
    sites.push(site)
  }  

	opt.on('-d', '--debug', 'Print verbose debug information') {
		$options["debug"] = true
	}
  
  opt.on_tail("-h", "--help", "Show this message") { |help|
    puts opt.to_s + "\n"
    exit
  } 
}

begin
	if $api_key == "<INSERT KEY HERE>"
		puts "[!] You must obtain a api key from virustotal.com"
		
		exit
	end
	
  if ARGV.length != 0 
    opt.parse!
  else
    puts opt.to_s + "\n"
  end
  
  puts ARGV
  if $options["xml"] == true
    puts "<results>"
  end
  
  if !files.empty?
    files.each { |file|
      fetch_results_from_file(file)
    }
  end
  
  if !hashes.empty?
    hashes.each { |hash|
      result = rest_fetch_results_from_hash(hash)
      display_output(result)
    }
  end

	if !uploads.empty?
		uploads.each do |file|
			result = rest_upload_and_fetch_results_from_file(file)
			display_output(result)
		end
	end

	if !sites.empty?
		sites.each do |site|
			result = rest_fetch_results_from_url(site)
			display_output(result)
		end
	end
  
  if $options["xml"] == true
    puts "</results>"
  end
end
