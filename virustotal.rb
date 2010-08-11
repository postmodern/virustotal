#!/usr/bin/env ruby

#Jacob Hammack
#jacob.hammack@hammackj.com
#http://www.hammackj.com

#01-31-2010: JPH - Updated a output bug on the usage statement. Thanks to smithj for finding it.
#06-10-2010: JPH - Added debug output
#06-10-2010: JPH - Added a check for the invalid hash error that seems to happen on some MD5 hashes
#06-10-2010: JPH - Added a timer between hash lookups from files
#08-10-2010: JPH - Modified to use the new virustotal api, the code has been simplified.

require 'rubygems'
require 'json'
require 'optparse'
require "net/http"
require "net/https"
require "uri"


$options = {}
$options["xml"] = false
$version = "1.4"

$api_key = "<INSERT KEY HERE>"

files = Array.new
hashes = Array.new

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
      puts "[*] Looking up hash #{line}" unless $options["debug"] != true
      result = fetch_results_from_hash(line)
      sleep 5 #So we do not DOS virustotal.com we wait 5 seconds between each query
      display_output(result)
    }
end

# Fetch results from virustotal using a specific hash
#
def fetch_results_from_hash(hash)
	results = Array.new
	hash = hash.chomp
	
	begin
		puts "[*] Attempting to query hash #{hash}"  unless $options["debug"] != true
		
		uri = URI.parse('https://www.virustotal.com/api/get_file_report.json')
		params = {:resource => hash, :key => $api_key }

		http = Net::HTTP.new(uri.host, uri.port)
		http.use_ssl = true
		http.verify_mode = OpenSSL::SSL::VERIFY_NONE

		request = Net::HTTP::Post.new(uri.path)
		request.set_form_data(params)
		
		req = Net::HTTP::Post.new(uri.path + '?' + request.body)
		response = http.request(req)		
		result = JSON.parse(response.read_body)
		
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
		STDERR.puts "[!] An error has occured. Retrying %s\n", hash
		sleep 5 #So we do not DOS virustotal.com we wait 5 seconds between each query
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
      result = fetch_results_from_hash(hash)
      display_output(result)
    }
  end
  
  if $options["xml"] == true
    puts "</results>"
  end
end
