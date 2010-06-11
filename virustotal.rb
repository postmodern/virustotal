#!/usr/bin/env ruby

#Jacob Hammack
#jacob.hammack@hammackj.com
#http://www.hammackj.com

#01-31-2010: JPH - Updated a output bug on the usage statement. Thanks to smithj for finding it.
#06-10-2010: JPH - Added debug output
#06-10-2010: JPH - Added a check for the invalid hash error that seems to happen on some MD5 hashes
#06-10-2010: JPH - Added a timer between hash lookups from files

require 'optparse'
require "net/http"
require "uri"

$options = {}
$options["xml"] = false
$version = "1.3"

files = Array.new
hashes = Array.new

# Displays the results of the virustotal query
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
def fetch_results_from_hash(hash)
	results = Array.new
	hash = hash.chomp
	
	begin
		puts "[*] Attempting to query hash #{hash}"  unless $options["debug"] != true
		wres = Net::HTTP.post_form(URI.parse('http://www.virustotal.com/vt/en/consultamd5'), {'hash' => hash})
		
		puts "[*] #{wres.body}" unless $options["debug"] != true
		
		if wres.body =~ /notfound/
			fres = Hash.new
			fres['hash'] = hash
			fres['scanner'] = '-'
			fres['version'] = '-'
			fres['date'] = '-'
			fres['result'] = "Hash Not Found"
			
			results.push fres
		elsif wres.body =~ /invalid/
			fres = Hash.new
			fres['hash'] = hash
			fres['scanner'] = '-'
			fres['version'] = '-'
			fres['date'] = '-'
			fres['result'] = "Invalid Hash"
			
			results.push fres		
		else
			if wres.body=~ /(analisis\/[A-Fa-f0-9]*-[A-Fa-f0-9]*)/
				uri = "http://www.virustotal.com/" + $1;		
				hres = Net::HTTP.get_response(URI.parse(uri))

				if hres.kind_of?(Net::HTTPRedirection)
					new_url = hres['Location']
					hres = Net::HTTP.get_response(URI.parse(new_url))
				end 
								
				hres.body.scan(/<tr.*>\n<td>(.*)<\/td>\n<td>(.*)<\/td>\n<td>(.*)<\/td>\n<td.*>(.*)<\/td>\n<\/tr>\n/) { |scanner, version, date, result| 
					fres = Hash.new
					if result != '-'
						fres['hash'] = hash
						fres['scanner'] = scanner
						fres['version'] = version
						fres['date'] = date
						fres['result'] = result
											
						results.push fres
					end
				}
				
				if results.length == 0
    			fres = Hash.new
    			fres['hash'] = hash
    			fres['scanner'] = '-'
    			fres['version'] = '-'
    			fres['date'] = '-'
    			fres['result'] = "No AV Results"
    			
    			results.push fres				  
			  end
			  
			end			
		end	
	rescue Net::HTTP::Error => e	
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
