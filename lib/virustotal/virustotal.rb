# encoding: utf-8

module VirusTotal
	class VirusTotal
		
		# Creates a new instance of the [VirusTotal] class
		#
		# @return [VirusTotal] 
		def initialize api_key, timeout
			@api_key = api_key
			@timeout = timeout
		end
		
		#
		#
		def query_hash hash
			begin
				#puts "[*] Querying hash #{hash}"  unless $options["debug"] != true

				response = RestClient.post 'https://www.virustotal.com/api/get_file_report.json', { :resource => hash, :key => @api_key }
				result = VirusTotalResult.new JSON.parse(response)

			rescue Exception => e		
				puts e.message
				STDERR.puts "[!] An error has occured. Retrying #{hash} in #{$timeout} seconds.\n"
				sleep $timeout #So we do not DOS virustotal.com we wait 5 seconds between each query
				retry
			end
		end
		
		#
		#
		def query_site site
			begin
				#puts "[*] Querying url #{url}"  unless $options["debug"] != true

				response = RestClient.post 'https://www.virustotal.com/api/get_url_report.json', { :resource => url, :key => $api_key }
				result = VirusTotalResult.new JSON.parse(response)
				
			rescue Exception => e		
				puts e.message
				STDERR.puts "[!] An error has occured. Retrying #{url}\n"
				sleep $timeout #So we do not DOS virustotal.com we wait 5 seconds between each query
				retry
			end
		end
		
	end
end
