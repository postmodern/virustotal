# encoding: utf-8

module VirusTotal
	class VirusTotal
		
		# Creates a new instance of the [VirusTotal] class
		#
		# @return [VirusTotal] 
		def initialize(api_key, timeout = 7, debug = false)
			@api_key = api_key
			@timeout = timeout.to_i
			@debug = debug
		end
		
		# Queries a single hash on virustotal.com
		#
		# @return [VirusTotalResult] of the results from the query
		def query_hash hash
			begin
				puts "[*] Querying hash #{hash}" if @debug
				hash.chomp!
				if hash.include?('-')
						hash = hash.split('-')[0]
					end

				response = RestClient.post 'https://www.virustotal.com/api/get_file_report.json', { :resource => hash, :key => @api_key }
				results = VirusTotalResult.new hash, :hash, JSON.parse(response)
				
				return results
			rescue Exception => e		
				puts e.message
				puts e.backtrace.join("\n")
				STDERR.puts "[!] An error has occured. Retrying #{hash} in #{@timeout} seconds.\n"
				sleep @timeout #So we do not DOS virustotal.com we wait at least 5 seconds between each query
				retry
			end
		end
		
		# Queries a single url on virustotal.com
		#
		# @return [VirusTotalResult] of the results from the query
		def query_site url
			begin
				puts "[*] Querying url #{url}" if @debug

				response = RestClient.post 'https://www.virustotal.com/api/get_url_report.json', { :resource => url, :key => @api_key }
				results = VirusTotalResult.new url, :site, JSON.parse(response)
				
				return results
			rescue Exception => e		
				puts e.message
				puts e.backtrace.join("\n")
				STDERR.puts "[!] An error has occured. Retrying #{url} in #{@timeout} seconds\n"
				sleep @timeout #So we do not DOS virustotal.com we wait at least 5 seconds between each query
				retry
			end
		end		
		
		# Fetch results from virustotal using a specific hash
		#
		def query_upload file
			results = Array.new
			file = file.chomp

			begin
				puts "[*] Attempting to upload file #{file}" if @debug

				response = RestClient.post 'https://www.virustotal.com/api/scan_file.json', { :key => @api_key, :file => File.new(file, 'rb') }
				result = JSON.parse(response)

				puts "[*] File #{file} uploaded, waiting for results this could take several minutes..." if @debug

				if result['result']	== 1
					results = query_hash result['scan_id']
					
					while results.results[0]['result'] == "Hash Not Found"
						puts "[*] File has not been analyized yet, waiting 60 seconds to try again" if @debug
						sleep 60				
						results = query_hash result['scan_id']
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
				puts e.backtrace.join("\n")
				STDERR.puts "[!] An error has occured. Retrying #{file} in #{@timeout} seconds\n"
				sleep @timeout #So we do not DOS virustotal.com we wait at least 5 seconds between each query
				retry
			end

			return results
		end	
	end
end
