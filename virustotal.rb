

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
