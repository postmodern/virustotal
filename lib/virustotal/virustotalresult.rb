# encoding: utf-8

module VirusTotal
	
	# A Wrapper class for the results from a virustotal.com
	# 
	# @author Jacob Hammack <jacob.hammack@hammackj.com>
	class VirusTotalResult		
		attr_accessor :results
		
		# Creates a 
		#
		def initialize hash, type, result
			@type = type
			@results = Array.new
			fres = Hash.new		
			
			if result["result"] == 0
					
				fres = Hash.new
				fres['hash'] = hash
				fres['scanner'] = '-'
				fres['date'] = '-'
				fres['permalink'] = '-'
				
				if @type == :hash
					fres['result'] = "Hash Not Found"
				elsif @type == :site
					fres['result'] = "Site Not Found"
				end

				@results.push fres
			elsif result["result"] == -1
				puts "[!] Invalid API KEY! Please correct this!"
				exit
			else				
				permalink = result["permalink"]
				date = result["report"][0]
				result["report"][1].each do |scanner, res|
					if res != ''
						fres = Hash.new
						fres['hash'] = hash
						fres['scanner'] = scanner
						fres['date'] = date
						fres['permalink'] = permalink unless permalink == nil
						fres['result'] = res

						@results.push fres
					end
				end
			end
			
			#if we didn't have any results let create a fake not found
			if @results.size == 0
				fres = Hash.new
				fres['hash'] = hash
				fres['scanner'] = '-'
				fres['date'] = '-'
				fres['permalink'] = '-'
				if @type == :hash
					fres['result'] = "Hash Not Found"
				elsif @type == :site
					fres['result'] = "Site Not Found"
				end
				@results.push fres				
			end			
		end
		
		# Prints the [VirusTotalResult] object to screen
		#
		def to_stdout
			result_string = String.new
			@results.each do |result|
				result_string << "#{result['hash']}: Scanner: #{result['scanner']} Result: #{result['result']}\n"
			end
			print result_string
		end
				
		# Prints the [VirusTotalResult] object as a xml string to the screen
		#
		def to_xml
			result_string = String.new
			@results.each do |result|
				result_string << "\t<vtresult>\n"
				result_string << "\t\t<hash>#{result['hash']}</hash>\n"
				result_string << "\t\t<scanner>#{result['scanner']}</scanner>\n"
				result_string << "\t\t<date>#{result['date']}</date>\n"
				result_string << "\t\t<permalink>#{result['permalink']}</permalink>\n" unless result['permalink'] == nil
				result_string << "\t\t<result>#{result['result']}</result>\n"
				result_string << "\t</vtresult>\n"
			end
			print result_string			
		end
		
		# Prints the [VirusTotalResult] object as a yaml string to the screen
		#
		def to_yaml
			result_string = String.new
			@results.each do |result|
				result_string << "vt-result:\n"
				result_string << "  hash: #{result['hash']}\n"
				result_string << "  scanner: #{result['scanner']}\n"
				result_string << "  date: #{result['date']}\n"
				result_string << "  permalink: #{result['permalink']}\n" unless result['permalink'] == nil
				result_string << "  result: #{result['result']}\n\n"
			end
			print result_string
		end
	end
end
