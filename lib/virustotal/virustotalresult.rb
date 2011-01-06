# encoding: utf-8

module VirusTotal
	
	#
	#
	#
	class VirusTotalResult
		
		#
		#
		def initialize result
			
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
		end		
		
		def to_display
		end
		
		def to_xml
		end
		
		def to_yaml
		end
	end
end
