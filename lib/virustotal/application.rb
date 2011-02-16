
module VirusTotal
	class Application
		def initialize(args)
			@options = {}
			@hashes = Array.new
			@files = Array.new
			@sites = Array.new
		end
		
		def parse_options(args)			
			opt = OptionParser.new do |opt|
				opt.banner =	"#{APP_NAME} v#{VERSION}\nJacob Hammack\nhttp://www.hammackj.com\n\n"
				opt.banner << "Usage: #{APP_NAME} <options>"
				opt.separator('')
				opt.separator("Search Options")
				
				opt.on('-h HASH', '--search-hash HASH', 'Searches a single hash on virustotal.com') { |hash| 
					@hashes.push(hash)
				}

				opt.on('-f FILE', '--search-file FILE', 'Searches a file of hashes on virustotal.com') { |file|
					if File.exists?(file)
						puts "[+] Adding file #{file}" unless @options["debug"] != true
						@files.push(file)
					else
						puts "[!] #{file} does not exist, please check your input!\n"
					end
				}	 

				opt.on('-s SITE', '--search-site SITE', 'Searches for a single url on virustotal.com') { |site| 
					@sites.push(site)
				}			
						
				opt.separator('')
				opt.separator('Output Options')

				opt.on('-x', '--xml-output', 'Print results as xml to stdout') {	
					@options["xml"] = true
				}
			
				opt.on('-y', '--yaml-output', 'Print results as yaml to stdout') {
					@options['yaml'] = true
				}

				opt.separator ''
				opt.separator 'Advanced Options'

				opt.on('-c', '--create-config', 'Creates a skeleton config file to use') do					
						if File.exists?(File.expand_path(CONFIG_FILE)) == false
							File.open(File.expand_path(CONFIG_FILE), 'w+') do |f| 
								f.write("virustotal: \n\tapi-key: \n\ttimeout: \n\n") 
							end

							puts "[*] An empty #{CONFIG_FILE} has been created. Please edit and fill in the correct values."
							exit
						else
							puts "[!]  #{CONFIG_FILE} already exists. Please delete it if you wish to re-create it."
							exit
						end
				end

				opt.on('-d', '--debug', 'Print verbose debug information') {
					@options["debug"] = true
				}
				
				opt.separator ''
				opt.separator 'Other Options'
				
				opt.on('-v', '--version', "Shows application version information") do
					puts "#{APP_NAME} - #{VERSION}"
					exit
				end

				opt.on_tail("-?", "--help", "Show this message") { |help|
					puts opt.to_s + "\n"
					exit
				} 
			end
			
			opts.parse!
			options			
		end
		
		def run(args)
			options = parse_options(args)
		end
		
		
	end
end