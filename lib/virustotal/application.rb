# encoding: utf-8

module VirusTotal
	class Application
		
		# Creates a new instance of the [Application] class
		#
		def initialize
			@options = {}
			@config = {}
			@hashes = Array.new
			@files_of_hashes = Array.new
			@sites = Array.new
			@uploads = Array.new
		end
		
		# Parses the command the line options and returns the parsed options hash
		#
		# @return [Hash] of the parsed options
		def parse_options(args)
			begin
				@options['output'] = :stdout
				@options['debug'] = false
				
				opt = OptionParser.new do |opt|
					opt.banner =	"#{APP_NAME} v#{VERSION}\nJacob Hammack\nhttp://www.hammackj.com\n\n"
					opt.banner << "Usage: #{APP_NAME} <options>"
					opt.separator('')
					opt.separator("Search Options")
				
					opt.on('-h HASH', '--search-hash HASH', 'Searches a single hash on virustotal.com') { |hash| 
						@hashes.push(hash)
					}

					opt.on('-f FILE', '--search-file FILE', 'Searches a each hash in a file of hashes on virustotal.com') { |file|
						if File.exists?(file)
							puts "[+] Adding file #{file}" if @options["debug"]
							@files_of_hashes.push(file)
						else
							puts "[!] #{file} does not exist, please check your input!\n"
						end
					}
					
					opt.on('-u FILE', '--upload-file FILE', 'Uploads a file to virustotal.com for analysis') do |file|
						if File.exists?(file)
							puts "[+] Adding file #{file}" if @options["debug"]
							@uploads.push(file)
						else
							puts "[!] #{file} does not exist, please check your input!\n"
						end
					end

					opt.on('-s SITE', '--search-site SITE', 'Searches for a single url on virustotal.com') { |site| 
						@sites.push(site)
					}			
						
					opt.separator('')
					opt.separator('Output Options')

					opt.on('-x', '--xml-output', 'Print results as xml to stdout') {	
						@options["output"] = :xml
					}
			
					opt.on('-y', '--yaml-output', 'Print results as yaml to stdout') {
						@options['output'] = :yaml
					}
					
					opt.on('--stdout-output', 'Print results as normal text line to stdout, this is default') {
						@options['output'] = :stdout
					}

					opt.separator ''
					opt.separator 'Advanced Options'

					opt.on('-c', '--create-config', 'Creates a skeleton config file to use') do					
						if File.exists?(File.expand_path(CONFIG_FILE)) == false
							File.open(File.expand_path(CONFIG_FILE), 'w+') do |f| 
								f.write("virustotal: \n  api-key: \n  timeout: 10\n\n") 
							end

							puts "[*] An empty #{File.expand_path(CONFIG_FILE)} has been created. Please edit and fill in the correct values."
							exit
						else
							puts "[!]  #{File.expand_path(CONFIG_FILE)} already exists. Please delete it if you wish to re-create it."
							exit
						end
					end

					opt.on('-d', '--debug', 'Print verbose debug information') do |d|
						@options["debug"] = d
					end
				
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
							
			  if ARGV.length != 0 
			    opt.parse!
			  else
			    puts opt.to_s + "\n"
				  exit
				end		
			rescue OptionParser::MissingArgument => m
				puts opt.to_s + "\n"
				exit
			end
		end
		
		# Loads the .virustotal config file for the api key
		#
		def load_config
			if File.exists?(File.expand_path(CONFIG_FILE))
				@config = YAML.load_file File.expand_path(CONFIG_FILE)
			else
				puts "[!] #{CONFIG_FILE} does not exist. Please run virustotal --create-config, to create it."
				exit
			end
		end
		
		# Processes all of the command line arguments and displays the results
		#
		def run(args)
			parse_options(args)		
			load_config
			
			vt = Client.new(@config["virustotal"]["api-key"], @config["virustotal"]["timeout"], @options["debug"])
			
			if @options['output'] == :stdout
				output_method = :to_stdout
			elsif @options['output'] == :yaml
				output_method = :to_yaml
			elsif @options['output'] == :xml
				output_method = :to_xml
				print "<results>\n"
			end
						
			if @files_of_hashes != nil
				@files_of_hashes.each do |file|
					f = File.open(file, 'r')

				  f.each do |hash|
				  	hash.chomp!
				    @hashes.push hash
				  end
				end
			end		
						
			if @hashes != nil
				@hashes.each do |hash|
					result = vt.query_hash hash					
					print result.send output_method
				end
			end
			
			if @sites != nil
				@sites.each do |site|
					result = vt.query_site site
					print result.send output_method
				end
			end
			
			if @uploads != nil
				@uploads.each do |upload|
					result = vt.query_upload upload
					print result.send output_method
				end
			end
			
			if @options['output'] == :xml
				print "</results>\n"
			end
		end		
	end
end
