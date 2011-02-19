$LOAD_PATH.unshift File.expand_path("../lib", __FILE__)

require "virustotal"
 
task :build do
  system "gem build #{VirusTotal::APP_NAME}.gemspec"
end
 
task :release => :build do
  system "gem push #{VirusTotal::APP_NAME}-#{VirusTotal::VERSION}.gem"
end

task :clean do
	system "rm *.gem"
end
