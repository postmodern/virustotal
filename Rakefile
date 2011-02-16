$LOAD_PATH.unshift File.expand_path("../lib", __FILE__)
require "virustotal"
 
task :build do
  system "gem build projmgr.gemspec"
end
 
task :release => :build do
  system "gem push projmgr-#{VirusTotal::VERSION}.gem"
end

task :clean do
	system "rm *.gem"
end
