begin
  require 'bundler/setup'
rescue LoadError => error
  abort error.message
end

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

require 'rspec/core/rake_task'
RSpec::Core::RakeTask.new
