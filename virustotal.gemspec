# encoding: utf-8

base = __FILE__
$:.unshift(File.join(File.dirname(base), 'lib'))

require 'virustotal'

Gem::Specification.new do |s|
	s.name 									= 'virustotal'
	s.version 							= VirusTotal::VERSION
	s.homepage 							= "http://github.com/hammackj/ruby-virustotal/"
	s.summary 							= "virustotal"
	s.description 					= "virustotal is a script for automating virustotal.com queries"
	s.license								= "BSD"
	
	s.author 								= "Jacob Hammack"
	s.email 								= "jacob.hammack@hammackj.com"
	
	s.files 								= Dir['[A-Z]*'] + Dir['lib/**/*'] + ['virustotal.gemspec']
	s.default_executable 		= 'virustotal'
	s.executables 					= ['virustotal']
	s.require_paths 				= ["lib"]
	
	s.required_rubygems_version = ">= 1.3.6"
	s.rubyforge_project         = "virustotal"
	
	s.add_development_dependency "rspec"
	
	s.has_rdoc 							= 'yard'
	s.extra_rdoc_files 			= ["README.md", "LICENSE", "NEWS.md", "TODO.md"]
	
	s.add_dependency('choice', '>= 0.1.4')
	s.add_dependency('json', '>= 1.4.6')
	s.add_dependency('restclient', '>= 1.6.1')
	
end
