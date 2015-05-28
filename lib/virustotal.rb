# encoding: utf-8

module VirusTotal
	APP_NAME = "virustotal"
	VERSION = "2.1.0"
	CONFIG_FILE = "~/.virustotal"
end

require 'json'
require 'rest_client'
require 'optparse'
require 'yaml'

require 'virustotal/application'
require 'virustotal/virustotal'
require 'virustotal/result'
