#!/usr/bin/env ruby

#Jacob Hammack
#jacob.hammack@hammackj.com
#http://www.hammackj.com

#01-31-2010: JPH - Updated a output bug on the usage statement. Thanks to smithj for finding it.
#06-10-2010: JPH - Added debug output
#06-10-2010: JPH - Added a check for the invalid hash error that seems to happen on some MD5 hashes
#06-10-2010: JPH - Added a timer between hash lookups from files
#08-10-2010: JPH - Modified to use the new virustotal api, the code has been simplified.
#08-11-2010: JPH - Added file upload option -u, so that files can be uploaded and waits for results
#08-11-2010: JPH - Added a url scan option -w, so that urls can be scanned using the new api
#08-27-2010: JPH - Cleaned up some dead code
#								 - Added URL for the report for easier web viewing.