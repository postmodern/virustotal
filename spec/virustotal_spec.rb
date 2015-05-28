base = __FILE__
$:.unshift(File.join(File.dirname(base), '../lib'))

module VirusTotal
  describe "./bin/virustotal -h FD287794107630FA3116800E617466A9" do
    it "returns 47 results for FD287794107630FA3116800E617466A9" do
      cmd = IO.popen "./bin/virustotal -h FD287794107630FA3116800E617466A9"
      data = cmd.readlines
      cmd.close
      data.length.should == 47
 			sleep 7
    end
  end
  
  describe "./bin/virustotal -s 'http://www.google.com'" do
    it "returns 63 sites for 'http://www.google.com'" do
      cmd = IO.popen "./bin/virustotal -s \"http://www.google.com\""
      data = cmd.readlines
      cmd.close      
      data.length.should == 63
			sleep 7
    end
  end
end
