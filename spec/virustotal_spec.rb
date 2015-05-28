base = __FILE__
$:.unshift(File.join(File.dirname(base), '../lib'))

describe "./bin/virustotal" do
  def run(arguments)
    cmd = IO.popen "./bin/virustotal #{arguments}"
    data = cmd.readlines
    cmd.close
    yield data
    sleep 7
  end

  context "with -h FD287794107630FA3116800E617466A9" do
    it "returns 47 results for FD287794107630FA3116800E617466A9" do
      run "-h FD287794107630FA3116800E617466A9" do |data|
        expect(data.length).to eq(47)
      end
    end
  end
  
  context "with -s 'http://www.google.com'" do
    it "returns 63 sites for 'http://www.google.com'" do
      run "-s http://www.google.com" do |data|
        expect(data.length).to eq(63)
      end
    end
  end
end
