##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanServer
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'HTTP Subversion Scanner',
      'Description' => 'Detect subversion directories and files and analize its content.',
      'Author'      => ['et', 'Nixawk'],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('TARGETURI', [ true, "The test path to .svn directory", '/'])
      ], self.class)
  end

  def uri(path)
    full_uri =~ %r{/$} ? "#{full_uri}#{path}" : "#{full_uri}/#{path}"
  end

  def svn_entries_parse(resp)
    return if resp.blank?
    authors = []
    dirs = []
    files = []
    temp_line = ''
    resp.split("\n").each do |line|
      if line == 'has-props' # code developer
        authors << temp_line unless temp_line.blank?
      elsif line == 'file' # source code file
        files << temp_line unless temp_line.blank?
      elsif line == 'dir' # directory
        dirs << temp_line unless temp_line.blank?
      end
      temp_line = line
    end
    {authors: authors, dirs: dirs, files: files}
  end

  def svn_entries(url)
    svn_uri = normalize_uri(url, '.svn/entries')
    peer_uri = uri('.svn/entries')
    res = send_request_cgi({
      'uri' => svn_uri
    })

    unless res
      vprint_error("#{peer_uri} - No response received")
      return
    end
    vprint_status("#{peer_uri} - HTTP/#{res.proto} #{res.code} #{res.message}")
    return unless res.code == 200

    records = svn_entries_parse(res.body)
    unless records[:authors].blank? && records[:dirs].blank? && records[:files].blank?
      print_good("#{peer_uri} - svn entries file found with #{records}.")

      report_note(
        host: rhost,
        port: rport,
        proto: 'tcp',
        type: 'svn_disclosure',
        data: records
      )
      path = store_loot('svn_entries', 'text/plain', rhost, res.body, peer_uri)
      print_good("Saved file to: #{path}")
    end
  end

  def run_host(target_host)
    vprint_status("#{full_uri} - scanning svn disclosure")
    svn_entries(target_uri.path)
  end
end
