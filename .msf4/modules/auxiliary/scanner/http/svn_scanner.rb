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
        OptString.new('TARGETURI', [ true, "The test path to .svn directory", '/']),
        OptBool.new('GET_SOURCE', [ false, "Attempt to obtain file source code", true ])
      ], self.class)
  end

  def peer
    "#{rhost}:#{rport}"
  end

  def svn_entry(url, filename)
    t_url = normalize_uri(url, '/.svn/text-base/', "#{filename}.svn-base")

    return unless datastore['GET_SOURCE']
    res = send_request_cgi({ 'uri' => t_url })
    retuen unless res && res.code == 200
    return if res.body.blank?

    path = store_loot(
      t_url,
      'text/plain',
      datastore['RHOST'],
      res.body,
      t_url)
    print_good("Saved file to: #{path}")
  end

  def svn_entries_url(url)
    normalize_uri(url, '/.svn/entries')
  end

  def svn_entries(url)
    authors = []
    dirs = []
    files = []

    res = send_request_cgi({ 'uri' => svn_entries_url(url) })

    if res && res.code == 200
      temp_line = ''
      if res.body
        res.body.split("\n").each do |line|
          if line == 'has-props' # code developer
            authors << temp_line unless temp_line.blank?
          elsif line == 'file' # source code file
            t_file = svn_entry(url, temp_line) unless temp_line.blank?
            files << t_file unless t_file.blank?
          elsif line == 'dir' # directory
            unless temp_line.blank?
              dirs << temp_line if temp_line
              t_authors, t_dirs, t_files = svn_entries(normalize_uri(url, temp_line))
              authors |= t_authors unless t_authors.blank?
              dirs |= t_dirs unless t_dirs.blank?
              files |= t_files unless t_files.blank?
            end
          end
          temp_line = line
        end
      end

      unless authors.blank? && dirs.blank? && files.blank?
        print_good("[#{peer}] SVN Entries file found.")
        report_note(
          host: rhost,
          port: rport,
          proto: 'tcp',
          type: 'svn_disclosure',
          data: { authors: authors, dirs: dirs, files: files }
        )
      end
    end
    [authors, dirs, files]
  end

  def run_host(target_host)
    vprint_status("#{peer} - scanning svn disclosure")
    vhost = datastore['VHOST'] || wmap_target_host
    svn_entries(normalize_uri(target_uri.path))
  end
end
