##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  RSYNC_HEADER = '@RSYNCD:'

  AUTH_REQURED = 'Authentication Required'
  AUTH_HEADER_OK = 'Header OK'
  AUTH_UNEXPECTED = 'Unexpected Response'
  AUTH_NO_RESPONSE = 'No Response'

  def initialize
    super(
      'Name'        => 'List Rsync Modules',
      'Description' => %q(
        An rsync module is essentially a directory share.  These modules can
        optionally be protected by a password.  This module connects to and
        negotiates with an rsync server, lists the available modules and,
        optionally, determines if the module requires a password to access.
      ),
      'Author'      => [
        'ikkini', # original metasploit module
        'Jon Hart <jon_hart[at]rapid7.com>', # improved metasploit module
        'Nixawk' # improved metasploit module
      ],
      'References'  =>
        [
          ['URL', 'http://rsync.samba.org/ftp/rsync/rsync.html']
        ],
      'License'     => MSF_LICENSE
    )
    register_options(
      [
        Opt::RPORT(873),
        OptBool.new('TEST_AUTHENTICATION', [true, 'Test if the rsync module requires authentication', true])
      ], self.class)

    register_advanced_options(
      [
        OptBool.new('SHOW_MOTD', [true, 'Show the rsync motd, if found', false]),
        OptBool.new('SHOW_VERSION', [true, 'Show the rsync version', false]),
        OptInt.new('READ_TIMEOUT', [true, 'Seconds to wait while reading rsync responses', 2])
      ], self.class)
  end

  def peer
    "#{rhost}:#{rport}"
  end

  def read_timeout
    datastore['READ_TIMEOUT']
  end

  def parse_rsync_rule(response)
    rsyncds = [] # @RSYNCD: *
    motds = [] # Message of the day
    if response
      response.strip!
      response.split(/\n/).map do |l|
        l =~ /^#{RSYNC_HEADER}/ ? (rsyncds << l) : (motds << l)
      end
    end
    [rsyncds, motds]
  end

  def get_rsync_exit_state(rmodule, resp)
    if rmodule.empty? && resp && resp =~ /#{RSYNC_HEADER} EXIT/
      true
    else
      false
    end
  end

  def get_rsync_auth_state(rmodule, resp)
    if resp
      vprint_status("#{peer} trying to auth #{rmodule}")
      if resp =~ /#{RSYNC_HEADER} AUTHREQD/
        AUTH_REQURED
      elsif resp =~ /#{RSYNC_HEADER} OK/
        AUTH_HEADER_OK
      else
        vprint_error("#{peer} - unexpected response when connecting to #{rmodule}")
        AUTH_UNEXPECTED
      end
    else
      vprint_error("#{peer} - no response when connecting to #{rmodule}")
      AUTH_NO_RESPONSE
    end
  end

  def rsync(modulename)
    begin
      state = 'No Authentication'
      rsyncds = []
      motds = []

      # A RSYNC client upon connecting should receive the ASCII string
      # "@RSYNC: 31.0" ended by a [l]LF.
      connect

      version = sock.get_once(-1, read_timeout)
      if version
        motds << version

        # Next the client should expect the Message of the Day (MOTD),
        # this is multiple lines, again, seperated by a LF. The client
        # should continue reading data until a [2]Empty line is found.

        resp = sock.get(read_timeout)
        if resp
          rs, ms = parse_rsync_rule(resp)
          rsyncds |= rs
          motds |= ms
        end

        # Now the client should respond with "@RSYNCD: 31.0" terminated
        # by a LF.
        sock.puts(version)

        # If the client sends a LF with no module name , the client should
        # expect ASCII strings seperated by LFs, the client should terminate the
        # connection upon receiving "@RSYNCD: EXIT"(LF)

        # If the client sends a module name terminated by LF, and the module is
        # present, and doesn't require authentication, a "@RSYNCD: OK"(LF) is
        # sent. If the modules is not present an "@ERROR: data"(LF) is sent to
        # the client. If authentication a "@RSYNCD: AUTHREQ <challenge>" is
        # sent, in which case the client must respond with <user> <response>
        # where 'response' is the MD4 hash of password+challenge in base64.

        sock.puts("#{modulename}\n")

        resp = sock.get(read_timeout)
        if resp
          rs, ms = parse_rsync_rule(resp)
          rsyncds |= rs
          motds |= ms
        end

        exit_status = get_rsync_exit_state(modulename, resp)
        if !exit_status && datastore['TEST_AUTHENTICATION']
          state = get_rsync_auth_state(modulename, resp)
        end
      end

    ensure
      disconnect
    end
    [version, state, rsyncds, motds]
  end

  def get_rsync_modules(motds)
    modules = []
    return if motds.blank?

    motds.each do |motd|
      name, desc = motd.split("\t") if motd && motd.include?("\t")
      next unless name
      name = name.strip
      modules << [name, desc]
    end
    modules
  end

  def run_host(ip)
    version, state, rsyncds, motds = rsync('')
    return if version.blank?

    modules = get_rsync_modules(motds)
    report_note(
      host: ip,
      port: rport,
      proto: 'tcp',
      type: 'rsync_modules',
      data: {
        version: version,
        state: state,
        rsyncds: rsyncds,
        motds: motds
      })

    print_status("#{peer} - rsync version: #{version.chomp}") if version && datastore['SHOW_VERSION']
    print_status("#{peer} - rsync MOTD: #{rsyncds}") if rsyncds && datastore['SHOW_MOTD']

    return if modules.blank?
    print_good("#{peer} - #{modules.size} rsync modules found: #{modules.join(', ')}")

    rows = []
    modules.each do |name, desc|
      version, state, rsyncds, motds = rsync(name)
      rows << [name, desc, state]
    end

    return if rows.blank?
    table = Msf::Ui::Console::Table.new(
      Msf::Ui::Console::Table::Style::Default,
      'Header'  => "rsync modules for #{peer}",
      'Columns' =>
      [
        'Name',
        'Comment',
        'Authentication?'
      ],
      'Rows' => rows)
    vprint_line(table.to_s)
  end

  def setup
    fail_with(Failure::BadConfig, 'READ_TIMEOUT must be > 0') if read_timeout <= 0
  end
end
