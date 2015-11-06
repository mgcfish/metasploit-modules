##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Rsync Unauthenticated List Command',
      'Description' => 'List all (listable) modules from a rsync daemon',
      'Author'      => ['ikkini', 'Nixawk'],
      'References'  =>
        [
          ['URL', 'http://rsync.samba.org/ftp/rsync/rsync.html']
        ],
      'License'     => MSF_LICENSE
    )
    register_options(
      [
        Opt::RPORT(873),
        OptBool.new('AUTH_CHECK', [true, 'Check authentication or not', false])
      ], self.class)

    register_advanced_options(
      [
        OptInt.new('TIMEOUT', [false, 'Maximum number of seconds to wait rsync response', 4])
      ], self.class)
  end

  def rsync(dir)
    connect

    version = sock.get_once # server_initialisation
    return if version.blank?

    sock.get(datastore['TIMEOUT']) # server_motd
    sock.puts(version) # client_initialisation
    sock.puts(dir) # client_query
    data = sock.get(datastore['TIMEOUT']) # module_list
    data.gsub!('@RSYNCD: EXIT', '') unless data.blank?
    disconnect
    [version, data]
  end

  def auth?(ip, port, dir)
    _version, data = rsync(dir)
    if data && data =~ /RSYNCD: OK/m
      vprint_status("#{ip}:#{port}: #{dir} needs authentication: false")
      false
    else
      vprint_status("#{ip}:#{port}: #{dir} needs authentication: true")
      true
    end
  end

  def module_list_format(ip, port, module_list)
    mods = {}
    rows = []

    return if module_list.blank?

    module_list = module_list.strip
    module_list = module_list.split("\n")

    module_list.each do |mod|
      name, desc = mod.split("\t")
      name = name.strip
      next unless name

      if datastore['AUTH_CHECK']
        is_auth = "#{auth?(ip, port, name)}"
      else
        is_auth = 'Unknown'
      end

      rows << [name, desc, is_auth]
    end

    unless rows.blank?
      table = Msf::Ui::Console::Table.new(
        Msf::Ui::Console::Table::Style::Default,
        'Header'  => "rsync modules for #{ip}:#{port}",
        'Columns' =>
        [
          'Name',
          'Comment',
          'Authentication?'
        ],
        'Rows' => rows)
      vprint_line(table.to_s)
    end
    mods[ip] = rows
    return if mods.blank?
    path = store_loot(
      'rsync',
      'text/plain',
      ip,
      mods.to_json,
      'rsync')
    vprint_good('Saved file to: ' + path)
    mods
  end

  def run_host(ip)
    vprint_status("#{ip}:#{rport}")
    version, data = rsync('')
    return if data.blank?

    print_good("#{ip}:#{rport} - #{version.chomp} found")

    report_service(
      :host => ip,
      :port => rport,
      :proto => 'tcp',
      :name => 'rsync',
      :info => version.chomp
    )
    module_list_format(ip, rport, data)
  end
end
