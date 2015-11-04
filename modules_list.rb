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
  end

  def rsync(dir)
    connect

    version = sock.get_once # server_initialisation
    return if version.blank?

    sock.get # server_motd

    sock.puts(version) # client_initialisation
    sock.puts(dir) # client_query

    data = sock.get # module_list
    data.gsub!('@RSYNCD: EXIT', '') if data # Final module list
    disconnect
    data
  end

  def auth?(dir)
    data = rsync(dir)
    if data && data =~ /RSYNCD: OK/m
      false
    else
      true
    end
  end

  def module_list_format(module_list)
    mods = []
    rows = []

    return if module_list.blank?

    module_list = module_list.strip
    module_list = module_list.split("\n")

    module_list.each do |mod|
      name, desc = mod.split("\t")
      name = name.strip
      mods << { name: name, desc: desc } if name

      if datastore['AUTH_CHECK']
        rows << [name, desc, "#{auth?(name)}"]
      else
        rows << [name, desc, 'Unknown']
      end
    end

    table = Msf::Ui::Console::Table.new(
      Msf::Ui::Console::Table::Style::Default,
      'Columns' =>
      [
        'Name',
        'Comment',
        'Authentication?'
      ],
      'Rows' => rows)
    vprint_line(table.to_s)
    mods
  end

  def run_host(ip)
    data = rsync('')
    return if data.blank?

    print_good("#{ip}:#{rport} - rsync found")
    report_service(
      :host => ip,
      :port => rport,
      :proto => 'tcp',
      :name => 'rsync'
    )

    mods = module_list_format(data)
    return if mods.blank?

    report_note(
      :host => ip,
      :proto => 'tcp',
      :port => rport,
      :type => 'rsync_list',
      :data => mods.to_s
    )
  end
end
