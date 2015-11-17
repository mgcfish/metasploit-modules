##
## WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
## If you'd like to imporve this script, please try to port it as a post
## module instead. Thank you.
###


##
## Meterpreter script for setting up a route from within a
## Meterpreter session, without having to background the
## current session.

## References
#
# http://www.darkoperator.com/blog/2013/6/11/
# stealing-user-certificates-with-meterpreter-mimikatz-extensi.html
#
# Location: /opt/metasploit-framework/scripts/meterpreter/checkpriv.rb


session = client

@@exec_opts = Rex::Parser::Arguments.new(
  "-h" => [ false,"Help menu." ]
)

@@exec_opts.parse(args) { |opt, idx, val|
  case opt
  when "-h"
    print_line("CheckPriv -- Check Admin Token / SYSTEM Priv / UAC ebable")
    print_line("USAGE: run checkvm")
    print_line(@@exec_opts.usage)
    raise Rex::Script::Completed
  end
}

def checkpriv(session)
  print_status "Admin token: #{is_admin?()}"
  print_status "Running as SYSTEM: #{is_system?()}"
  print_status "UAC Enabled: #{is_uac_enabled?()}"
end

if client.platform =~ /win32|win64/
  checkpriv(session)
else
  print_error("This version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end
