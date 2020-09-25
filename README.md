# WinrmTool

### Command Line Usage

usage: WinRMTool.py [-h] [--host HOST] [--username USERNAME] [--useSSL]
                    (--hash HASH | --password PASSWORD | --kerberos)
                    --powershell_script POWERSHELL_SCRIPT |
                    --powershell_command POWERSHELL_COMMAND | --shell |
                    --command COMMAND)

parsing arguments

optional arguments:
  -h, --help            show this help message and exit

Main arguments:
  --host HOST           host to connect to
  --username USERNAME   username to login with
  --useSSL              specify if using winrm over https
  --hash HASH           Ntlm hash to connect with
  --password PASSWORD   password to login with
  --kerberos            specifiy if using a kerberos auth (must have tgt)
  --powershell_script POWERSHELL_SCRIPT
                        path to powershell script
  --powershell_command POWERSHELL_COMMAND
                        run powershell command
  --shell               open a shell look like powershell(but only oneliners
                        works)
  --command COMMAND     cmd command to run on remote host

examples:
                                                            NTLM
    ============================================================================================================================================
    python winrm_ntlm.py --host 10.100.102.100 --username "weber\ansible" --password "A123a123" --powershell_command "Get-ADComputer -Filter *"
    python winrm_ntlm.py --host 10.100.102.100 --username "weber\ansible" --hash "7bb16b7c77a30c947ac16a79f0b8a111" --command "ipconfig /all"
    python winrm_ntlm.py --host 10.100.102.100 --username "weber\ansible" --password "A123a123" --shell
    ============================================================================================================================================

                                                            KERBEROS
    ============================================================================================================================================
                                                Please notice that in kerberos you must use fqdn

    python winrm_ntlm.py --host weberdc.weber.com --kerberos --command "ipconfig /all"
    python winrm_ntlm.py --host weberdc.weber.com --kerberos --shell
    ============================================================================================================================================

                                                    Specical shell commands
    ============================================================================================================================================
    PS WinrmTool> upload "<src path>" "<dest path>"
    PS WinrmTool> download "<dest path>" "<src path>"

    PS WinrmTool> upload "/root/file.txt" "c:\temp\file.txt"
    PS WinrmTool> download "c:\temp\file.txt" "/root/file.txt"
    ============================================================================================================================================
