#! /usr/bin/python2.7
import argparse
from winrm.protocol import Protocol
from base64 import b64encode,b64decode
import unicodedata
import xmltodict
import sys
import re
import readline #imported for history feature

RED = '\033[91m'
GREEN = '\033[92m'
ENDC = '\033[0m'

examples = '''examples:
                                                            NTLM
    ============================================================================================================================================
    python WinrmTool.py --host 10.100.102.100 --username "weber\\ansible" --password "A123a123" --powershell_command "Get-ADComputer -Filter *"
    python WinrmTool.py --host 10.100.102.100 --username "weber\\ansible" --hash "7bb16b7c77a30c947ac16a79f0b8a111" --command "ipconfig /all"
    python WinrmTool.py --host 10.100.102.100 --username "weber\\ansible" --password "A123a123" --shell
    ============================================================================================================================================

                                                            KERBEROS
    ============================================================================================================================================
                                                Please notice that in kerberos you must use fqdn

    python WinrmTool.py --host weberdc.weber.com --kerberos --command "ipconfig /all"
    python WinrmTool.py --host weberdc.weber.com --kerberos --shell
    ============================================================================================================================================

                                                    Specical shell commands
    ============================================================================================================================================
    PS WinrmTool> upload "<src path>" "<dest path>"
    PS WinrmTool> download "<dest path>" "<src path>"

    PS WinrmTool> upload "/root/file.txt" "c:\\temp\\file.txt"
    PS WinrmTool> download "c:\\temp\\file.txt" "/root/file.txt"
    ============================================================================================================================================
'''


def run_cmd(p, command, args=()):
    shell_id = p.open_shell()
    command_id = p.run_command(shell_id, command, args)
    std_out, std_err, status_code = p.get_command_output(shell_id, command_id)
    rs = {'std_out':std_out,'std_err':std_err,'status_code':status_code}
    p.cleanup_command(shell_id, command_id)
    p.close_shell(shell_id)
    return rs


def run_ps(PowershellScript):
        encoded_ps = b64encode(PowershellScript.encode('utf_16_le')).decode('ascii')
        rs = run_cmd(p,'powershell -encodedcommand {0}'.format(encoded_ps))
        return rs    


def parse_xml_err(std_err):
    if(std_err[:11] == "#< CLIXML\r\n"):
        try:
            new_std_err = ""
	    error_dict = xmltodict.parse(std_err[11:])
	    for s in error_dict['Objs']['S']:
	        new_std_err += s['#text']
	    new_std_err = unicodedata.normalize('NFKD',new_std_err).encode('ascii','ignore')
	    new_std_err = new_std_err.replace("_x000D__x000A_","\n")
        except:
            print(RED + "[x] Failed to parse CLIXML" + ENDC)
            new_std_err = std_err
    else:
        new_std_err = std_err
    return new_std_err


def powershell_shell(p):
    shell_id = p.open_shell()
    
    while True:
	temp_command = raw_input("\nPS WinrmTool>")
        
        if(temp_command == "exit"):
            p.close_shell(shell_id)
            sys.exit()

        elif("cd" == temp_command.split()[0] or "Set-Location" == temp_command.split()[0]):
            print(RED + "\n[x] cd or Set-Location is not implemented, sorry :(" + ENDC)
            continue
        
        elif("download" == temp_command.split()[0]):
            powershell_command = b64encode(("[Convert]::ToBase64String([IO.File]::ReadAllBytes({0}))".format(temp_command.split()[1])).encode('utf-16le')).decode('ascii')
            command = 'powershell -encodedcommand {0}'.format(powershell_command)
        
        elif("upload" == temp_command.split()[0]):
            file = open(temp_command.split()[1].replace('"',''),"rb")
            content = b64encode(file.read())
            powershell_command = b64encode(("[System.IO.File]::WriteAllBytes({0},[convert]::FromBase64String('{1}'))".format(temp_command.split()[-1],content)).encode('utf-16le')).decode('ascii')
            command = 'powershell -encodedcommand {0}'.format(powershell_command)

        else:
            powershell_command = b64encode('{}'.format(temp_command.encode('utf_16_le'))).decode('ascii')
            command = 'powershell -encodedcommand {0}'.format(powershell_command)
        
	command_id = p.run_command(shell_id,command)
        std_out, std_err, status_code = p.get_command_output(shell_id, command_id)
        p.cleanup_command(shell_id, command_id)
        
        if(std_out and temp_command.split()[0] != "download"):
            print('\n{}'.format(std_out))
        
        elif(std_out and temp_command.split()[0] == "download"):
            file = open(temp_command.split()[-1].replace('"',''),"wb")
            file.write(b64decode(std_out))
            file.close()
            print(GREEN + "[*] File successfully downloaded" + ENDC)

        elif(std_err):
            new_err = parse_xml_err(std_err)
            print('\n{}'.format(new_err))


def build_connection(host,username='',password='',transport='ntlm',useSSL=False):
    if(useSSL):
        p = Protocol(endpoint='https://' + host + ':5986/wsman',
            username=username,
            password=password,
            transport=transport,
            server_cert_validation='ignore')
    else:
        p = Protocol(endpoint='http://' + host + ':5985/wsman',
            username=username,
            password=password,
            transport=transport)
    return p



parser = argparse.ArgumentParser(description="parsing arguments",epilog=examples,formatter_class=argparse.RawDescriptionHelpFormatter)
sgroup = parser.add_argument_group("Main arguments")
command_group = sgroup.add_mutually_exclusive_group(required=True)
pass_group = sgroup.add_mutually_exclusive_group(required=True)

sgroup.add_argument('--host' , dest='host', help='host to connect to')
sgroup.add_argument('--username', dest='username' , help='username to login with')
sgroup.add_argument('--useSSL', dest='useSSL', help='specify if using winrm over https',action='store_true')
pass_group.add_argument('--hash', dest='hash', help='Ntlm hash to connect with')
pass_group.add_argument('--password', dest='password', help='password to login with')
pass_group.add_argument('--kerberos',dest='kerberos',help='specifiy if using a kerberos auth (must have tgt)',action='store_true')
command_group.add_argument('--powershell_script', dest='powershell_script', help='path to powershell script')
command_group.add_argument('--powershell_command', dest='powershell_command', help='run powershell command')
command_group.add_argument('--shell', dest='shell',help='open a shell look like powershell(but only oneliners works)',action='store_true')
command_group.add_argument('--command', dest='command', help='cmd command to run on remote host')
args = parser.parse_args()


if(args.hash):
    if(re.match(r'^[a-fA-F0-9]{32}',args.hash)):
        args.password = "%s:%s" % (args.hash,args.hash)
    else:
        print(RED + "[x] not valid hash format" + ENDC)
        sys.exit()

if(args.kerberos):
    p = build_connection(args.host,transport='kerberos',useSSL=args.useSSL)

else:
    p = build_connection(args.host,args.username,args.password,useSSL=args.useSSL)

if(args.command):
    r = run_cmd(p,args.command)
    if(r['std_out']):
        print("\n{}".format(r['std_out'].decode()))
    elif(r['std_err']):
        print("\n{}".format(r['std_err'].decode()))
    
elif(args.shell):
    powershell_shell(p)

else:
    if(args.powershell_script):
        try:
            script = open(args.powershell_script, 'r', encoding='utf-8-sig')
            powershell_command = script.read()
        except:
            script = open(args.powershell_script, 'r', encoding='utf-16')
            powershell_command = script.read()
    else:
        powershell_command = args.powershell_command       

    r = run_ps(powershell_command)
    if(r['std_out']):
        print("\n{}".format(r['std_out'].decode()))
    elif(r['std_err']):
        r['std_err'] = parse_xml_err(r['std_err'])
        print("\n{}".format(r['std_err'].decode()))
