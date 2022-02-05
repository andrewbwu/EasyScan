# EasyScan

## Cybersecurity Scanning Made Easy

Need to do some reconnaissance? Forgot all of your commands and can't be bothered to look them up? Try this script to get some of the answers you need. We've included a number of useful tools that will help the novice security analyst gather and report any information security issues they find.

Requirements:

- May require pip3 installation. To install, enter the command
```
sudo apt install python3-pip
```

- Install nmap lib if you don't already have it. To install, enter the command
```
sudo pip3 install python-nmap
```

- To enable Operating System detection in nmap, run the script as root.


## Main Menu
1. What is my Local IP Address?
2. Nmap (Network Scanning)
    * 2.1 Find hosts on the network (-sn -n)
    * 2.2 Scan for all open ports (standard scan) (-n)
    * 2.3 Scan the top 20 ports (--top-ports 20)
    * 2.4 Prob open ports for services and version information (-sV -n)
    * 2.5 Attempt to detect the OS (requires root!) (-O)
    * 2.6 Scan specific ports (-p)
3. Nikto (Vulnerability Scanning)
    * 3.1 Nikto web server vulnerability scanner
4. Log Stats
    * 4.1 Get the top 10 of all IPs (from a log file)
    * 4.2 Get the top 10 of a field you choose (from a log file)
5. Encoding and Decoding
    * 5.1 Hex to Ascii
    * 5.2 Ascii to Hex
    * 5.3 Base64 to Ascii
    * 5.4 Ascii to Base64
    * 5.5 Binary to Ascii
    * 5.6 Ascii to Binary
6. Hash Checker
    * 6.1 MD5 of a string
    * 6.2 MD5 of a file
    * 6.3 SHA-256 of a string
    * 6.4 SHA-256 of a file
7. (About)

Thanks for making it to the end! Check out these tools in the not so Easter Egg Menu!

8.  Easter Egg Menu
    * 8.1 Make an ascii banner
    * 8.2 aNgRy InTeRnEt TrAnSlAtOr


## About 
Created by [Andrew Wu](https://github.com/andrewbwu) and [Berenice Nava-Morales](https://github.com/ynreb) 

## Shoutouts
Special thanks to the staff at Fullstack Academy and our instructors for their knowledge and guidance in our cybersecurity journey!

And shoutout to our cohort peers for thei willingness to lend a hand while learning together.
