#!/usr/bin/env python3
import sys
import hashlib
import nmap
import socket

def mainmenu():
  print("""
        Main Menu

    1. What is my Local IPv4 Address?
    2. Nmap (network scanning)
    3. Nikto (vulnerability scanning)
    4. Log stats
    5. Encoding
    6. Hash checker

              """)
  menuchoice = input("Pick a tool: ")
  for tool in menuchoice:
    if tool == "1":
      s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      s.connect(('8.8.8.8', 1))  # connect() for UDP doesn't send packets
      local_ip_address = s.getsockname()[0]
      print()
      print("Your local IP address is:" + local_ip_address)
      mainmenu()
    elif tool == "2":
      nmapmenu()
    elif tool == "3":
      niktomenu()
    elif tool == "4":
      logstatsmenu()
    elif tool == "5":
      encodingmenu()
    elif tool == "6":
      hashcheckermenu()
    else:
      print("Try again")
      mainmenu()
  
def nmapmenu():
  print("""
        Nmap

    1. Enter IP or IP range to scan
    2. Enter port or port range to scan (-p)
    3. Enter a filename to output to (-oG)
    4. Ping scan to discover hosts (-sn)
    5. Scan top 20 ports (--top-ports 20)
    6. Scan with service and version detection (-sV) 
    7. Operating system discovery (-O)
    8. Return to Main Menu
              """)
  nmapmenuchoice = input("Pick an option: ")
  print()
  for nmapoption in nmapmenuchoice:
    if nmapoption == "1":
      iprange = input("Enter IP scan (ex: 1.1.1.1, 1.2.3.4-5.6.7.8, 1.2.3.0/24): ")
      nmapmenu()
    elif nmapoption == "2":
      portrange = input("Enter port or port range to scan: ")
      nmapmenu()
    elif nmapoption == "3":
      fileoutput = input("Enter a filename for output (to cancel, leave blank): ")
      nmapmenu()
    # elif nmapoption == "4":
    # elif nmapoption == "5":
    # elif nmapoption == "6":
    # elif nmapoption == "7":
    elif nmapoption == "8":
      mainmenu()
    else:
      print("Try again")
      nmapmenu()

def main():
  print("""
        EasyScan v0.1           """)
  mainmenu()

if __name__ == "__main__":
  main()
