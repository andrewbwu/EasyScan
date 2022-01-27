#!/usr/bin/env python3
import sys
import haslib
import nmap

def mainmenu():
  print("""
        Main Menu

    1. What is my IP?
    2. Nmap (network scanning)
    3. Nikto (vulnerability scanning)
    4. Log stats
    5. Encoding
    6. Hash checker

              """)
  menuchoice = input("Pick a tool:")
  for tool in menuchoice:
    if int(tool) == 1:
      print("IP SCAN BZZZT")
    elif int(tool) == 2:
      nmapmenu()
    elif int(tool) == 3:
      niktomenu()
    elif int(tool) == 4:
      logstatsmenu()
    elif int(tool) == 5:
      encodingmenu()
    elif int(tool) == 6:
      hashcheckermenu()
    else:
      print("Try again")
      mainmenu()
  return

def nmapmenu():
  print("""
        Nmap

    1. Enter IP or IP range to scan:
    2. Enter port or port range to scan:
    3. (-sp) Ping scan
    4. (--top-ports 20) Top 20 ports
    5. (-A) OS and version detection
    6. (-oG) out to a file
    7. Return to Main Menu
              """)


def main():
  print("""
        EasyScan v0.1           """)
  mainmenu()

if __name__ == "__main__":
  main()
