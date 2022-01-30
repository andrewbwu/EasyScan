#!/usr/bin/env python3
import sys
import hashlib
import nmap
import socket
import netifaces as ni
import subprocess
import re

def main_menu():
  print("""
        Main Menu

    1. What is my Local IPv4 Address?
    2. Nmap (network scanning)
    3. Nikto (vulnerability scanning)
    4. Log stats
    5. Encoding
    6. Hash checker
              """)
  menu_choice = input("Pick a tool: ")
  for tool in menu_choice:
    if tool == "1":
#      s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#      s.connect(('8.8.8.8', 1))  # connect() or UDP doesn't send packets
#      local_ip_address = s.getsockname()[0]
      ni.ifaddresses('eth0')
      local_ip_address = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']
      print()
      print('------------------------------------------------------------')
      print("Your local IP address is: " + local_ip_address)
      print('------------------------------------------------------------')
      main_menu()
    elif tool == "2":
      nmap_menu()
    elif tool == "3":
      nikto_menu()
    elif tool == "4":
      log_stats_menu()
    elif tool == "5":
      encoding_menu()
    elif tool == "6":
      hash_checker_menu()
    else:
      print("Try again")
      main_menu()
  
def nmap_menu():
  print("""
        Nmap

    1. -sn -n (Find hosts on your network. No Ports. Use CIDR notation)
    2. standard scan (all ports)
    3. --top-ports 20
    4. -sV (Service/Version Detection)
    5. -O (Enable OS Detection)
    6. -p (Port Scan)
    7. Return to Main Menu
              """)
  nmapscan = nmap.PortScanner()
  nmap_menu_choice = input("Pick an option: ")
  print()

  for nmap_option in nmap_menu_choice:

    if nmap_option == "1":
      ip_range = input('Enter IP to scan: ')
      nmapscan.scan(ip_range, arguments='-sn -n')
      print('------------------------------------------------------------')
      for ip_range in nmapscan.all_hosts():
          print('Host : %s (%s)' % (ip_range, nmapscan[ip_range].hostname()))
          print('State : %s' % nmapscan[ip_range].state())
      print('------------------------------------------------------------')
      nmap_menu()

    elif nmap_option == "2":
      ip_range = input("Enter IP to scan: ")
      nmapscan.scan(ip_range, arguments='-n')
      print('------------------------------------------------------------')
      for ip_range in nmapscan.all_hosts():
          print('Host : %s (%s)' % (ip_range, nmapscan[ip_range].hostname()))
          print()
          print(nmapscan[ip_range].all_protocols())
          for proto in nmapscan[ip_range].all_protocols():
              lport = nmapscan[ip_range][proto].keys()
              for port in lport:
                  print ('port: %s\tstate : %s' % (port, nmapscan[ip_range][proto][port]['state']))
          print()
      print('------------------------------------------------------------')
      nmap_menu()

    elif nmap_option == "3":
      ip_range = input("Enter IP to scan: ")
      nmapscan.scan(ip_range, arguments='--top-ports 20')
      print('------------------------------------------------------------')
      for ip_range in nmapscan.all_hosts():
          print('Host : %s (%s)' % (ip_range, nmapscan[ip_range].hostname()))
          print()
          print(nmapscan[ip_range].all_protocols())
          for proto in nmapscan[ip_range].all_protocols():
              lport = nmapscan[ip_range][proto].keys()
              for port in lport:
                  print('port: %s\tstate : %s' % (port, nmapscan[ip_range][proto][port]['state']))
          print()
      print('------------------------------------------------------------')
      nmap_menu()

    elif nmap_option == "4":
      ip_range = input("Enter IP to scan: ")
      nmapscan.scan(ip_range, '135, 3000', arguments='-sV -n')
      print('------------------------------------------------------------')
      for ip_range in nmapscan.all_hosts():
          print('Host : %s (%s)' % (ip_range, nmapscan[ip_range].hostname()))
          print()
          for proto in nmapscan[ip_range].all_protocols():
              lport = nmapscan[ip_range][proto].keys()
              for port in lport:
                  print('port : %s\tstate : %s' % (port, nmapscan[ip_range][proto][port]['state']))
                  print('Service : %s' % (nmapscan[ip_range][proto][port]['name']))
                  print('Product : %s' % (nmapscan[ip_range][proto][port]['product']))
                  print('Version : %s' % (nmapscan[ip_range][proto][port]['version']))
                  print()
          print()
      print('------------------------------------------------------------')
      nmap_menu()

    elif nmap_option == "5":
      ip_range = input("Enter IP to scan: ")
      nmapscan.scan(ip_range, arguments='-O')
      print('------------------------------------------------------------')
      for ip_range in nmapscan.all_hosts():
          print('Host : %s (%s)' % (ip_range, nmapscan[ip_range].hostname()))
          print()
          if 'osmatch' in nmapscan[ip_range]:
              for osmatch in nmapscan[ip_range]['osmatch']:
                  print('OS Name : {0}'.format(osmatch['name']))
# more details
#                  print('OsMatch.accuracy : {0}'.format(osmatch['accuracy']))
#                  print('OsMatch.line : {0}'.format(osmatch['line']))
#                  print()
#              if 'osclass' in osmatch:
#                  for osclass in osmatch['osclass']:
#                      print('OsClass.type : {0}'.format(osclass['type']))
#                      print('OsClass.vendor : {0}'.format(osclass['vendor']))
#                      print('OsClass.osfamily : {0}'.format(osclass['osfamily']))
#                      print('OsClass.osgen : {0}'.format(osclass['osgen']))
#                      print('OsClass.accuracy : {0}'.format(osclass['accuracy']))
#                      print()
          print()
      print('-----------------------------------------------------------')
      nmap_menu()
    elif nmap_option == "6":
      ip_range = input("Enter IP to scan: ")
      port_range = input("Enter ports to scan: ")
      nmapscan.scan(ip_range, port_range, '-n')
      print('-----------------------------------------------------------')
      for ip_range in nmapscan.all_hosts():
          print('Host : %s (%s)' % (ip_range, nmapscan[ip_range].hostname()))
          print()
          print(nmapscan[ip_range].all_protocols())
          for proto in nmapscan[ip_range].all_protocols():
              lport = nmapscan[ip_range][proto].keys()
              for port in lport:
                print('port: %s\tstate : %s' % (port, nmapscan[ip_range][proto][port]['state']))
          print()
      print('-----------------------------------------------------------')
      nmap_menu()  

    elif nmap_option == "7":
      main_menu()

    else:
      print("Try again")
      nmap_menu()

def nikto_menu():
  print("""
        Nikto

    1. Scan
    2. Return to Main Menu
            """)
  nikto_menu_choice = input("Pick an option: ")
  print()
  for nikto_option in nikto_menu_choice:
    if nikto_option == "1":
        host = input("Enter IP or FQDN to scan (BEWARE OF WHO YOU'RE SCANNING!!!!): ")
        niktoargs = input("Enter your arguments here (Use quotes if entering multiple arguments): ")
        print()
        niktoresults = nikto(host, niktoargs).decode()
        print('---------------------------------------------------------------------------')
        print(niktoresults)
        print('---------------------------------------------------------------------------')
        nikto_menu()

    elif nikto_option == "2":
      main_menu()

    else:
      print("Try again")
      nikto_menu()

def nikto(host, niktoargs):
    return subprocess.check_output(['nikto', '-h', host, niktoargs])




def main():
  print("""
        EasyScan v0.1           """)
  main_menu()

if __name__ == "__main__":
  main()
