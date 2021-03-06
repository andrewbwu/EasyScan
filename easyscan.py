#!/usr/bin/env python3
import hashlib
import nmap
import netifaces as ni
import subprocess
import pyfiglet
import time
import base64
import re

def main_menu():
  print("""
        Main Menu

    1. What is my Local IP Address?
    2. Nmap (Network Scanning)
    3. Nikto (Vulnerability Scanning)
    4. Log Stats
    5. Encoding and Decoding
    6. Hash Checker
    7. (About)
              """)
  menu_choice = input("Pick a tool: ")
  for tool in menu_choice:
    if tool == "1":
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
    elif tool == "7":
      authors()
    elif tool == "8":
      ee_menu()
    else:
      print("Try again")
      main_menu()
  
def nmap_menu():
  print("""
        Nmap

    1. Find hosts on the network. Use a range or CIDR notation
    2. Scan for all open ports (Standard scan)
    3. Scan the top 20 ports
    4. Probe open ports for services and version info
    5. Attempt to detect the OS (Requires root!)
    6. Scan specific ports
    7. Return to Main Menu
              """)
  nmapscan = nmap.PortScanner()
  nmap_menu_choice = input("Pick an option: ")
  print()

  for nmap_option in nmap_menu_choice:

    if nmap_option == "1":
      ip_range = input('Enter IP to scan: ')
      nmapscan.scan(ip_range, arguments='-sn -n')
      print('--------------------------------------------------------------------------')
      for ip_range in nmapscan.all_hosts():
          print('Host : %s (%s)' % (ip_range, nmapscan[ip_range].hostname()))
          print('State : %s' % nmapscan[ip_range].state())
      print('--------------------------------------------------------------------------')
      nmap_menu()

    elif nmap_option == "2":
      ip_range = input("Enter IP to scan: ")
      nmapscan.scan(ip_range, arguments='-n')
      print('--------------------------------------------------------------------------')
      for ip_range in nmapscan.all_hosts():
          print('Host : %s (%s)' % (ip_range, nmapscan[ip_range].hostname()))
          print()
          print(nmapscan[ip_range].all_protocols())
          for proto in nmapscan[ip_range].all_protocols():
              lport = nmapscan[ip_range][proto].keys()
              for port in lport:
                  print ('port: %s\tstate : %s' % (port, nmapscan[ip_range][proto][port]['state']))
          print()
      print('---------------------------------------------------------------------------')
      nmap_menu()

    elif nmap_option == "3":
      ip_range = input("Enter IP to scan: ")
      nmapscan.scan(ip_range, arguments='--top-ports 20')
      print('--------------------------------------------------------------------------')
      for ip_range in nmapscan.all_hosts():
          print('Host : %s (%s)' % (ip_range, nmapscan[ip_range].hostname()))
          print()
          print(nmapscan[ip_range].all_protocols())
          for proto in nmapscan[ip_range].all_protocols():
              lport = nmapscan[ip_range][proto].keys()
              for port in lport:
                  print('port: %s\tstate : %s' % (port, nmapscan[ip_range][proto][port]['state']))
          print()
      print('--------------------------------------------------------------------------')
      nmap_menu()

    elif nmap_option == "4":
      ip_range = input("Enter IP to scan: ")
      nmapscan.scan(ip_range, arguments='-sV -n')
      print('--------------------------------------------------------------------------')
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
      print('---------------------------------------------------------------------------')
      nmap_menu()

    elif nmap_option == "5":
      ip_range = input("Enter IP to scan: ")
      nmapscan.scan(ip_range, arguments='-O')
      print('---------------------------------------------------------------------------')
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
      print('---------------------------------------------------------------------------')
      nmap_menu()

    elif nmap_option == "6":
      ip_range = input("Enter IP to scan: ")
      port_range = input("Enter ports to scan: ")
      nmapscan.scan(ip_range, port_range, '-n')
      print('---------------------------------------------------------------------------')
      for ip_range in nmapscan.all_hosts():
          print('Host : %s (%s)' % (ip_range, nmapscan[ip_range].hostname()))
          print()
          print(nmapscan[ip_range].all_protocols())
          for proto in nmapscan[ip_range].all_protocols():
              lport = nmapscan[ip_range][proto].keys()
              for port in lport:
                print('port: %s\tstate : %s' % (port, nmapscan[ip_range][proto][port]['state']))
          print()
      print('---------------------------------------------------------------------------')
      nmap_menu()  

    elif nmap_option == "7":
      main_menu()

    else:
      print("Try again")
      nmap_menu()

def nikto_menu():
  print("""
        Nikto

    1. Scan a webserver for vulnerabilities
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

def log_stats_menu():
    print("""
        Log Statistics

    1. Get the top 10 of all IPs (from a log file)
    2. Get the top 10 of a field you choose (from a log file)
    3. Main Menu
              """)
    menu_choice = input('Choose an Option: ')
    print()

    for x in menu_choice:
        if x == '2':	      
           filename = input("Enter filename: ")                            #take the filename
           print()
           print("Here is the first line of your log")
           print()
           with open(filename, "r") as f:                                  #open file
               print(f.readline())                                         #print first line

               deli = input("Enter delimiter: ")                           #enter the delimiter
               fld = int(input("Enter field [0][1][2][3][4][5][etc]: "))    #enter the field position
               print()

               f.seek(0)                                                   #go back to start of file
               log = f.readlines()                                         #make each line into a list
               strippedfield = []                                          #create list for the stripped field
               for entry in log:
                   strippedfield.append(entry.split(deli)[fld])             #use split method to grab field and append to list

               counter = {}                                                #create counter dictionary
               for entry in strippedfield:
                   if entry in counter:
                       counter[entry] += 1
                   else:
                       counter[entry] = 1

               print()
               print('---------------------------------------------------------------------------')
               for key in sorted(counter, key=counter.get, reverse=True)[:10]:
                   print(key, '-', counter[key])
               print('---------------------------------------------------------------------------')
               log_stats_menu()

        elif x == '1':
            filename = input("Enter filename: ")                                      #enter filename
            with open(filename, "r") as f:
             iplist = re.findall('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', f.read())  #strip IPs out

             counter = {}                                                           #create counter dictionary

            for ip in iplist:
              if ip in counter:
               counter[ip] += 1
              else:
               counter[ip] = 1


            print()
            print('---------------------------------------------------------------------------')
            for key in sorted(counter, key=counter.get, reverse=True)[:10]:        #print top 10 results
             print(key, '-', counter[key])

            print('---------------------------------------------------------------------------')
            log_stats_menu()

        elif x == '3':
            main_menu()

        else:
            print('Try again')
            log_stats_menu()


def encoding_menu():
    print("""
        Encoding and Decoding

    1. Hex to Ascii
    2. Ascii to Hex
    3. Base64 to Ascii
    4. Ascii to Base64
    5. Binary to Ascii
    6. Ascii to Binary 
    7. Main Menu
              """)
    menu_choice = input('Choose an Option: ')
    print()
    
    for x in menu_choice:
     if x == '1':
        hexstring = input("Enter your code: ")
        a_string = bytes.fromhex(hexstring)
        a_string = a_string.decode("ascii")
        print()
        print('---------------------------------------------------------------------------')
        print(a_string)
        print('---------------------------------------------------------------------------')
        encoding_menu()

     elif x == '2':
       x = input("Enter your code: ")
       output = x.encode('utf-8').hex()
       print()
       print('---------------------------------------------------------------------------')
       print(output)
       print('---------------------------------------------------------------------------')
       encoding_menu()

     elif x == '3': #base642ascii
       base64_message = input('Enter your code: ')
       base64_bytes = base64_message.encode('ascii')
       message_bytes = base64.b64decode(base64_bytes)
       message = message_bytes.decode('ascii')
       print()
       print('---------------------------------------------------------------------------')
       print(message)
       print('---------------------------------------------------------------------------')
       encoding_menu()

     elif x == '4':
       message = input("Enter your code: ")
       message_bytes = message.encode('ascii')
       base64_bytes = base64.b64encode(message_bytes)
       base64_message = base64_bytes.decode('ascii')
       print()
       print('---------------------------------------------------------------------------')
       print(base64_message)
       print('---------------------------------------------------------------------------')
       encoding_menu()

     elif x == '5': #binary2ascii
       text = input('Enter your code: ')
       binary_int = int(text, 2)
       byte_number = binary_int.bit_length() + 7 // 8
       binary_array = binary_int.to_bytes(byte_number, "big")
       ascii_text = binary_array.decode()
       print()
       print('---------------------------------------------------------------------------')
       print(ascii_text)
       print('---------------------------------------------------------------------------')
       encoding_menu()

     elif x == '6': #ascii2binary
       byte_array = input('Enter your code: ').encode()
       binary_int = int.from_bytes(byte_array, 'big')
       binary_string = bin(binary_int)
       print()
       print('---------------------------------------------------------------------------')
       print(binary_string)
       print('---------------------------------------------------------------------------')
       encoding_menu()

     elif x == '7': #return2main
       main_menu()

     else:
       print('Try Again')
       encoding_menu()



def hash_checker_menu():
    print("""
        Hash Checker

    1. MD5 of a string
    2. MD5 of a file
    3. SHA-256 of a string
    4. SHA-256 of a file
    5. Main Menu
              """)

    menu_option = input('Choose an Option: ')
    print()

    for x in menu_option:
      if x == '1':
       md_c = input('Enter text to generate md5 hash: ')
       print('---------------------------------------------------------------------------')
       print(hashlib.md5(md_c.encode('utf-8')).hexdigest())
       print('---------------------------------------------------------------------------')
       hash_checker_menu()

      elif x == '2':
       filename = input("Enter file name: ")
       with open(filename, "rb") as f:
           print()
           print('---------------------------------------------------------------------------')
           print(hashlib.md5(f.read()).hexdigest())
           print('---------------------------------------------------------------------------')
           hash_checker_menu()

      elif x == '3':
       sha_txt = input('Enter text to generate hash: ')
       result = hashlib.sha256(sha_txt.encode())
       print('---------------------------------------------------------------------------')
       print(result.hexdigest())
       print('---------------------------------------------------------------------------')
       hash_checker_menu()

      elif x == '4':
       filename = input("Enter file name: ")
       sha256_hash = hashlib.sha256()
       with open(filename, "rb") as f:
           for byte_block in iter(lambda: f.read(4096),b""):
               sha256_hash.update(byte_block)
           print()
           print('---------------------------------------------------------------------------')
           print(sha256_hash.hexdigest())
           print('---------------------------------------------------------------------------')
           hash_checker_menu()

      elif x == '5':
       main_menu()

      else:
       print('Try Again')
       hash_checker_menu()



def authors():
    print("""
        Brought to you by

             ____   _   _      ___        _  __        __
            | __ ) | \ | |    ( _ )      / \ \ \      / /
            |  _ \ |  \| |    / _ \/\   / _ \ \ \ /\ / / 
            | |_) || |\  |_  | (_>  <  / ___ \ \ V  V /_ 
            |____(_)_| \_(_)  \___/\/ /_/   \_(_)_/\_/(_)
                """)
    time.sleep(3)
    main_menu()

def ee_menu():
    print("""
        Easter Eggs

    1. Make an ascii banner
    2. Convert your text into aNgRy InTeRnEt TeXt
    3. Main Menu
              """)
    menu_option = input('Choose an Option: ')
    print()
    for x in menu_option:
        if x == '1':
            ascii2banner()
            ee_menu()
        elif x == '2':
            angry_translator()
            ee_menu()
        elif x == '3':
            main_menu()
        else:
            print("Try again")
            ee_menu()

def ascii2banner():
    text_to_ascii = input("Enter text to turn into ascii banner: ")
    ascii_banner = pyfiglet.figlet_format(text_to_ascii)
    print()
    print(ascii_banner)
    ee_menu()

def angry_translator():
    text = input("Enter text to translate into aNgRy InTeRnEt TeXt!: ")
#    text_lowercase = text.ascii_lowercase
    angry_text = ""
    i = True
    for char in text:
        if i:
            angry_text += char.lower()
        else:
            angry_text += char.upper()
        if char !=' ':
            i = not i
    print()
    print(angry_text)
    ee_menu()

def main():
    print("""
              _____                ____                  
             | ____|__ _ ___ _   _/ ___|  ___ __ _ _ __  
             |  _| / _` / __| | | \___ \ / __/ _` | '_ \ 
             | |__| (_| \__ \ |_| |___) | (_| (_| | | | |
             |_____\__,_|___/\__, |____/ \___\__,_|_| |_|
                             |___/                              v0.1
        """)
    main_menu()

if __name__ == "__main__":
  main()
