#!/usr/bin/env python3

__author__ = "Andrea Fioraldi"
__copyright__ = "Copyright 2017-19, Andrea Fioraldi"
__license__ = "MIT"
__email__ = "andreafioraldi@gmail.com"

import os
import json
import csv
import requests
import time
import random
import sys
import progressbar

if sys.version_info[0] < 3:
    range = xrange

pdir = os.path.dirname(os.path.abspath(__file__))

cve_map = {}

########## Library functions

def iter_edbid_from_cve(cve):
    cve = cve.upper()
    if cve not in cve_map:
        return

    files = open(pdir + "/exploit-database/files_exploits.csv")
    reader = csv.reader(files)
    #reader.next() #skip header
    next(reader)
    
    for row in reader:
        edb, file, description, date, author, platform, type, port = tuple(row)
        if edb in cve_map[cve]:
            yield int(edb)

    files.close()
    return

def edbid_from_cve(cve):
    return list(iter_edbid_from_cve(cve))

def iter_cve_from_edbid(edb):
    edb = str(int(edb))

    for cve in cve_map:
        if edb in cve_map[cve]:
            yield cve.upper()

def cve_from_edbid(edb):
    return list(iter_cve_from_edbid(edb))

##########

def update_db():
    data = {}

    if not os.path.exists(pdir + "/exploitdb_mapping.json"):
        with open(pdir + "/exploitdb_mapping.json", "w") as data_file:
            json.dump(data, data_file)
    else:
        with open(pdir + "/exploitdb_mapping.json") as data_file:
            data = json.load(data_file)

    print ("Refreshing exploit-database repo with lastest exploits")
    os.system("cd %s/exploit-database/; git pull origin master" % pdir)
    
    files = open(pdir + "/exploit-database/files_exploits.csv")
    reader = csv.reader(files)
    #reader.next() #skip header
    next(reader)

    reader = list(reader)
    csv_len = len(reader)
    
    get_header = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}

    def locations_of_substring(string, substring):
        substring_length = len(substring)    
        def recurse(locations_found, start):
            location = string.find(substring, start)
            if location != -1:
                return recurse(locations_found + [location], location+substring_length)
            else:
                return locations_found
        return recurse([], 0)

    print ("Refreshing EDBID-CVE mapping")
    with progressbar.ProgressBar(max_value=csv_len) as bar:
        for i in range(csv_len):
            edb = tuple(reader[i])[0]
            if edb in data:
                #print "Skipping edb id " + edb
                pass
            else:
                #print "Downloading https://www.exploit-db.com/exploits/" + edb
                content = ""
                while True:
                    try:
                        r = requests.get("https://www.exploit-db.com/exploits/" + edb, headers=get_header)
                        content = r.text
                    except Exception:
                        time.sleep(10)
                        continue
                    finally:
                        break
                used = []
                indexes = locations_of_substring(content, 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-')
                for pos in indexes:
                      cve = r.text[pos + len('https://cve.mitre.org/cgi-bin/cvename.cgi?name='): pos + len('https://cve.mitre.org/cgi-bin/cvename.cgi?name=') + 13].upper()
                      if cve in used: continue
                      used.append(cve)
                      print ("Found: edbid " + edb + " <---> " + cve)
                data[edb] = used
                indexes = locations_of_substring(content, 'https://nvd.nist.gov/vuln/detail/CVE-')
                for pos in indexes:
                      cve = r.text[pos + len('https://nvd.nist.gov/vuln/detail/'): pos + len('https://nvd.nist.gov/vuln/detail/') + 13].upper()
                      if cve in used: continue
                      used.append(cve)
                      print ("Found: edbid " + edb + " <---> " + cve)
                time.sleep(random.uniform(0.1, 0.3))
            bar.update(i)

    with open(pdir + "/exploitdb_mapping.json", "w") as data_file:
        json.dump(data, data_file, indent=2)

    cve_data = {}
    for k, v in data.items():
        for e in v:
            cve_data[e] = cve_data.get(e, [])
            cve_data[e].append(k)

    with open(pdir + "/exploitdb_mapping_cve.json", "w") as data_file:
        json.dump(cve_data, data_file, indent=2)


def _search_cve_aux(cve):
    files = open(pdir + "/exploit-database/files_exploits.csv")
    reader = csv.reader(files)
    #reader.next() #skip header
    next(reader)
    
    found = False
    for row in reader:
        edb, file, description, date, author, platform, type, port = tuple(row)
        if edb in cve_map[cve]:
            found = True
            print (" Exploit DB Id: " + edb)
            print (" File: " + pdir + "/exploit-database/" + file)
            print (" Date: " + date)
            print (" Author: " + author)
            print (" Platform: " + platform)
            print (" Type: " + type)
            if port != "0":
                print (" Port: " + port)
            print ("")
    if not found:
        print ("ERROR - No EDB Id found")
        print ("")

    files.close()
    return found

def search_from_file(file):
    for line in file:
        line = line.strip()
        if len(line) == 0:
            continue
        
        cve = line.upper()
        sname = "| " + cve + " |"
        print ("+" + "-" * (len(sname)-2) + "+")
        print (sname)
        print ("+" + "-" * (len(sname)-2) + "+")
        print ("")

        if not cve in cve_map:
            print ("ERROR - CVE not found.")
            print ("")
            continue

        _search_cve_aux(cve)

def search_from_nessus(file):
    reader = csv.reader(file)
    #reader.next() #skip header
    next(reader)
    
    for row in reader:
        cve = tuple(row)[1].upper()
        proto = tuple(row)[5]
        port = tuple(row)[6]
        name = tuple(row)[7]
        
        if not cve in cve_map:
            continue

        sname = "| " + name + " |"
        print ("+" + "-" * (len(sname)-2) + "+")
        print (sname)
        print ("+" + "-" * (len(sname)-2) + "+")
        print ("")
        print (" CVE: " + cve)
        print (" Protocol: " + proto)
        print (" Port: " + port)
        print ("")
        print (" +----+ Exploit DB matching +----+ ")
        print ("")
        
        _search_cve_aux(cve)
        print ("")

def search_cve(cve):
    cve = cve.upper()
    
    sname = "| " + cve + " |"
    print ("+" + "-" * (len(sname)-2) + "+")
    print (sname)
    print ("+" + "-" * (len(sname)-2) + "+")
    print ("")
    
    if not cve in cve_map:
        print ("ERROR - CVE not found.")
        print ("")
        exit(1)
    
    found = _search_cve_aux(cve)
    if not found:
        exit(1)
    
    print

def usage():
    print ("+------------------------------------+")
    print ("|          cve_searchsploit          |")
    print ("| Copyright 2017-19, Andrea Fioraldi |")
    print ("+------------------------------------+")
    print ("")
    print ("Usage:")
    print ("  python3 cve_searchsploit.py [parameters...]")
    print ("")
    print ("Parameters:")
    print ("  <cve>                      search exploits by a cve")
    print ("  -u                         update the cve-edbid database")
    print ("  -f <file with cve list>    search exploits by a cve list file")
    print ("  -n <nessus csv scan file>  search exploits by the cve matching with a nessus scan in csv format")
    print ("")
    exit(1)

def main():
    global cve_map
    
    if len(sys.argv) < 2:
        usage()
    if sys.argv[1] == "-u":
        update_db()
        exit(0)
    
    for i in range(1, len(sys.argv)):
        a = sys.argv[i]
        if a == "-u":
            print ("ERROR - '-u' is mutually exclusive with all the other arguments")
            print ("")
            exit(1)
        elif a == "-f":
            if i +1 == len(sys.argv):
                usage()
            try:
                file = open(sys.argv[i+1], "r")
                search_from_file(file)
            except Exception as exc:
                print ("ERROR - " + str(exc))
                print ("")
                exit(1)
        elif a == "-n":
            if i +1 == len(sys.argv):
                usage()
            try:
                file = open(sys.argv[i+1], "r")
                search_from_nessus(file)
            except Exception as exc:
                print ("ERROR - " + str(exc))
                print ("")
                exit(1)
        else:
            search_cve(a)


if not os.path.isdir(pdir + "/exploit-database"):
    print ("Cloning exploit-database repository")
    os.system("cd %s; git clone https://github.com/offensive-security/exploit-database" % pdir)

with open(pdir + "/exploitdb_mapping_cve.json") as data_file:
    cve_map = json.load(data_file)

if __name__ == "__main__":
    main()
