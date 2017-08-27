#!/usr/bin/env python

__author__ = "Andrea Fioraldi"
__copyright__ = "Copyright 2017, Andrea Fioraldi"
__license__ = "MIT"
__email__ = "andreafioraldi@gmail.com"

import os
import json
import csv
import requests
import time
import random
import sys

cve_map = {}

def update_db():
    data = {}

    if not os.path.exists("exploitdb_mapping.json"):
        with open("exploitdb_mapping.json", "w") as data_file:
            json.dump(data, data_file)
    else:
        with open("exploitdb_mapping.json") as data_file:
            data = json.load(data_file)

    files = open("files.csv")
    reader = csv.reader(files)
    reader.next() #skip header

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

    for row in reader:
        edb = tuple(row)[0]
        if edb in data:
            print "Skipping edb id " + edb
        else:
            print "Downloading https://www.exploit-db.com/exploits/" + edb
            content = ""
            while True:
                try:
                    r = requests.get("https://www.exploit-db.com/exploits/" + edb, headers=get_header)
                    content = r.content
                except Exception:
                    time.sleep(10)
                    continue
                finally:
                    break
            indexes = locations_of_substring(content, 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-')
            used = []
            for pos in indexes:
                  cve = r.content[pos + 47: pos + 47 + 13]
                  if cve in used: continue
                  used.append(cve)
                  print "Found: " + cve
            data[edb] = used
            time.sleep(random.uniform(0.1, 0.3))

    with open("exploitdb_mapping.json", "w") as data_file:
        json.dump(data, data_file, indent=2)

    cve_data = {}
    for k, v in data.iteritems():
        for e in v:
            cve_data[e] = cve_data.get(e, [])
            cve_data[e].append(k)

    with open("exploitdb_mapping_cve.json", "w") as data_file:
        json.dump(cve_data, data_file, indent=2)



def _search_cve_aux(cve):
    files = open("files.csv")
    reader = csv.reader(files)
    reader.next() #skip header
    
    found = False
    for row in reader:
        edb, file, description, date, author, platform, type, port = tuple(row)
        if edb in cve_map[cve]:
            found = True
            print "Exploit DB Id: " + edb
            print "File: /usr/share/exploitdb/" + file
            print "Date: " + date
            print "Author: " + author
            print "Platform: " + platform
            print "Type: " + type
            if port != "0":
                print "Port: " + port
            print
    if not found:
        print "ERROR - No EDB Id found"
        print

    files.close()
    return found

def search_from_file(file):
    for line in file:
        line = line.strip()
        if len(line) == 0:
            continue
        
        print " ++++ " + line + " ++++ "
        cve = line.upper()

        if not cve in cve_map:
            print "ERROR - CVE not found."
            print
            continue

        _search_cve_aux(line)
        print

def search_from_nessus(file):
    reader = csv.reader(file)
    reader.next() #skip header
    
    for row in reader:
        cve = tuple(row)[1]
        proto = tuple(row)[5]
        port = tuple(row)[6]
        name = tuple(row)[7]
        
        if not cve in cve_map:
            continue

        sname = "* " + name + " *"
        print "*"*len(sname)
        print sname
        print "*"*len(sname)
        print
        print "CVE: " + cve
        print "Protocol: " + proto
        print "Port: " + port
        print
        print " ++++ Exploit DB matching ++++ "
        print
        
        _search_cve_aux(cve)
        print

def search_cve(cve):
    cve = cve.upper()

    if not cve in cve_map:
        print "ERROR - CVE not found."
        print
        sys.exit(1)
    
    found = _search_cve_aux(cve)
    if not found:
        sys.exit(1)
    
    print

def usage():
    print "***********************************"
    print "*         cve_searchsploit        *"
    print "* Copyright 2017, Andrea Fioraldi *"
    print "***********************************"
    print
    print "Usage:"
    print "  python cve_searchsploit.py [parameters...]"
    print
    print "Parameters:"
    print "  <cve>                      search exploits by a cve"
    print "  -u                         update the cve-edbid database"
    print "  -f <file with cve list>    search exploits by a cve list file"
    print "  -n <nessus csv scan file>  search exploits by the cve matching with a nessus scan in csv format"
    print
    sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()
    if sys.argv[1] == "-u":
        update_db()
        sys.exit(0)
    else:
        with open("exploitdb_mapping_cve.json") as data_file:
            cve_map = json.load(data_file)

    if sys.argv[1] == "-f":
        if len(sys.argv) < 3:
            usage()
        try:
            file = open(sys.argv[2], "r")
            search_from_file(file)
        except Exception as exc:
            print "ERROR - " + str(exc)
            print
            sys.exit(1)
    elif sys.argv[1] == "-n":
        if len(sys.argv) < 3:
            usage()
        try:
            file = open(sys.argv[2], "r")
            search_from_nessus(file)
        except Exception as exc:
            print "ERROR - " + str(exc)
            print
            sys.exit(1)
    else:
        search_cve(sys.argv[1])
