# cve_searchsploit

> version 1.2

Search an exploit in the local exploitdb database by its CVE.

Here you can get a free cve to exploit-db mapping in json format.

## Install

#### from PyPI

```
$ pip3 install cve_searchsploit
```

#### from GitHub

```
$ git clone https://github.com/andreafioraldi/cve_searchsploit
$ cd cve_searchsploit
$ python3 setup.py install
```

#### Requirements

+ python3
+ requests
+ progressbar2
+ git

## Usage
```
$ cve_searchsploit [parameters...]
```

#### Parameters
+  ```<cve>```                      search exploits by a cve
+  ```-u```                         update the cve-edbid mapping
+  ```-f <file with cve list>```    search exploits by a cve list file
+  ```-n <nessus csv scan file>```  search exploits by the cve matching with a nessus scan in csv format

