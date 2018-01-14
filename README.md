# cve_searchsploit
Search an exploit in the local exploitdb database by its CVE.

Here you can get a free cve and exploit-db mapping in json format.

### Install
```
$ python setup.py install
```
#### Requirements
+ python2
+ requests
+ progressbar2
+ git

### Usage
```
$ cve_searchsploit [parameters...]
```

#### Parameters
+  ```<cve>```                      search exploits by a cve
+  ```-u```                         update the cve-edbid mapping
+  ```-f <file with cve list>```    search exploits by a cve list file
+  ```-n <nessus csv scan file>```  search exploits by the cve matching with a nessus scan in csv format

