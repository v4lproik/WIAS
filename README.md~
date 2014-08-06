# WIAS

* This program has been designed to submit login forms automatically.
* Why ?This tool can be useful during an internal pentest when you need to quickly check default credentials of web interfaces.S

** This program comes with several modules :

* hash : Hash computation will be performed, trying to identify the web interface.
* bruteforce : A bruteforce attack will be performed if a login form is at the root of the domain provided or detected by the crawler module.
* favicon : A Hash computation will be performed on the favicon, trying to identify the web interface.
* enumeration : All forms found will be display to the screen.
* default_password : A bruteforce attack will be performed if a favicon hash or page hash is found - with default login/password - from password/default-password-web-interface.txt.
* crawler : If no login form is found within the response of the url provided, the web crawler will try to find a login form."
* report : Create a report in to ./report folder.

** Several modules has been designed to detect which type of web interface is being scanned.

* Detection modules : favicon, hash, default_password
To be able to find which type of web interfaces you provided, the tool will be trying to find the favicon of the website. Once found, it will compare the favicon with the database you provided (by default the database at the root folder is a mix of OWASP bdd and NMAP bdd @all credits belong to them) and then will submit its default credentials, stored in the file password/default-password-web-interface.
If the program do not find any entry in the favicon database, it will perform another test trying to identify the web interface : comparison with the hash of the page.

* Submit Credentials module: Bruteforce
If the detection modules fail, you can attempt a bruteforce against the login form in order to find valid credentials.

* Login Form module : Crawler
If you provid a list of domain or IP and the home page do not provide a login form, you can activate the crawler module. This module aims to crawl the domain in order to find a login form for the program to work on.


Feel free to fork it...

##Usage
```
python wias.py -f ip.txt -db favicon-db -m crawler,bruteforce,report,favicon -c -kf
```

## Configuration
Many configuration variables can be found in the folder ROOT/conf/, including configuration for :
* crawler
* http request
* bruteforce
* web login form detection
* multiprocessing

## Pre-Installation Libraries
Works with python 2.7. Haven't tested with python 3 yet.

```
python-beautifulsoup
python-urllib2
python-lxml.html
```

## Installation

No installation required

## Execution
```
	    |----------------------------------------------------------|
    |              Web Interface Auto Submit 1.2               |
    |                         V4lproik                         |
    |----------------------------------------------------------|

usage: wias.py [-h] -f FILENAME -db DATABASE -m MODULE [MODULE ...] [-v] [-c]
               [-a] [-conf]

optional arguments:
  -h, --help            show this help message and exit

main arguments:
  -f FILENAME, --filename FILENAME
                        File with IP or DOMAIN - One per line
  -db DATABASE, --database DATABASE
                        File with MD5:WEBName - One par line
  -m MODULE [MODULE ...], --module MODULE [MODULE ...]
                        List of module that be running. For more details
                        regarding modules, try : -m list. Modules List :
                        ['hash', 'bruteforce', 'favicon', 'enumeration',
                        'default_password', 'crawler']

optional arguments:
  -v, --verbose         Verbosity level
  -c, --color           Display Color to stdin
  -a, --aggressive      Try to identify a login form through different
                        process.
  -conf, --conf_folder  Path of the conf folder where all the configuration
                        files are stored
```

Examples :

```
 python wias.py -f ip.txt -db favicon-db -m favicon,default_password,bruteforce,crawler -c

    |----------------------------------------------------------|
    |              Web Interface Auto Submit 1.0               |
    |                         V4lproik                         |
    |----------------------------------------------------------|


[*] Analyse running for url given : http://xxx/cms
 [] 301 Found : http://xxx/cms -> http://xxx/cms/
 [] The server returned : 200
 [*] Favicon Tests
  [] Favicon found : /cms/templates/protostar/favicon.ico
  [] Favicon md5 computation : 8894791e84f5cafebd47311d14a3703c
  [] Favicon belongs to : cms
 [*] Form Tests
  []  No Form Found
 [*] Crawler Test
  [] Login Form Found at : http://xxx/cms/administrator
 [*] BruteForce Tests
  [] Test with Dictionaries
  [] No Credentials Found

[*] Analyse running for url given : http://xxx/dvwa
 [] 301 Found : http://xxx/dvwa -> http://xxx/dvwa/login.php
 [] The server returned : 200
 [*] Favicon Tests
  [] No Favicon within the html response
  [] Favicon found at : http://xxx/dvwa/favicon.ico
  [] Favicon md5 computation : 69c728902a3f1df75cf9eac73bd55556
  [] Favicon belongs to : Damn Vulnerable Web App (DVWA) - Login
  [] Default Passwords Found
 [*] Form Tests
  [] 1 Form(s) found.
 [*] Login Form Tests
  [] Found
 [*] BruteForce Tests
  [] Test with Default Logins Passwords
  [] Credentials Found : admin password

[*] Analyse running for url given : http://xxx:8080/VulnApp/attack
 [] The server returned : 401
 [*] BruteForce Tests
  [] Test with Dictionaries
  [] Credentials Found : guest guest

```

## Modification 05/08/14

*Crawler Web added
*Modification of domains/ips detection (you can now pass full url to the program)
*Bug fixed
*Added two new options (-kf & -kb)
*Report module

## Todo List

* Create switch with phantomJS
* Improvement of the autologin form process
* Import specific modules for specific web interfaces
* Csrf Detection
* Html Report
