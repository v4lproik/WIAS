#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Copyright (C) 2013  v4lproik

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
'''


'''
This program aims to submit login forms.
This tool can be useful during an internal pentest when you need to quickly check default credentials of web interfaces.
It has not been design for handling javascript "strings transformation" submission, only basic web interface.
'''

__author__ = "v4lproik"
__date__ = "27/04/2013"
__version__ = "1.0"
__maintainer__ = "v4lproik"
__email__ = "v4lproik@gmail.com"
__status__ = "Development"
__twitter__ = "v4lproik"

'''
Further work is actually  being undertaken :
- Crawler web to find login form
- Improvement of the autologin form process
- Import specific modules for specific web interfaces
- Csrf Detection
- Html Report

Any other feature you'd like to see implemented ? Feel free to contact me.
'''

try:
    import re
    import traceback
    import sys
    import urlparse
    import ConfigParser
    import argparse
    from modules import *
    import urlparse
    import multiprocessing
    import difflib

except ImportError, err:
    raise
    print >>sys.stderr, "[X] Unable to import : %s\n" % err
    sys.exit(1)


def banner():
    banner = '''
    |----------------------------------------------------------|
    |              Web Interface Auto Submit 1.1               |
    |                         V4lproik                         |
    |----------------------------------------------------------|\n'''
    print banner


def checkArgs():
    if len(sys.argv) == 3:
        if sys.argv[1] == "-m" and sys.argv[2] == "list":
            print " [*] Modules"
            for i in conf.all_module_description:
                print i
        else:
            parser.print_help()
        sys.exit()
    elif len(sys.argv) < 7:
        parser.print_help()
        sys.exit()


def checkMod(value):
    try:
        for i in value.split(','):
            if not i in conf.all_module:
                raise
        return value
    except:
        raise argparse.ArgumentTypeError(
            "Modules must be : " + str(conf.all_module))


def worker(tab):
    if not tab[0]:
        for i in objBF.login:
            for y in objBF.password:
                yield i, y, tab
    else:
        for i in arr_default_login_password:
            tmp = i.split(":", 1)
            yield tmp[0], tmp[1], tab


def process(tab):
    login, pass_u, tab_plus = tab

    pattern_login = tab_plus[3]
    pattern_pass = tab_plus[2]
    action = tab_plus[1]
    bad_cred = tab_plus[4]

    data[pattern_login] = login
    data[pattern_pass] = pass_u

    flag_response, response = objReq.request(url=urlparse.urljoin(
        objReq.getUrl(), action), method=method, data=data)
    if flag_response:
        content = response.read()

        if htmlAnalyser.getDifferenceBetweenTwoPages(content, bad_cred) != 0:

            # let's perform another test... if another random parameter exists within the web (eg : visit counter)
            # print content
            diffs = htmlAnalyser.extractDiffFromResponseHTML(bad_cred, content)
            diffs = htmlAnalyser.removeHTMLTag(diffs)

            if not objHtml.amILoggedInGrep(diffs, login):
                objConf.printMessage(
                    "   [] Bad Credentials : " + login + "/" + pass_u, "v")
                return False, login, pass_u
            else:
                objConf.printMessage(
                    "   [] Potentionaly Good Credentials : " + login + "/" + pass_u, "v", "find")
                return True, login, pass_u
        else:
            objConf.printMessage(
                "   [] Good Credentials : " + login + "/" + pass_u, "v", "find")
            return True, login, pass_u


def process_401(tab):
    login, pass_u, tab_plus = tab
    action = tab_plus[1]

    cred_encode = webRequest.base64stringAuth(login, pass_u)
    # print cred_encode
    # update headers...

    objReq.headers["Authorization"] = cred_encode

    flag_response, response = objReq.request(
        url=action)

    if flag_response:
        if response.code == 401:
            objConf.printMessage(
                "   [] Bad Credentials : " + login + "/" + pass_u, "v")
            return False, login, pass_u
        else:
            objConf.printMessage(
                "   [] Good Credentials : " + login + "/" + pass_u, "v", "find")
            return True, login, pass_u


if __name__ == "__main__":

    try:
        parser = argparse.ArgumentParser()
        gr1 = parser.add_argument_group("main arguments")
        gr1.add_argument('-f', '--filename', dest='filename',
                         required=True, help='File with IP or DOMAIN - One per line')
        gr1.add_argument('-db', '--database', dest='database',
                         required=True, help='File with MD5:WEBName - One par line')
        gr1.add_argument(
            '-m', '--module', dest='module', required=True, nargs='+', type=checkMod,
            help='List of module that be running. For more details regarding modules, try : -m list. Modules List : ' + str(conf.all_module))

        gr2 = parser.add_argument_group("optional arguments")
        gr2.add_argument('-v', '--verbose', dest='verbose',
                         default=False,  action='store_true', help='Verbosity level')
        gr2.add_argument('-c', '--color', dest='color', default=False,
                         action='store_true', help='Display Color to stdin')
        gr2.add_argument(
            '-a', '--aggressive', dest='aggressive', default=False,
            action='store_true', help='Try to identify a login form through different process.')
        gr2.add_argument(
            '-conf', '--conf_folder', dest='conf_folder', default="conf/",
            action='store_true', help='Path of the conf folder where all the configuration files are stored')

        banner()
        checkArgs()

        args = parser.parse_args()

        # Store CLI variable
        aggressive = args.aggressive
        verbosity = args.verbose
        color = args.color
        filename = args.filename
        favdb = args.database
        configuration_folder_path = args.conf_folder
        module = args.module

        # Configuration Init
        objConf = conf(configuration_folder_path, module)
        objFav = faviconDB(conf.getFileContent(favdb))
        objBF = bruteForce(objConf.login_dictionnary, objConf.pass_dictionnary)
        dic_domain = conf.getFileContent(filename)
        if verbosity:
            objConf.verbosity = True
        if color:
            objConf.color = True
        kwargs = objConf.getTAGVariable()
        objHtml = htmlAnalyser(**kwargs)

        # Display Settings
        objConf.printMessage("[*] Settings", "v", "info")
        objConf.displaySettings()

        # Run test for each web interface
        for domain in dic_domain:

            objConf.printMessage(
                "\n[*] Analyse running for url given : " + domain, "r", "find")

            # Init variables for each domain
            flag_form = True
            flag_login_form = False
            flag_401 = False
            flag_hash_found = False
            flag_favicon_found = False
            flag_bf_found = False
            nb_proc = int(objConf.thread)
            action = ""
            html_response = ""

            # Check activated modules
            if "favicon" in objConf.module:
                # allFavicon = objFav.getAllFavicon()
                flag_favicon = True
            else:
                flag_favicon = False

            if "hash" in objConf.module:
                flag_hash = True
            else:
                flag_hash = False

            if "bruteforce" in objConf.module:
                flag_bf = True
            else:
                flag_bf = False

            if "enumeration" in objConf.module:
                flag_bf = False
                flag_favicon = False
                flag_hash = False
                flag_form = False

            if "default_password" in objConf.module:
                flag_default_password = True
            else:
                flag_default_password = False

            if "crawler" in objConf.module:
                flag_crawler = True
            else:
                flag_crawler = False

            # Url Request
            objReq = webRequest(
                domain, UA=objConf.user_agent, proxy=objConf.proxy,
                timeout=objConf.http_timeout, cookie_redirection=objConf.redirect_cookie)
            flag_response, response = objReq.request()

            # Exception...
            if flag_response:
                # if 301 -> update the domain
                if domain in MyHTTPRedirectHandler.permanent_redirection:
                    objReq.domain = response.url
                    objConf.printMessage(
                        " [] 301 Found : " + domain + " -> " + objReq.domain, "r", "find")

                if response.code == 401:
                    objConf.printMessage(
                        " [] The server returned : " + str(response.code), "r")

                    # only bf is available for 401
                    if not flag_bf:
                        objConf.printMessage(
                            " [] Only BruteForce Tests are available for Unauthorised response", "r", "error")
                        continue

                    flag_favicon = False
                    flag_hash = False
                    flag_form = False
                    flag_login_form = True
                    flag_401 = True
                    flag_401_url = objReq.domain
                    data = {}
                    html_response = response.read()
                elif response.code == 200:
                    if not "enumeration" in objConf.module:
                        objConf.printMessage(
                            " [] The server returned : " + str(response.code), "r")
                    html_response = response.read()
                else:
                    objConf.printMessage(
                        " [] The server returned : " + str(response.code), "r")
                    continue
            else:
                objConf.printMessage(" [] Error : " + str(
                    response), "r", "error")
                continue

            # Form enumeration only
            if not flag_hash and not flag_favicon and not flag_form and not flag_bf:
                forms = htmlAnalyser.getAllForm(html_response)
                if len(forms) > 0:
                    print forms
                continue

            # Favicon Tests
            try:
                if flag_favicon:
                    objConf.printMessage(" [*] Favicon Tests", "r", "info")

                    fav_response, fav = objReq.getFavicon(
                        html_response=html_response)

                    # favicon method
                    md5_favicon = cryptoComputation.md5ChecksumContent(
                        fav.read())
                    if(fav_response):
                        objConf.printMessage(
                            "  [] Favicon md5 computation : " + md5_favicon, "r")
                        fav_db = objFav.isFaviconInDB(md5_favicon)
                        if fav_db:
                            objConf.printMessage(
                                "  [] Favicon belongs to : " + fav_db, "r")

                            # check if default pass stored
                            flag_favicon_found = objConf.isFaviconPass(
                                md5_favicon)
                            if flag_favicon_found:
                                objConf.printMessage(
                                    "  [] Default Passwords Found", "r", "find")
                        else:
                            objConf.printMessage(
                                "  [] No Favicon found in the Database", "r")
                            if objConf.entry_favicon:
                                html_title = htmlAnalyser.getTitle(
                                    html_response)
                                conf.setOneLineFileContent(
                                    favdb, md5_favicon + ":" + html_title + "\n")
                                objConf.printMessage(
                                    "  [] Favicon added to the Database", "r")
                    else:
                        objConf.printMessage(
                            "  [] No Favicon found !", "r", "error")
                else:
                    objConf.printMessage(" [*] Favicon Tests", "v")
                    objConf.printMessage("  [] Skipped", "v")
            except Exception, e:
                objConf.printMessage(
                    "  [] Favicon Error: " + str(e), "r", "error")

            # Hash Tests
            if flag_hash:
                objConf.printMessage(" [*] Hash Tests", "r", "info")
                objConf.printMessage("  []  Under Development", "r", "error")
            else:
                objConf.printMessage(" [*] Hash Tests", "v")
                objConf.printMessage("  [] Skipped", "v")

            # Form Tests : Extract All form and then try to identify a login
            # form, according to the configuration file stored in "conf/"
            if flag_form:
                objConf.printMessage(" [*] Form Tests", "r", "info")
                flag_response, response = objReq.request()

                if flag_response:
                    content = response.read()

                    number = htmlAnalyser.isThereAForm(content)
                    if(number > 0):
                        objConf.printMessage("  [] " + str(
                            number) + " Form(s) found.", "r")

                        all_form = htmlAnalyser.getAllForm(content)
                        for form_u in all_form:
                            input_match, form = objHtml.isThereALoginForm(
                                form_u, aggressive)
                        # print form
                        if input_match != []:
                            objConf.printMessage(
                                "  [] " + str(input_match), "v")
                        else:
                            objConf.printMessage(
                                "  [] Extracting Form Issue", "r", "error")

                        objConf.printMessage(
                            " [*] Login Form Tests", "r", "info")
                        if len(input_match) > 0:
                            flag_login_form = True
                            objConf.printMessage("  [] Found", "r")

                            objConf.printMessage("  [] Login Form", "v")
                            objConf.printMessage(form, "v")

                            # extract information and try to submit
                            method, action, data, res_u, res_p = objHtml.extractFormInput(
                                form, objConf.pattern_login, objConf.pattern_pass)

                            if res_p:
                                objConf.printMessage(
                                    "  [] Login Input " + str(res_p), "v")

                            if res_u:
                                objConf.printMessage(
                                    "  [] Password Input " + str(res_u), "v")

                            objConf.printMessage(
                                "  [] Method : " + method, "v")
                            objConf.printMessage(
                                "  [] Action : " + action, "v")
                            objConf.printMessage(
                                "  [] Data : " + str(data), "v")
                        else:
                            objConf.printMessage(
                                "  [] No Login Form Found", "r", "error")
                    else:
                        objConf.printMessage(
                            "  []  No Form Found", "r", "error")
            else:
                objConf.printMessage(" [*] Form Tests", "v")
                objConf.printMessage("  [] Skipped", "v")

            try:
                # Crawler... trying to find a login form...
                if flag_crawler and not flag_login_form:
                    objConf.printMessage(" [*] Crawler Test", "r", "info")
                    crawler = mySpider(objReq, objHtml)
                    crawler.crawl(callback="LoginForm")

                try:
                    if crawler.login_form_link:
                        objConf.printMessage("  [] Login Form Found at : " + str(
                            crawler.login_form_link), "r", "find")
                        flag_login_form = True
                except:
                    objConf.printMessage(
                        "  [] No Login Form Found...", "r", "error")
                else:
                    if crawler.login_form != None:
                        # extract information and try to submit
                        method, action, data, res_u, res_p = objHtml.extractFormInput(
                            crawler.login_form, objConf.pattern_login, objConf.pattern_pass)
                        if res_p:
                            objConf.printMessage(
                                "  [] Login Input " + str(res_p), "v")

                        if res_u:
                            objConf.printMessage(
                                "  [] Password Input " + str(res_u), "v")

                        objConf.printMessage("  [] Method : " + method, "v")
                        objConf.printMessage("  [] Action : " + action, "v")
                        objConf.printMessage("  [] Data : " + str(data), "v")
                    else:
                        flag_401 = True
                        flag_401_url = crawler.login_form_link

            except Exception, e:
                objConf.printMessage(
                    "  [] Crawler's Issue: " + str(e), "r", "error")

            # Bruteforce Tests
            inc = 0
            objConf.printMessage(" [*] BruteForce Tests", "r", "info")
            if flag_login_form:
                switch = False
                if flag_bf:
                    inc += 1
                if flag_default_password and (flag_favicon_found or flag_hash_found):
                    inc += 1
                    switch = True

                if inc > 0:
                    inc_loop = 0

                    while inc_loop < inc and not flag_bf_found:
                        if inc_loop == 0 and switch:
                            objConf.printMessage(
                                "  [] Test with Default Logins Passwords", "r")
                            if flag_favicon_found:
                                arr_default_login_password = objConf.getDefaultLoginPasswordByFavicon(
                                    md5_favicon)
                            elif flag_hash_found:
                                arr_default_login_password = objConf.getDefaultLoginPasswordByHash(
                                    md5_favicon)
                            else:
                                objConf.printMessage(
                                    "  [] Error... Something Wrong happened during detection...", "r", "error")
                                continue
                        else:
                            objConf.printMessage(
                                "  [] Test with Dictionaries", "r")
                            switch = False

                        if flag_401:

                            pool = multiprocessing.Pool(nb_proc)
                            results = pool.imap(
                                func=process_401, iterable=worker([switch, flag_401_url]))
                            for i, login, password in results:
                                if i:
                                    flag_bf_found = True
                                    break
                            pool.terminate()
                            pool.close()

                            if flag_bf_found:
                                objConf.printMessage(
                                    "  [] Credentials Found : " + login + " " + password, "r", "find")
                            else:
                                objConf.printMessage(
                                    "  [] No Credentials Found", "r", "error")
                        else:
                            # get a response with bad creds
                            flag_response, response = objReq.request(url=urlparse.urljoin(
                                objReq.getUrl(), action), method=method, data=data)
                            if flag_response:
                                bad_cred = response.read()
                                # print bad_cred
                                # print
                                # htmlAnalyser.getDifferenceBetweenTwoPages(testa,
                                # content)
                            else:
                                pass

                            for i in data:
                                if data[i] == objConf.pattern_pass:
                                    pattern_pass = i
                                elif data[i] == objConf.pattern_login:
                                    pattern_login = i

                            pool = multiprocessing.Pool(nb_proc)

                            results = pool.imap(func=process, iterable=worker(
                                [switch, action, pattern_pass, pattern_login, bad_cred]))
                            for i, login, password in results:
                                if i:
                                    flag_bf_found = True
                                    break
                            pool.terminate()
                            pool.close()

                            if flag_bf_found:
                                objConf.printMessage(
                                    "  [] Credentials Found : " + login + " " + password, "r", "find")
                            else:
                                objConf.printMessage(
                                    "  [] No Credentials Found", "r", "error")

                        inc_loop += 1
                else:
                    objConf.printMessage(" [*] BruteForce Tests", "v")
                    objConf.printMessage("  [] Skipped", "v")
            else:
                objConf.printMessage(
                    "  [] Skipped because no Login Form Found", "r", "error")

        objConf.printMessage(" \n", "r")

    except KeyboardInterrupt:
        objConf.printMessage("Process interrupted by user..", "r", "error")
    except:
        print "\n\n", traceback.format_exc()
        pass
