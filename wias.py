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
__date__ = "22/07/2013"
__version__ = "1.3"
__maintainer__ = "v4lproik"
__email__ = "v4lproik@gmail.com"
__status__ = "Development"
__twitter__ = "v4lproik"

'''
Further work is actually  being undertaken :
- Improvement of web crawler (switch with phantomJS)
- Improvement of the autologin form process
- Module loader for specific web interfaces
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
    import time

except ImportError, err:
    raise
    print >>sys.stderr, "[X] Unable to import : %s\n" % err
    sys.exit(1)


def banner():
    banner = '''
    |----------------------------------------------------------|
    |              Web Interface Auto Submit 1.3               |
    |                         v4lproik                         |
    |----------------------------------------------------------|\n'''
    print banner


def checkArgs():
    if len(sys.argv) == 3:
        if sys.argv[1] == "-m" and sys.argv[2] == "list":
            print " [*] Modules"
            for i in conf.ALL_MODULE_DESCRIPTION:
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
            if not i in conf.ALL_MODULE:
                raise
        return value
    except:
        raise argparse.ArgumentTypeError(
            "Modules must be : " + str(conf.ALL_MODULE))


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
        objReq.url, action), method=method, data=data)


    #print response.headers


    if flag_response:
        #print response.url
        #print data[pattern_login]
        #print data[pattern_pass]
        content = response.read()
        #print content
        if htmlAnalyser.get_difference_between_two_pages(content, bad_cred) != 0:
            # let's perform another test... if another random parameter exists within the web (eg : visit counter)
            #print content
            diffs = htmlAnalyser.extract_diff_from_response_HTML(bad_cred, content)
            diffs = htmlAnalyser.remove_HTML_Tag(diffs)
            #print "diff " + str(diffs)

            res_am_IL_logged = objHtml.am_I_logged_In_grep(diffs, login);

            #first check : grep word
            if not res_am_IL_logged:
                #agressive test mode
                #second check : is the login form still here ?
                if objHtml.am_I_logged_in_is_form_here(bad_cred, content) and aggressive:
                    conf.print_message(
                        "   [] Potentionaly Good Credentials : " + login + "/" + pass_u, "r", "find")
                    conf.print_message(
                        "       Pattern found : Password input is not here anymore...", "r")
                    return True, login, pass_u
                else:
                    conf.print_message(
                        "   [] Bad Credentials : " + login + "/" + pass_u, "v")
                return False, login, pass_u
            else:
                conf.print_message(
                    "   [] Potentionaly Good Credentials : " + login + "/" + pass_u, "r", "find")
                conf.print_message(
                    "       Pattern found : " + res_am_IL_logged, "r")
                return True, login, pass_u
        else:
            conf.print_message(
                "   [] Good Credentials : " + login + "/" + pass_u, "v", "find")
            return True, login, pass_u


def process_401(tab):
    login, pass_u, tab_plus = tab
    action = tab_plus[1]

    cred_encode = webRequest.base64stringAuth(login, pass_u)
    #print cred_encode
    # update headers...

    objReq.headers["Authorization"] = cred_encode

    flag_response, response = objReq.request(
        url=action)

    if flag_response:
        if response.code == 401:
            conf.print_message(
                "   [] Bad Credentials : " + login + "/" + pass_u, "v")
            return False, login, pass_u
        else:
            conf.print_message(
                "   [] Good Credentials : " + login + "/" + pass_u, "v", "find")
            return True, login, pass_u


if __name__ == "__main__":

    report = []

    try:
        start_time = time.time()
        parser = argparse.ArgumentParser()
        gr1 = parser.add_argument_group("main arguments")
        gr1.add_argument('-f', '--filename', dest='filename',
                         required=True, help='File with IP or DOMAIN - One per line')
        gr1.add_argument('-db', '--database', dest='database',
                         required=True, help='File with MD5:WEBName - One par line')
        gr1.add_argument(
            '-m', '--module', dest='module', required=True, nargs='+', type=checkMod,
            help='List of module that be running. For more details regarding modules, try : -m list. Modules List : ' + str(conf.ALL_MODULE))

        gr2 = parser.add_argument_group("optional arguments")
        gr2.add_argument('-v', '--verbose', dest='verbose',
                         default=False,  action='store_true', help='Verbosity level')
        gr2.add_argument('-c', '--color', dest='color', default=False,
                         action='store_true', help='Display Color to stdin')
        gr2.add_argument(
            '-a', '--aggressive', dest='aggressive', default=False,
            action='store_true', help='Try to identify a login form through different processes such as the input name attribute.')
        gr2.add_argument(
            '-conf', '--conf_folder', dest='conf_folder', default="conf/",
            action='store_true', help='Path of the conf folder where all the configuration files are stored')
        gr3 = parser.add_argument_group("optional arguments for crawler module")
        gr3.add_argument('-kf', '--keep_searching_form', dest='keep_searching_form', default=False,
                         action='store_true', help='Keep looking for every auth forms within the domain. The program won\'t stop after finding the first occurence.')
        gr4 = parser.add_argument_group("optional arguments for bruteforce module")
        gr4.add_argument('-kb', '--keep_bruteforcing', dest='keep_bruteforcing', default=False,
                         action='store_true', help='Keep bruteforcing even if a pair of credentials is found.')


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
        keep_bruteforcing = args.keep_bruteforcing
        keep_searching_form = args.keep_searching_form


        # Configuration Init
        conf(configuration_folder_path, module)

        if keep_searching_form and not 'crawler' in conf.MODULES:
            conf.print_message(
                "\n[*] You cannot set --keep_searching_form (-kf) without activating the crawler module", "r", "error")
            keep_searching_form = False
            sys.exit(1)

        if keep_bruteforcing and not 'bruteforce' in conf.MODULES:
            conf.print_message(
                "\n[*] You cannot set --keep_bruteforcing (-kb) without activating the bruteforce module", "r", "error")
            keep_bruteforcing = False
            sys.exit(1)



        objFav = faviconDB(conf.get_file_content(favdb))
        objBF = bruteForce(conf.LOGIN_DICTIONNARY, conf.PASS_DICTIONNARY)
        dic_domain = conf.get_file_content(filename)
        if verbosity:
            conf.VERBOSITY = True
        if color:
            conf.COLOR = True
        kwargs = conf.get_tag_variable()
        objHtml = htmlAnalyser(**kwargs)

        # Display Settings
        conf.print_message("[*] Settings", "v", "info")
        conf.print_message(conf.get_settings(), "v", "info")

        # Run test for each web interface
        for domain in dic_domain:

            # check the domain syntax...
            res_domain = conf.check_ip_conformity(domain)

            if not res_domain:
                conf.print_message(
                    "\n[*] Syntax Error with domain given : " + domain, "r", "error")
                continue
            else:
                domain = res_domain
                conf.print_message(
                    "\n[*] Analyse running for url given : " + domain, "r", "find")

            # Init variables for each domain
            flag_form = True
            flag_login_form = False
            flag_401 = False
            flag_hash_found = False
            flag_favicon_found = False
            flag_bf_found = False
            nb_proc = int(conf.THREAD)
            action = ""
            html_response = ""

            # Check activated modules
            if "favicon" in conf.MODULES:
                # allFavicon = objFav.getAllFavicon()
                flag_favicon = True
            else:
                flag_favicon = False

            if "hash" in conf.MODULES:
                flag_hash = True
            else:
                flag_hash = False

            if "bruteforce" in conf.MODULES:
                flag_bf = True
            else:
                flag_bf = False

            if "enumeration" in conf.MODULES:
                flag_bf = False
                flag_favicon = False
                flag_hash = False
                flag_form = False

            if "default_password" in conf.MODULES:
                flag_default_password = True
            else:
                flag_default_password = False

            if "crawler" in conf.MODULES:
                flag_crawler = True
            else:
                flag_crawler = False

            if "report" in conf.MODULES:
                flag_report = True
            else:
                flag_report = False

            ###############################
            #           TEST URL
            ###############################


            #we are not extracting login  form at this point however if a 401 http code is found... it is considered by the program as a login form
            login_form_link_tab = []

            # Url Request
            objReq = webRequest(
                domain, conf.URL_DO_NOT_SCAN, UA=conf.USER_AGENT, proxy=conf.PROXY,
                timeout=conf.HTTP_TIMEOUT, cookie_redirection=conf.REDIRECT_COOKIE)
            flag_response, response = objReq.request()

            # Exception...
            if flag_response:
                # if 30X code -> update the domain
                if domain in MyHTTPRedirectHandler.permanent_redirection:
                    objReq.url = response.url
                    conf.print_message(
                        " [] " + str(response.code) + " Found : " + domain + " -> " + objReq.url, "r", "find")

                if response.code == 401:
                    conf.print_message(
                        " [] The server returned : " + str(response.code), "r")

                    # only bf is available for 401
                    if not flag_bf:
                        conf.print_message(
                            " [] Only BruteForce Tests are available for Unauthorised response", "r", "error")
                        continue

                    #401 is a "login form" obviously...
                    flag_favicon = False
                    flag_hash = False
                    flag_form = False
                    flag_login_form = True
                    flag_401 = True
                    flag_401_url = objReq.url
                    data = {}
                    login_form_link_tab.append([objReq.url, 401, None])


                    html_response = response.read()
                elif response.code == 200:
                    #update reponse_url
                    objReq.url = response.url
                    if not "enumeration" in conf.MODULES:
                        conf.print_message(
                            " [] The server returned : " + str(response.code), "r")
                    html_response = response.read()
                    #print html_response
                else:
                    conf.print_message(
                        " [] The server returned : " + str(response.code), "r")
                    continue
            else:
                conf.print_message(" [] Error : " + str(
                    response), "r", "error")
                continue



            ###############################
            # FORM TEST : Is there a form ?
            ###############################


            # Form enumeration only
            if not flag_hash and not flag_favicon and not flag_form and not flag_bf:
                forms = htmlAnalyser.get_all_form(html_response)
                if len(forms) > 0:
                    print forms
                continue



            ###############################
            # FAVICON TEST : Do I have a favicon matching the one used by the domain ?
            ###############################



            # Favicon Tests
            try:
                if flag_favicon:
                    conf.print_message(" [*] Favicon Tests", "r", "info")

                    fav_response, fav = objReq.get_favicon(
                        html_response=html_response)

                    # favicon method
                    md5_favicon = cryptoComputation.md5ChecksumContent(
                        fav.read())
                    if(fav_response):
                        conf.print_message(
                            "  [] Favicon md5 computation : " + md5_favicon, "r")
                        fav_db = objFav.isFaviconInDB(md5_favicon)
                        if fav_db:
                            conf.print_message(
                                "  [] Favicon belongs to : " + fav_db, "r")

                            # check if default pass stored
                            flag_favicon_found = conf.is_favicon_pass(
                                md5_favicon)
                            if flag_favicon_found:
                                conf.print_message(
                                    "  [] Default Passwords Found", "r", "find")
                            else:
                                conf.print_message(
                                    "  [] Default Passwords not Found", "r", "")
                        else:
                            conf.print_message(
                                "  [] No Favicon found in the Database", "r")
                            if conf.entry_favicon:
                                html_title = htmlAnalyser.get_title(
                                    html_response)
                                conf.set_one_line_file_content(
                                    favdb, md5_favicon + ":" + html_title + "\n")
                                conf.print_message(
                                    "  [] Favicon added to the Database", "r")
                    else:
                        conf.print_message(
                            "  [] No Favicon found !", "r", "error")
                else:
                    conf.print_message(" [*] Favicon Tests", "v")
                    conf.print_message("  [] Skipped", "v")
            except Exception, e:
                conf.print_message(
                    "  [] Favicon Error: " + str(e), "r", "error")



            ###############################
            # HASH TEST : Do I have a hash matching the web page of the url ?
            ###############################


            # Hash Tests
            if flag_hash:
                conf.print_message(" [*] Hash Tests", "r", "info")
                conf.print_message("  []  Under Development", "r", "error")
            else:
                conf.print_message(" [*] Hash Tests", "v")
                conf.print_message("  [] Skipped", "v")



            ###############################
            # LOGIN FORM TEST : Is my login is a login form ?
            ###############################


            # Form Tests : Extract All form and then try to identify a login
            # form, according to the configuration file stored in "conf/"

            #array with all the url response code and form extracted
            #login_form_link_tab = []
            login_form_link_tab2 = []
            login_form_link_tab3 = []

            if flag_form:
                conf.print_message(" [*] Form Tests", "r", "info")
                flag_response, response = objReq.request()

                if flag_response:
                    content = response.read()
                    #grep
                    url_response = response.url
                    url = objReq.url
                    response_code = response.code

                    number = htmlAnalyser.is_there_a_form(content)
                    if(number > 0):
                        conf.print_message("  [] " + str(
                            number) + " Form(s) found.", "r")

                        all_form = htmlAnalyser.get_all_form(content)
                        for form_u in all_form:
                            input_match, form = objHtml.is_there_a_login_form(
                                form_u, aggressive)

                        # print form
                        if input_match != []:
                            conf.print_message(
                                "  [] " + str(input_match), "v")
                        else:
                            conf.print_message(
                                "  [] Extracting Form Issue", "r", "error")

                        conf.print_message(
                            " [*] Login Form Tests", "r", "info")
                        if len(input_match) > 0:
                            flag_login_form = True

                            conf.print_message("  [] Found", "r")

                            conf.print_message("  [] Login Form", "v")
                            conf.print_message(form, "v")

                            # extract information and try to submit
                            method, action, data, res_u, res_p = objHtml.extract_form_input(
                                form, conf.PATTERN_LOGIN, conf.PATTERN_PASS)

                            try:
                                if res_p:
                                    conf.print_message(
                                        "  [] Login Input " + str(res_p), "v")
                                else:
                                    raise
                                if res_u:
                                    conf.print_message(
                                        "  [] Password Input " + str(res_u), "v")
                                else:
                                    raise

                                if res_u and res_p and len(data)>0:
                                    conf.print_message(
                                        "  [] Method : " + method, "v")
                                    conf.print_message(
                                        "  [] Action : " + action, "v")
                                    conf.print_message(
                                        "  [] Data : " + str(data), "v")
                                    #pass form[0] instead of url - contains url_response if redirection
                                    login_form_link_tab.append([objReq.url, response_code, form])

                            except Exception, e:
                                conf.print_message(
                                    "   [] Extracting data failed :", "r", "error")
                                conf.print_message(
                                    "       password : " + str(res_u) + "\n       login : " + str(res_p), "r")

                        else:
                            conf.print_message(
                                "  [] No Login Form Found", "r", "error")
                    else:
                        conf.print_message(
                            "  []  No Form Found", "r", "error")
            else:
                conf.print_message(" [*] Form Tests", "v")
                conf.print_message("  [] Skipped", "v")









            ###############################
            # CRAWLER TEST : Can I find a login form or more within the domain ?
            ###############################

            try:
                # Crawler... trying to find a login form...
                if flag_crawler and not flag_login_form:
                    conf.print_message(" [*] Crawler Test", "r", "info")

                    crawler = mySpider(objReq, objReq.url, objReq.domain, objHtml, conf.MAX_DEPTH, conf.EXTENSIONS_DO_NOT_SCAN, conf.LIMIT_REQUEST_P_PAGE, keep_searching_form)

                    try:
                        crawler.crawl(objReq.url, callback="LoginForm")
                    except Exception, e:
                        conf.print_message("  [] Crawler's Issue : " + str(e), "r", "error")


                    #if found any forms
                    login_form_link_tab2 = crawler.login_form_link_tab
                    if len(login_form_link_tab2) > 0:
                        for form in login_form_link_tab2:
                            conf.print_message("  [] Login Form Found with code " + str(form[1]) + " at : " + str(
                                form[0]), "r", "find")


                            # extract information and try to submit
                            if int(form[1]) != 401:
                                method, action, data, res_u, res_p = objHtml.extract_form_input(
                                    form[2], conf.PATTERN_LOGIN, conf.PATTERN_PASS)

                                try:
                                    if res_p:
                                        conf.print_message(
                                            "  [] Login Input " + str(res_p), "v")
                                    else:
                                        raise

                                    if res_u:
                                        conf.print_message(
                                            "  [] Password Input " + str(res_u), "v")
                                    else:
                                        raise

                                    if res_u and res_p and len(data)>0:
                                        conf.print_message(
                                            "  [] Method : " + method, "v")
                                        conf.print_message(
                                            "  [] Action : " + action, "v")
                                        conf.print_message(
                                            "  [] Data : " + str(data), "v")

                                        conf.print_message("  [] Updating url : " + objReq.url + " -> " + str(form[0]), "v")
                                        #pass form[0] instead of url - contains url_response if redirection
                                        login_form_link_tab.append([form[0], response_code, form[2]])
                                except Exception, e:
                                    conf.print_message(
                                        "   [] Extracting data failed :", "r", "error")
                                    conf.print_message(
                                        "       password : " + str(res_u) + "\n       login : " + str(res_p), "r")

                            elif int(form[1]) == 401:
                                login_form_link_tab.append([form[0], form[1], None])



                            else:
                                flag_401 = True
                                flag_401_url = crawler.login_form_link
                                conf.print_message("  [] Updating url : " + objReq.url + " -> " + str(form[0]), "v")

                            flag_login_form = True
                    else:
                        conf.print_message(
                            "  [] No Login Form Found...", "r", "error")


            except Exception, e:
                conf.print_message(
                    "  [] Crawler's Issue: " + str(e), "r", "error")









            ###############################
            # BRUTEFORCE TEST
            ###############################

            conf.print_message(" [*] BruteForce Tests", "r", "info")

            if flag_bf:

                #merge al the tabs with forms
                login_form_link_tab3 = login_form_link_tab
                login_form_link_tab = []
                #for array in login_form_link_tab2:
                #    login_form_link_tab.append(array)
                for array in login_form_link_tab3:
                    login_form_link_tab.append(array)


                #print login_form_link_tab
                for array in login_form_link_tab:
                    inc = 0
                    url = array[0]
                    response_code = array[1]
                    flag_bf_found = False
                    login_password_result = []

                    if array[1] != 401:
                        objReq.url = array[0]
                        form = array[2]

                        #print str(array)

                        method, action, data, c, d = objHtml.extract_form_input(
                            form, conf.PATTERN_LOGIN, conf.PATTERN_PASS)

                        #print data
                    #print method
                    #print str(form)

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
                                    conf.print_message(
                                        "  [] Test with Default Logins Passwords", "r")
                                    if flag_favicon_found:
                                        arr_default_login_password = conf.getDefaultLoginPasswordByFavicon(
                                            md5_favicon)
                                    elif flag_hash_found:
                                        arr_default_login_password = conf.getDefaultLoginPasswordByHash(
                                            md5_favicon)
                                    else:
                                        conf.print_message(
                                            "  [] Error... Something Wrong happened during detection...", "r", "error")
                                        continue
                                else:
                                    switch = False

                                conf.print_message(
                                    "  [] Test with Dictionaries for URL " + url, "r")



                                #normal process...
                                if response_code == 401:

                                    #action doesn't exist...
                                    action = ""

                                    pool = multiprocessing.Pool(nb_proc)
                                    results = pool.imap(
                                        func=process_401, iterable=worker([switch, url]))
                                    for i, login, password in results:
                                        if i:
                                            flag_bf_found = True
                                            login_password_result.append([url, [login, password]])
                                            if not keep_bruteforcing:
                                                break

                                    #close processes
                                    pool.terminate()
                                    pool.close()

                                    if flag_bf_found:

                                        gen = (array for array in login_password_result if url in array[0])
                                        for array in gen:
                                            report.append([array[0], array[1][0], array[1][1]])
                                            conf.print_message(
                                                "  [] Credentials Found : " + str(array[1][0]) + " " + str(array[1][1]), "r", "find")
                                    else:
                                        conf.print_message(
                                            "  [] No Credentials Found", "r", "error")

                                #if no 401
                                else:
                                    # get a response with bad creds

                                    #we need to create request with action !

                                    #if action is relative path, we need to add the domain


                                    #if action is url within the domain, replace url to action

                                    '''
                                    print "request = > " + urlparse.urljoin(
                                        url, action)
                                    print "method => " + method
                                    print "data => " + str(data)
                                    print "action => " + action
                                    '''

                                    flag_response, response = objReq.request(url=urlparse.urljoin(
                                        url, action), method=method, data=data)

                                    if flag_response:

                                        bad_cred = response.read()
                                        #print bad_cred
                                        # print
                                        # htmlAnalyser.get_difference_between_two_pages(testa,
                                        # content)

                                        for i in data:
                                            if data[i] == conf.PATTERN_PASS:
                                                pattern_pass = i
                                            elif data[i] == conf.PATTERN_LOGIN:
                                                pattern_login = i

                                        pool = multiprocessing.Pool(nb_proc)

                                        results = pool.imap(func=process, iterable=worker(
                                            [switch, action, pattern_pass, pattern_login, bad_cred]))
                                        for i, login, password in results:
                                            if i:
                                                flag_bf_found = True
                                                login_password_result.append([url, [login, password]])
                                                if not keep_bruteforcing:
                                                    pool.terminate()
                                                    pool.close()
                                                    break

                                        #close processes
                                        pool.terminate()
                                        pool.close()

                                        if flag_bf_found:
                                            gen = (array for array in login_password_result if url in array[0])
                                            for array in gen:
                                                report.append([array[0], array[1][0], array[1][1]])
                                                conf.print_message(
                                                    "  [] Credentials Found : " + str(array[1][0]) + " " + str(array[1][1]), "r", "find")
                                        else:
                                            report.append([array[0], "****", "****"])
                                            conf.print_message(
                                                "  [] No Credentials Found", "r", "error")

                                    else:
                                        conf.print_message(
                                            "  [] Form request error : " + response, "r", "error")

                                inc_loop += 1
                        else:
                            conf.print_message(" [*] BruteForce Tests", "v")
                            conf.print_message("  [] Skipped", "v")
                    else:
                        conf.print_message(
                            "  [] Skipped because no Login Form Found", "r", "error")

            else:
                conf.print_message("  [] Skipped", "r")


        gen=[i[1]!="****" for i in report]
        if True in gen:
            conf.print_message("\n  [] Credentials found", "r")
            for i in filter(lambda w:w[1]!="****",report):
                print "   " + i[1] + "/" + i[2] + " | " + i[0]

        if False in gen:
            conf.print_message("\n  [] Credentials not found", "r")
            for i in filter(lambda w:w[1]=="****",report):
                print "   " + i[1] + "/" + i[2] + " | " + i[0]
            print "\n"



        conf.print_message(" [*] Report", "r", "info")
        if flag_report:
            conf.print_message("  [] Report can be found at the following location : " + str(conf.REPORT_PATH), "r")
            conf.print_message(" \n", "r")

        print("\n--- %s seconds ---" % str(time.time() - start_time))
        print "\n"
    except KeyboardInterrupt:
        conf.print_message("Process interrupted by user..", "r", "error")
    except:
        print "\n\n", traceback.format_exc()
        pass
