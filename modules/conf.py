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


try:
    import re
    import sys
    import time
    import os
except ImportError, err:
    raise
    print >>sys.stderr, "[X] Unable to import : %s\n" % err
    sys.exit(1)


class conf(object):

    ALL_MODULE = ["hash", "bruteforce", "favicon",
                  "enumeration", "default_password", "crawler", "report"]
    ALL_MODULE_DESCRIPTION = [
        '  [] hash : Hash computation will be performed, trying to identify the web interface.',
        "  [] bruteforce : A bruteforce attack will be performed if a login form is detected.",
        "  [] favicon : A Hash computation will be performed on the favicon, trying to identify the web interface.",
        "  [] enumeration : All forms found will be display to the screen. This module has been implemented so you can easily add password pattern thanks to the form's html response.",
        "  [] default_password : A bruteforce attack will be performed if a favicon hash or page hash is found - with default login/password - from password/default-password-web-interface.txt.",
        "  [] crawler : If not login form is found within the response of the url provided, the web crawler will try to find a login form.",
        "  [] report : Create a report at ./report/<date>.txt"]


    def __init__(self, configuration_folder_path, module):

        conf.CONFIGURATION_FOLDER_PATH = configuration_folder_path
        #find general.conf
        general_file = conf.get_file_content(
            conf.CONFIGURATION_FOLDER_PATH + "general.conf")

        #store modules from cli
        conf.MODULES = ','.join(module).split(',')




        for option in general_file:

            if re.match("#(.*)#", option):
                continue
            elif "Thread=" in option:
                conf.THREAD = option.replace("Thread=", "")
            elif "User-Agent=" in option:
                conf.USER_AGENT = option.replace("User-Agent=", "")
            elif "Redirect_cookie=" in option:
                conf.REDIRECT_COOKIE = option.replace("Redirect_cookie=", "")
            elif "Timeout=" in option:
                conf.HTTP_TIMEOUT = option.replace("Timeout=", "")
            elif "Proxy=" in option:
                self.proxy = option.replace("Proxy=", "")
                conf.PROXY = self._proxy
                del self._proxy
            elif "Pattern_login=" in option:
                conf.PATTERN_LOGIN = option.replace("Pattern_login=", "")
            elif "Pattern_pass=" in option:
                conf.PATTERN_PASS = option.replace("Pattern_pass=", "")
            elif "Login_dictionary=" in option:
                self.login_dictionnary = option.replace(
                    "Login_dictionary=", "")
                conf.LOGIN_DICTIONNARY = self.login_dictionnary
                del self._login_dictionnary
            elif "Pass_dictionary=" in option:
                self.pass_dictionnary = option.replace("Pass_dictionary=", "")
                conf.PASS_DICTIONNARY = self.pass_dictionnary
                del self._pass_dictionnary
            elif "Form_tags=" in option:
                conf.FORM_TAGS = option.replace("Form_tags=", "")
            elif "Form_tags_password_name=" in option:
                conf.FORM_TAGS_password_name = option.replace(
                    "Form_tags_password_name=", "")
            elif "Form_tags_password_type=" in option:
                conf.FORM_TAGS_password_type = option.replace(
                    "Form_tags_password_type=", "")
            elif "Form_tags_username_name=" in option:
                conf.FORM_TAGS_username_name = option.replace(
                    "Form_tags_username_name=", "")
            elif "Form_tags_username_type=" in option:
                conf.FORM_TAGS_username_type = option.replace(
                    "Form_tags_username_type=", "")
            elif "Form_tags_csrf_name=" in option:
                conf.FORM_TAGS_csrf_name = option.replace(
                    "Form_tags_csrf_name=", "")
            elif "Found=" in option:
                conf.ENTRY_FAVICON = option.replace("Found=", "")
            elif "Default_login_pass_dictionary=" in option:
                conf.DEFAULT_LOGIN_PASS_DICTIONNARY = option.replace(
                    "Default_login_pass_dictionary=", "")
            elif "Pattern_logged_in=" in option:
                conf.PATTERN_LOGGED_IN = option.replace(
                    "Pattern_logged_in=", "")
            elif "scan_other_domain=" in option:
                conf.SCAN_OTHER_DOMAIN = option.replace(
                    "scan_other_domain=", "")
            elif "doNotScan=" in option:
                conf.EXTENSIONS_DO_NOT_SCAN_PATH = option.replace(
                    "doNotScan=", "")
            elif "max_depth=" in option:
                conf.MAX_DEPTH = option.replace(
                    "max_depth=", "")
            elif "only_scan_domain_scope=" in option:
                conf.ONLY_SCAN_DOMAIN_SCOPE = option.replace(
                    "only_scan_domain_scope=", "")
            elif "url_do_not_scan=" in option:
                conf.URL_DO_NOT_SCAN_PATH = option.replace(
                    "url_do_not_scan=", "")
            elif "limit_request_p_page=" in option:
                conf.LIMIT_REQUEST_P_PAGE = int(option.replace(
                    "limit_request_p_page=", ""))
            elif "dir_report=" in option:
                conf.DIR_REPORT = option.replace(
                    "dir_report=", "")


        # check default login password file syntax
        try:
            conf.DEFAULT_LOGIN_PASS_DICTIONNARY = conf.extract_file_default_password(
                conf.DEFAULT_LOGIN_PASS_DICTIONNARY)
        except Exception(), e:
            print e

        # get eextensions not to scan
        try:
            conf.EXTENSIONS_DO_NOT_SCAN = conf.extract_extensions_do_not_scan(
                self.CONFIGURATION_FOLDER_PATH + conf.EXTENSIONS_DO_NOT_SCAN_PATH)
        except Exception(), e:
            print e


        # get url not to scan
        try:
            conf.URL_DO_NOT_SCAN = conf.extract_url_do_not_scan(
                self.CONFIGURATION_FOLDER_PATH + conf.URL_DO_NOT_SCAN_PATH)
        except Exception(), e:
            print e

        # set verbosity 0 by default
        conf.VERBOSITY = False

        # set color
        conf.COLOR = False

         #if report module activated
        flag_report = False;
        if "report" in conf.MODULES:
            conf.REPORT_PATH = conf.generate_report_name(dir=str(conf.DIR_REPORT) + str(os.sep))
        else:
            conf.REPORT_PATH = ""


    def get_proxy(self):
        return self._proxy

    def set_proxy(self, value=None):
        try:
            tmp = value.split("|")
            if tmp[0] == "http" or tmp[0] == "https":
                self._proxy = {tmp[0]: tmp[1] + ":" + tmp[2]}
            elif re.match("#", value):
                self._proxy = None
            else:
                raise
        except:
            if value == None:
                self._proxy = None
            else:
                print "Proxy syntax : <http|https>|<host>|<port>"
                sys.exit(1)

    proxy = property(get_proxy, set_proxy)


    @staticmethod
    def display_settings():
        for i in filter(lambda w:w.isupper(),conf.__dict__ ):
            print " [] " + i + "=" + str(conf.__dict__[i])

    @staticmethod
    def get_settings():
        stri = ""
        for i in filter(lambda w:w.isupper(),conf.__dict__ ):
            stri = stri + " [] " + i + "=" + str(conf.__dict__[i]) + "\n"
        return stri

    @staticmethod
    def get_file_content(filename):
        try:
            with open(filename):
                pass
            handle = open(filename, 'r')
            return handle.read().splitlines()
        except IOError:
            print "The file " + filename + " does not exist."
            sys.exit(1)

    @staticmethod
    def set_file_content():
        pass

    @staticmethod
    def set_one_line_file_content(filename, line):
        try:
            with open(filename, "a") as f:
                f.write(line)
        except Exception as e:
            print "Errror : " + e

    @staticmethod
    def generate_report_name(dir):
        return dir + "wias-report-"+time.strftime("%Y%m%d-%H%M%S")+".txt"

    @staticmethod
    def get_http_variable():
        tmp = []
        tmp.append(conf.THREAD)
        tmp.append(conf.REDIRECT_COOKIE)
        tmp.append(conf.HTTP_TIMEOUT)
        tmp.append(conf.USER_AGENT)
        return tmp

    @staticmethod
    def get_bf_variable():
        tmp = {}
        tmp["Pattern_pass"] = conf.PATTERN_PASS
        tmp["Pattern_login"] = conf.PATTERN_LOGIN
        tmp["Pass_dictionnary"] = conf.get_file_content(
            conf.CONFIGURATION_FOLDER_PATH + conf.PASS_DICTIONNARY)
        tmp["Login_dictionnary"] = conf.get_file_content(
            conf.CONFIGURATION_FOLDER_PATH + conf.LOGIN_DICTIONNARY)
        return tmp

    @staticmethod
    def get_tag_variable():
        tmp = {}
        tmp["Form_tags"] = conf.FORM_TAGS
        tmp["Form_tags_password_name"] = conf.get_file_content(
            conf.CONFIGURATION_FOLDER_PATH + conf.FORM_TAGS_password_name)
        tmp["Form_tags_password_type"] = conf.get_file_content(
            conf.CONFIGURATION_FOLDER_PATH + conf.FORM_TAGS_password_type)
        tmp["Form_tags_username_name"] = conf.get_file_content(
            conf.CONFIGURATION_FOLDER_PATH + conf.FORM_TAGS_username_name)
        tmp["Form_tags_username_type"] = conf.get_file_content(
            conf.CONFIGURATION_FOLDER_PATH + conf.FORM_TAGS_username_type)
        tmp["Form_tags_csrf_name"] = conf.get_file_content(
            conf.CONFIGURATION_FOLDER_PATH + conf.FORM_TAGS_csrf_name)
        tmp["Pattern_logged_in"] = conf.get_file_content(
            conf.CONFIGURATION_FOLDER_PATH + conf.PATTERN_LOGGED_IN)
        return tmp

    def get_pass_dictionnary(self):
        return self.get_file_content(self._pass_dictionnary)

    def set_pass_dictionnary(self, value):
        self._pass_dictionnary = value

    pass_dictionnary = property(get_pass_dictionnary, set_pass_dictionnary)

    def get_login_dictionnary(self):
        return self.get_file_content(self._login_dictionnary)

    def set_login_dictionnary(self, value):
        self._login_dictionnary = value

    login_dictionnary = property(get_login_dictionnary, set_login_dictionnary)

    def get_redirect_cookie(self):
        return self._redirect_cookie

    def set_redirect_cookie(self, value):
        if value == "On" or value == "on":
            self._redirect_cookie = True
        else:
            self._redirect_cookie = False

    redirect_cookie = property(get_redirect_cookie, set_redirect_cookie)

    def get_scan_other_domain(self):
        return self._scan_other_domain

    @staticmethod
    def set_scan_other_domain(value):
        if value == "On" or value == "on":
            self._scan_other_domain = True
        else:
            self._scan_other_domain = False

    redirect_cookie = property(get_redirect_cookie, set_redirect_cookie)

    def get_entry_favicon(self):
        return self._entry_favicon

    def set_entry_favicon(self, value):
        if value == "On":
            self._entry_favicon = True
        elif value == "Off":
            self._entry_favicon = False
        else:
            print "The value for Found must be On or Off"
            sys.exit()

    entry_favicon = property(get_entry_favicon, set_entry_favicon)


    @staticmethod
    def print_message(message, level, type=None):
        dir = conf.REPORT_PATH
        if(dir != ""):
            conf.set_one_line_file_content(dir, str(message))
        if level == "r" or (level == "v" and conf.VERBOSITY):
            if conf.COLOR:
                if type == "info":
                    print(chr(27) + "[0;93m" + message + chr(27) + "[0m")
                elif type == "find":
                    print(chr(27) + "[0;32m" + message + chr(27) + "[0m")
                elif type == "error":
                    print(chr(27) + "[0;31m" + message + chr(27) + "[0m")
                else:
                    print message
            else:
                print message

    @staticmethod
    def extract_file_default_password(filename):
        try:
            handle = open(filename, 'r')
            content = handle.readlines()
            size = len(content)
            line = 0

            arr = []
            while line <= size:
                fav = ""
                has = ""
                key = ""
                pas = []
                if re.match("#favicon:", content[line]):
                    fav = content[line].rstrip().replace(
                        "#favicon:", "").split(";")
                    # print content[line]
                    if re.match("#hash:", content[line + 1]):
                        has = content[line + 1].rstrip().replace(
                            "#hash:", "").split(";")
                        if re.match("#keywords:", content[line + 2]):
                            key = content[line + 2].rstrip().replace(
                                "#keywords:", "").split(";")
                            while content[line + 3] != "\n":
                                pas.append(content[line + 3].rstrip())
                                line += 1
                                if line + 3 >= size:
                                    break
                        else:
                            raise
                    else:
                        raise
                else:
                    raise
                arr.append([fav, has, key, pas])
                line += 4
        except IOError:
            print "The file " + filename + " does not exist."
            sys.exit(1)
        except IndexError:
            sys.exit()
        except Exception, e:
            # print " [] Error " + e
            print e
            sys.exit()

        return arr

    @staticmethod
    def is_favicon_pass(favicon):
        for i in conf.DEFAULT_LOGIN_PASS_DICTIONNARY:
            for fav in i[0]:
                if str(fav) == str(favicon):
                    return True
        return False

    def getDefaultLoginPasswordByFavicon(self, favicon):
        for i in conf.DEFAULT_LOGIN_PASS_DICTIONNARY:
            for fav in i[0]:
                if str(fav) == str(favicon):
                    return i[3]
        print "Can't get Default Login Password..."
        sys.exit()

    def getDefaultLoginPasswordByHash(self, hash):
        for i in conf.DEFAULT_LOGIN_PASS_DICTIONNARY:
            for fav in i[0]:
                if str(fav) == str(favicon):
                    return i[3]
        print "Can't get Default Login Password..."
        sys.exit()

    @staticmethod
    def check_ip_conformity(domain):
        regex = re.compile(
            r'^(?:http|ftp)s?://' # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
            r'localhost|' #localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
            r'(?::\d+)?' # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        if regex.search(domain):
            return domain
        else:
            regex = re.compile(
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
                r'localhost|' #localhost...
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
                r'(?::\d+)?' # optional port
                r'(?:/?|[/?]\S+)$', re.IGNORECASE)
            if regex.search(domain):
                return "http://"+domain
            else:
                return False

    @staticmethod
    def extract_extensions_do_not_scan(path):
        handle = open(path, 'r')
        return [line.rstrip() for line in handle.readlines()]

    @staticmethod
    def extract_url_do_not_scan(path):
        handle = open(path, 'r')
        return [line.rstrip() for line in handle.readlines()]


