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
except ImportError, err:
    raise
    print >>sys.stderr, "[X] Unable to import : %s\n" % err
    sys.exit(1)

class conf(object):
    
    all_module = ["hash", "bruteforce", "favicon", "enumeration", "default_password", "crawler"]
    all_module_description = ['  [] hash : Hash computation will be performed, trying to identify the web interface.',
                              "  [] bruteforce : A bruteforce attack will be performed if a login form is detected.",
                              "  [] favicon : A Hash computation will be performed on the favicon, trying to identify the web interface.",
                              "  [] enumeration : All forms found will be display to the screen. This module has been implemented so you can easily add password pattern thanks to the form's html response.",
                              "  [] default_password : A bruteforce attack will be performed if a favicon hash or page hash is found - with default login/password - from password/default-password-web-interface.txt.",
                              "  [] crawler : If not login form is found within the response of the url provided, the web crawler will try to find a login form." ]

    def __init__(self, configuration_folder_path, module):

        self.configuration_folder_path = configuration_folder_path
        general_file = self.getFileContent(configuration_folder_path + "general.conf")

        self.module = ','.join(module).split(',')

        for option in general_file:

            if re.match("#(.*)#", option):
                continue
            elif "Thread=" in option:
                self.thread = option.replace("Thread=", "")
            elif "User-Agent=" in option:
                self.user_agent = option.replace("User-Agent=", "")
            elif "Redirect_cookie=" in option:
                self.redirect_cookie = option.replace("Redirect_cookie=", "")
            elif "Timeout=" in option:
                self.http_timeout = option.replace("Timeout=", "")
            elif "Proxy=" in option:
                self.proxy = option.replace("Proxy=", "")
            elif "Pattern_login=" in option:
                self.pattern_login = option.replace("Pattern_login=", "")
            elif "Pattern_pass=" in option:
                self.pattern_pass = option.replace("Pattern_pass=", "")
            elif "Login_dictionary=" in option:
                self.login_dictionnary = option.replace("Login_dictionary=", "")
            elif "Pass_dictionary=" in option:
                self.pass_dictionnary = option.replace("Pass_dictionary=", "")
            elif "Form_tags=" in option:
                self.form_tags = option.replace("Form_tags=", "")
            elif "Form_tags_password_name=" in option:
                self.form_tags_password_name = option.replace("Form_tags_password_name=", "")
            elif "Form_tags_password_type=" in option:
                self.form_tags_password_type = option.replace("Form_tags_password_type=", "")
            elif "Form_tags_username_name=" in option:
                self.form_tags_username_name = option.replace("Form_tags_username_name=", "")
            elif "Form_tags_username_type=" in option:
                self.form_tags_username_type = option.replace("Form_tags_username_type=", "")
            elif "Form_tags_csrf_name=" in option:
                self.form_tags_csrf_name = option.replace("Form_tags_csrf_name=", "")
            elif "Found=" in option:
                self.entry_favicon = option.replace("Found=", "")
            elif "Default_login_pass_dictionary=" in option:
                self.default_login_pass_dictionary = option.replace("Default_login_pass_dictionary=", "")
            elif "Pattern_logged_in=" in option:
                self.pattern_logged_in = option.replace("Pattern_logged_in=", "")
        
        #check default login password file syntax
        try:
            self.default_login_pass_dictionary = self.extractFileDefaultPassword(self.default_login_pass_dictionary)
        except Exception(), e:
            print e

        #set verbosity 0 by default
        self.verbosity = False

        #set color
        self.color = False

    def displaySettings(self):
        if self.verbosity:
            for i in self.__dict__:
                print " [] " + i + "=" + str(self.__dict__[i])

    @staticmethod
    def getFileContent(filename):
        try:
            with open(filename):pass
            handle = open(filename, 'r')
            return handle.read().splitlines()
        except IOError:
            print "The file " + filename + " does not exist."
            sys.exit(1)
    
    @staticmethod
    def setFileContent():
        pass

    @staticmethod
    def setOneLineFileContent(filename, line):
        try:
            with open(filename, "a") as f:
                f.write(line)
        except Exception as e:
            print "Errror : " + e



    def getHTTPVariable(self):
        tmp = []
        tmp.append(self.thread)
        tmp.append(self.redirect_cookie)
        tmp.append(self.http_timeout)
        tmp.append(self.user_agent)
        return tmp

    def getBFVariable(self):
        tmp = {}
        tmp["Pattern_pass"] = self.pattern_pass
        tmp["Pattern_login"] = self.pattern_login
        tmp["Pass_dictionnary"] = self.getFileContent(self.configuration_folder_path + self.pass_dictionnary)
        tmp["Login_dictionnary"] = self.getFileContent(self.configuration_folder_path + self.login_dictionnary)
        return tmp

    def getTAGVariable(self):
        tmp = {}
        tmp["Form_tags"] = self.form_tags
        tmp["Form_tags_password_name"] = self.getFileContent(self.configuration_folder_path + self.form_tags_password_name)
        tmp["Form_tags_password_type"] = self.getFileContent(self.configuration_folder_path + self.form_tags_password_type)
        tmp["Form_tags_username_name"] = self.getFileContent(self.configuration_folder_path + self.form_tags_username_name)
        tmp["Form_tags_username_type"] = self.getFileContent(self.configuration_folder_path + self.form_tags_username_type)
        tmp["Form_tags_csrf_name"] = self.getFileContent(self.configuration_folder_path + self.form_tags_csrf_name)
        tmp["Pattern_logged_in"] = self.getFileContent(self.configuration_folder_path + self.pattern_logged_in)
        return tmp

    def get_pass_dictionnary(self):
        return self.getFileContent(self._pass_dictionnary)

    def set_pass_dictionnary(self, value):
        self._pass_dictionnary = value

    pass_dictionnary = property(get_pass_dictionnary, set_pass_dictionnary)

    def get_login_dictionnary(self):
        return self.getFileContent(self._login_dictionnary)

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

    def get_proxy(self):
        return self._proxy

    def set_proxy(self, value = None):
        try:
            tmp = value.split("|")
            if tmp[0] == "http" or tmp[0] == "https":
                self._proxy = {tmp[0] : tmp[1] + ":" + tmp[2]}
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


    def printMessage(self, message, level, type=None):
        
        if level == "r" or (level == "v" and self.verbosity):
            if self.color:
                if type == "info":
                    print(chr(27)+"[0;93m"+message+chr(27)+"[0m")
                elif type == "find":
                    print(chr(27)+"[0;32m"+message+chr(27)+"[0m")
                elif type == "error":
                    print(chr(27)+"[0;31m"+message+chr(27)+"[0m")
                else:
                    print message
            else:
                print message

    def extractFileDefaultPassword(self, filename):
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
                    fav = content[line].rstrip().replace("#favicon:", "").split(";")
                    #print content[line]
                    if re.match("#hash:", content[line+1]):
                        has = content[line+1].rstrip().replace("#hash:", "").split(";")
                        if re.match("#keywords:", content[line+2]):
                            key = content[line+2].rstrip().replace("#keywords:", "").split(";")
                            while content[line+3] != "\n":
                                pas.append(content[line+3].rstrip())
                                line += 1
                                if line+3 >= size:
                                    break;
                        else:
                            raise
                    else:
                        raise
                else:
                    raise
                arr.append([fav,has,key,pas])
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

    def isFaviconPass(self, favicon):
        for i in self.default_login_pass_dictionary:
            for fav in i[0]:
                if str(fav) == str(favicon):
                    return True
        return False

    def getDefaultLoginPasswordByFavicon(self, favicon):
        for i in self.default_login_pass_dictionary:
            for fav in i[0]:
                if str(fav) == str(favicon):
                    return i[3]
        print "Can't get Default Login Password..."
        sys.exit()

    def getDefaultLoginPasswordByHash(self, hash):
        for i in self.default_login_pass_dictionary:
            for fav in i[0]:
                if str(fav) == str(favicon):
                    return i[3]
        print "Can't get Default Login Password..."
        sys.exit()




   