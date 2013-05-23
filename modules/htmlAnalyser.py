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
    from BeautifulSoup import BeautifulSoup
    import lxml.html as XML
    import sys
    import re
    import difflib
    import collections
except ImportError, err:
    raise
    print >>sys.stderr, "[X] Unable to import : %s\n" % err
    sys.exit(1)

class htmlAnalyser:

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    @staticmethod
    def getAllForm(content):
        soup = BeautifulSoup(str(content))
        all_form = soup.findAll('form')
        soup.close()
        return all_form

    @staticmethod
    def isThereAForm(content):
        all_form = htmlAnalyser.getAllForm(content)
        return len(all_form)

    def isThereALoginForm(self, content, aggressive):
        all_form = htmlAnalyser.getAllForm(content)
        
        if all_form == []:
            return None, False

        for form in all_form:
            input_match = self.grepTypeInput(form)

            if (len(input_match) < 1 and aggressive):
                return self.grepNameInput(form), form
            else:
                return input_match, form
        
    def grepNameInput(self, form):
        soup = BeautifulSoup(str(form))
        for name in self.Form_tags_password_name:
            res = soup.findAll("input", {"name" : name})
            if res:
                return res
        return []

    def grepTypeInput(self, form):
        soup = BeautifulSoup(str(form))
        for name in self.Form_tags_password_type:
            res = soup.findAll("input", {"type" : name})
            if res:
                return res
        return []

    def extractFormInput(self, form, pattern_login, pattern_password):
        
        soup = BeautifulSoup(str(form))

        #find action
        action = form["action"]
        method = form["method"]

        #find password
        #first with type.. easiest way
        for name in self.Form_tags_password_type:
            res_p = soup.find("input", attrs={"type" : re.compile(name)})
            if res_p:
                break;

        #second with key words...
        if not res_p:
            for name in self.Form_tags_password_name:
                res_p = soup.find("input", attrs={"name" : re.compile(name)})
                if res_p:
                    break;
        
        #find login
        #first with type.. easiest way
        for name in self.Form_tags_username_type:
            res_u = soup.find("input", attrs={"type" : re.compile(name)})
            if res_u:
                break;

        #second with key words...
        if not res_u:
            for name in self.Form_tags_username_name:
                res_u = soup.find("input", attrs={"name" : re.compile(name)})
                if res_u:
                    break;

        data = {}
        data[res_u["name"]] = pattern_login
        data[res_p["name"]] = pattern_password

        all_input = soup.findAll("input")
        #print all_input
        for input_n in all_input:
            
            if not re.match(str(res_u), str(input_n)) and not re.match(str(res_p), str(input_n)):
                try:
                    data[input_n["name"]] = input_n["value"]
                except:
                    pass

        return method,action,data,res_p,res_u
        
    @staticmethod
    def getDifferenceBetweenTwoPages(page1, page2):
        s = difflib.SequenceMatcher(None, page1, page2)
        return s.ratio()

    @staticmethod
    def getTitle(page):
        soup = BeautifulSoup(str(page))
        return soup.find('title').renderContents()

    @staticmethod
    def removeHTMLTag(value):
        if isinstance(value, collections.Iterable):
            tmp = []
            for i in value:
                tmp.append(re.sub('<[^<]+?>', '', i))
            return tmp
        else:
            return re.sub('<[^<]+?>', '', value)

    @staticmethod
    def extractDiffFromResponseHTML(request, response):
        tmp = []
        request = request.splitlines(1)
        response = response.splitlines(1)
        diff = difflib.unified_diff(request, response)

        for i in diff:
            if i.startswith("+"): tmp.append(i)

        return tmp

    def amILoggedInGrep(self, arr, username):
        tmp = []
        for i in self.Pattern_logged_in:
            tmp.append(i.replace("#USERNAME", username))
        
        for y in arr:
            for i in tmp:
                if re.search(i, y, re.IGNORECASE):
                    return True
        
        return False

    @staticmethod
    def extractAllLinks(page):
        # soup = BeautifulSoup(str(content))
        # print soup.findAll('a')
        # return soup.findAll('a', href=True)

        #@http://stackoverflow.com/questions/1080411/retrieve-links-from-web-page-using-python-and-beautiful-soup
        links = re.findall(r"<a.*?\s*href=\"(.*?)\".*?>(.*?)</a>", page)
        return links


         
