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
    def get_all_form(content):
        try:
            soup = BeautifulSoup(str(content))
            all_form = soup.findAll('form')
            soup.close()
            return all_form
        except Exception, e:
            return []



    @staticmethod
    def is_there_a_form(content):
        all_form = htmlAnalyser.get_all_form(content)
        return len(all_form)

    def is_there_a_login_form(self, content, aggressive):

        all_form = htmlAnalyser.get_all_form(content)

        if all_form == []:
            return None, False

        for form in all_form:
            input_match = self.grep_type_input(form)
            #print "input_match => " + str(input_match)
            if (len(input_match) < 1 and aggressive):
                return self.grep_name_input(form), form
            else:
                return input_match, form

        
    def grep_name_input(self, form):
        soup = BeautifulSoup(str(form))
        for name in self.Form_tags_password_name:
            res = soup.findAll("input", {"name" : name})
            if res:
                return res
        return []

    def grep_type_input(self, form):
        soup = BeautifulSoup(str(form))
        for name in self.Form_tags_password_type:
            res = soup.findAll("input", {"type" : name})
            if res:
                return res
        return []

    def extract_form_input(self, form, pattern_login, pattern_password):
        
        soup = BeautifulSoup(str(form))

        #find action
        try:
            action = form["action"]
        except Exception, e:
            action = ""

        #if method doesn't exist, default value is set to "get"
        try:
            method = form["method"]
        except Exception, e:
            method = "get"


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
            #print name
            res_u = soup.find("input", attrs={"type" : re.compile(name)})
            if res_u:
                break;

        #second with key words...
        if not res_u:
            for name in self.Form_tags_username_name:
                res_u = soup.find("input", attrs={"name" : re.compile(name)})
                if res_u:
                    break;


        #if no res_u || no res_p => not form found

        '''
        data = {}
        data[res_u["name"]] = pattern_login
        data[res_p["name"]] = pattern_password

        '''
        data = {}

        try:
            data[res_u["name"]] = pattern_login
            data[res_p["name"]] = pattern_password
        except Exception, e:
            return method,action,data,res_p,res_u


        all_input = soup.findAll("input")
        #print all_input
        for input_n in all_input:

            #if not re.match(str(res_u), str(input_n)) and not re.match(str(res_p), str(input_n)):
            if str(res_u) != str(input_n) and str(res_p) != str(input_n):
                #print "match " + str(res_u) + "!=" + str(input_n) + " AND match " + str(res_p) + "!=" + str(input_n)
                try:
                    data[input_n["name"]] = input_n["value"]
                except:
                    pass
        return method,action,data,res_p,res_u
        
    @staticmethod
    def get_difference_between_two_pages(page1, page2):
        s = difflib.SequenceMatcher(None, page1, page2)
        return s.ratio()

    @staticmethod
    def get_title(page):
        soup = BeautifulSoup(str(page))
        return soup.find('title').renderContents()

    @staticmethod
    def remove_HTML_Tag(value):
        if isinstance(value, collections.Iterable):
            tmp = []
            for i in value:
                tmp.append(re.sub('<[^<]+?>', '', i))
            return tmp
        else:
            return re.sub('<[^<]+?>', '', value)

    @staticmethod
    def extract_diff_from_response_HTML(request, response):
        tmp = []
        request = request.splitlines(1)
        response = response.splitlines(1)
        diff = difflib.unified_diff(request, response)

        for i in diff:
            if i.startswith("+"): tmp.append(i)

        return tmp

    def am_I_logged_In_grep(self, arr, username):
        tmp = []
        for i in self.Pattern_logged_in:
            tmp.append(i.replace("#USERNAME", username))
            
        for y in arr:
            for i in tmp:
                if re.search(i, y, re.IGNORECASE):
                    #print i
                    return i
        
        return False

    @staticmethod
    def extract_all_links(page):
        soup = BeautifulSoup(str(page))
        #return soup.findAll('a')
        #print soup.findAll('a', href=True)
        #print page
        m = re.findall('href="(.*?)"', page)
        #print m
        return soup.findAll('a', href=True)


        #conventional links
        #@http://stackoverflow.com/questions/1080411/retrieve-links-from-web-page-using-python-and-beautiful-soup
        #links = re.findall(r"<a.*?\s*href=\"(.*?)\".*?>(.*?)</a>", page)

        #non-conventional links
        #print page
        #m = re.findall('href="(.*?)"', page)


        #return m

    def am_I_logged_in_is_form_here(self, page1, page2):
        soup1 = BeautifulSoup(str(page1))
        soup2 = BeautifulSoup(str(page2))
        flag1 = True
        flag2 = True
        for name in self.Form_tags_password_type:
            res_p = soup1.find("input", attrs={"type" : re.compile(name)})
            if res_p:
                flag1 = False;
        soup1.close()

        for name in self.Form_tags_password_type:
            res_p = soup2.find("input", attrs={"type" : re.compile(name)})
            if res_p:
                flag2 = False
                break;
        soup2.close()

        if not flag2:
            return False
        else:
            return True