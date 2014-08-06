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
    import urllib2
    import modules.webRequest
    import modules.htmlAnalyser as htmlAnalyser
    import urlparse
    import sys
    import os
    import re
except ImportError, err:
    raise
    print >>sys.stderr, "[X] Unable to import : %s\n" % err
    sys.exit(1)


class mySpider():

    instances = []

    #def __init__(self, objReq, objHtml, depth, extensions_not_to_scan, limit_request_p_page, no_stop_after_callback=False, display=False, verbosity=True):
    def __init__(self, objReq, domain, url, objHtml, depth, extensions_not_to_scan, limit_request_p_page, no_stop_after_callback=False, display=False, verbosity=True):
        self.objReq = objReq
        self.domain = domain
        self.url = url
        self.objHtml = objHtml
        #self.links_tested = [objReq.domain]
        #self.links = [objReq.domain]
        self.verbosity = verbosity
        self.login_form_link_tab = []
        self.no_stop_at_first = no_stop_after_callback
        self.extensions_not_to_scan = extensions_not_to_scan
        self.processed = []
        self.depth = depth
        self.limit_request_p_page = limit_request_p_page
        mySpider.instances.append(self)

    def crawl(self, url, callback=None):

        # only do http links
        if self.domain in url:
            if (url.startswith("http://") and (not url in self.processed)):

                self.processed.append(url)
                # make the first request

                flag_response, response = self.objReq.request(url=url)
                if flag_response:
                    #update url and redirection
                    #url = response.url
                    #self.processed.append(url)

                    # find the links
                    content = response.read()
                    #print content
                    if self.verbosity:
                        print "  [+]  " + str(response.code) + " | " + str(mySpider.getDepth(url))  + " | " + str(url)


                    if callback == "LoginForm":
                        if response.code == 401:
                            self.login_form_link = url
                            self.login_form = None
                            self.login_form_link_tab.append([url, 401, None])
                            if not self.no_stop_at_first:
                                return
                        else:
                            #follow redirection
                            url = response.url
                            self.processed.append(url)

                            all_form = htmlAnalyser.get_all_form(content)
                            for form_u in all_form:
                                input_match, form = self.objHtml.is_there_a_login_form(form_u, True)

                                if input_match != []:
                                    self.login_form_link_tab.append([response.url, response.code, form])
                                    self.login_form_link = url
                                    self.login_form = form
                                else:
                                    self.login_form = None
                    #if error while extracting form....
                    try:
                        m = htmlAnalyser.extract_all_links(content)
                    except Exception, e:
                        m = []

                    for href in m:
                        href = href.get('href', None)
                        #print href
                        href = urlparse.urljoin(url, href)
                        #print href + " depth " + str(mySpider.getDepth(href)) + " <= " + self.depth
                        if(int(mySpider.getDepth(href)) <= int(self.depth) and not self.getLimitPerPage(href)):
                            #if stop at first login form found leave the function
                            if(not self.no_stop_at_first and len(self.login_form_link_tab)>0):
                                return
                            else:
                                self.crawl(href, callback)

            else:
                #print "skipping " + url + " not in domain " + self.objReq.domain
                self.processed.append(url)
        else:
            #print "skipping already checked " + url
            self.processed.append(url)

    @staticmethod
    def getDepth(url):
        #take into account parameters
        try:
            tmp = url.split("?")
            return tmp[0].count('/')-2
        except Exception, e:
            return url.count('/')-2


    def getLimitPerPage(self, url):

        page = ""
        count = 0;

        try:
            tmp = url.split("?")
            page = tmp[0]
        except Exception, e:
            page = url

        for request in self.processed:
         #   print "rq " + request
            if str(page) in str(request):
                count+=1
        #print str(count) +" vs " + str(self.limit_request_p_page)

        if count >= self.limit_request_p_page: return True; return False;


'''
        while len(self.links) > 0:

            url = self.links.pop(0)
            #print "pop => " + self.links.pop(0)
            self.links_tested.append(url)
            extension = os.path.splitext(url)[1]
            #print self.links_tested

            if extension not in self.extensions_not_to_scan:

                flag_response, response = self.objReq.request(url=url)
                if flag_response:
                    content = response.read()
                    url = response.url

                    if self.verbosity:
                        print "  [+]  " + str(response.code) + " | " + str(url)

                    if callback == "LoginForm":

                        if response.code == 401:
                            self.login_form_link = url
                            self.login_form = None
                            self.login_form_link_tab.append([url, 401, None])
                            if not self.no_stop_at_first:
                                return
                        else:
                            all_form = htmlAnalyser.get_all_form(content)
                            for form_u in all_form:
                                input_match, form = self.objHtml.is_there_a_login_form(form_u, True)

                                if input_match != []:
                                    self.login_form_link_tab.append([url, response.code, form])
                                    self.login_form_link = url
                                    self.login_form = form
                                    if not self.no_stop_at_first:
                                        return
                                else:
                                    self.login_form = None





                tags = htmlAnalyser.extract_all_links(content)
                print tags

                for tag in tags:
                    tag = tag[0]

                    tag = urlparse.urljoin(url, tag)

                    print tag
                    if self.objReq.domain in tag:
                        if tag not in self.links_tested and tag not in self.links:
                            #print tag
                            self.links.append(tag)
'''