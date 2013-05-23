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
    import cookielib 
    import lxml.html as XML
    import urlparse
    import urllib
    import base64
    import socket
    import time

except ImportError, err:
    raise
    print >>sys.stderr, "[X] Unable to import : %s\n" % err
    sys.exit(1)

#
class MyHTTPRedirectHandler(urllib2.HTTPRedirectHandler):

    permanent_redirection = []

    def http_error_302(self, req, fp, code, msg, headers):
        # print req.__dict__
        return urllib2.HTTPRedirectHandler.http_error_302(self, req, fp, code, msg, headers)

    def http_error_301(self, req, fp, code, msg, headers):
        MyHTTPRedirectHandler.permanent_redirection.append(req.__dict__["_Request__original"])
        return urllib2.HTTPRedirectHandler.http_error_301(self, req, fp, code, msg, headers)

    #behave on 30x errors
    http_error_303 = http_error_307 = http_error_302

class webRequest:
    all_url = []
    
    def __init__(self, domain, UA, method="GET", headers={}, proxy=None, timeout=None, cookie_redirection=False):
        
        self.url = ""
        self.domain = domain
        self.method = method
        self.headers = headers
        self.UA = UA
        self.headers['User-Agent'] = UA
        self.proxy = proxy
        self.timeout = float(timeout)
        self.cookie = cookielib.CookieJar()
        self.cookie_redirection = cookie_redirection

    def get_domain(self):
        return self._domain

    def set_domain(self, domain):
        tab = urlparse.urlparse(domain)
        self._url = tab[2] + "?" + tab[4]
        self._domain = tab[0] + "://" + tab[1]
               

    domain = property(get_domain, set_domain)

    def request(self, url="", method="GET", data="", cookie=""):

        if not url:
            url = self.url

        if not method:
            method = self.method

        craft_url = urlparse.urljoin(self.domain, url)

        #print "\n" + craft_url + "\n"
        # if(self.domain.endswith('/') and url.startswith('/')):
        #     craft_url = self.domain[:1] + url
        # elif(not self.domain.endswith('/') and not url.startswith('/')):
        #     craft_url = self.domain + "/" + url
        # else:
        #     craft_url = self.domain + url
        
        #record all url for a domain
        self.all_url.append(craft_url)

        try:
            if(method.upper()=="GET"):
                #print "[*] Url : " + craft_url + " => GET"
                req = urllib2.Request(craft_url, None, self.headers)
            elif(method.upper()=="POST"):
                if data:
                    data = urllib.urlencode(data)
                else:
                    return False
                req = urllib2.Request(craft_url, data, self.headers)

            #print self.cookie
            
            # if redirect cookie True
            if self.cookie_redirection:
                self.cookie.add_cookie_header(req)

            cj = cookielib.CookieJar()

            cookieHandler = urllib2.HTTPCookieProcessor(cj)
        
            if self.proxy:
                opener = urllib2.build_opener(MyHTTPRedirectHandler, cookieHandler, urllib2.ProxyHandler(self.proxy))
            else:
                opener = urllib2.build_opener(MyHTTPRedirectHandler, cookieHandler)
            
            #set timeout
            socket.setdefaulttimeout(self.timeout)

            opener.addheaders = []

            response = opener.open(req)
            #print response.url
            self.cookie = cj
            #print data
            #print cj

            return True, response

        except urllib2.URLError as e:
            if hasattr(e, 'code'):
                #print " [] The server returned : ", e.code
                return True, e
            elif hasattr(e, 'reason'):
                #print " [] The server is unreachable : ", e.reason
                return False, e.reason              
            else:
                return False, None
        except socket.timeout, e:
            return False, str(e)
        except Exception, e:
            return False, str(e)

    '''
    @staticmethod
    def request(domain, url, method="GET", data="", cookie=""):

        craft_url = urlparse.urljoin(domain, url)

        try:
            if(method.upper()=="GET"):
                #print "[*] Url : " + craft_url + " => GET"
                req = urllib2.Request(craft_url, None, self.headers)
            elif(method.upper()=="POST"):
                if data:
                    data = urllib.urlencode(data)
                else:
                    return False
                req = urllib2.Request(craft_url, data, self.headers)

            #if you want to redirect cookies...
            cj = cookielib.CookieJar()
            cookieHandler = urllib2.HTTPCookieProcessor(cj)
        
            if self.proxy:
                opener = urllib2.build_opener(MyHTTPRedirectHandler, cookieHandler, urllib2.ProxyHandler(self.proxy))
            else:
                opener = urllib2.build_opener(MyHTTPRedirectHandler, cookieHandler)
            response = opener.open(req)
            print cj
            return True, response

        except urllib2.URLError as e:
            if hasattr(e, 'code'):
                #print " [] The server returned : ", e.code
                return True, e
            elif hasattr(e, 'reason'):
                #print " [] The server is unreachable : ", e.reason
                return False, e.reason              
            else:
                return False, None
        '''                    

    def createUrlAbsoluteRelative(self, url):
        return urlparse.urljoin(self.domain, url)

    def getFavicon(self, html_response=False, url="favicon.ico"):

        #first approach : search through html response
        if not html_response:
            flag_response, response = self.request()
        else:
            response = html_response
            flag_response = True


        if not flag_response:
            print "[] Url Error : ", response
        else:
            if not html_response:
                html_response = response.read()
            #can't find a way to sensitive case :/
            icon_path = XML.fromstring(html_response).xpath('//link[@rel="icon" or @rel="ICON" or @rel="shortcut icon" or @rel="SHORTCUT ICON"]/@href')
            if icon_path:
                print "  [] Favicon found : " + icon_path[0]
                return self.request(url=icon_path[0])
            else:
                print "  [] No Favicon within the html response"
        
        #second approach : guess favicon path
        url_test = urlparse.urljoin(self.domain + self.url, url)
        flag_response, response = self.request(url=url_test) 
        
        if flag_response:
            print "  [] Favicon found at : " + url_test
            return True, response
        else:
            return False, None
        
        '''
        #print response
        #there is a real favicon ?
        try:
            content = response.read()
            #print content
        except:
            pass

        if response and not "<html" in content:
            print content
            return content
        
        else:
            print "Is it a real favicon ?"        

        '''

    @staticmethod
    def base64stringAuth(username, password):
        base64string = base64.encodestring('%s:%s' % (username, password)).replace('\n', '')
        authheader =  "Basic %s" % base64string
        return authheader

    def getUrl(self):
        return self.url

    def getDomain(self):
        return self.domain

    def checkHTTPResponse(handler):
        pass