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
except ImportError, err:
    raise
    print >>sys.stderr, "[X] Unable to import : %s\n" % err
    sys.exit(1)

class mySpider():

	def __init__(self, objReq, objHtml, display=False):
		self.objReq = objReq
		self.objHtml = objHtml
		self.links_tested = [objReq.domain]
		self.links = [objReq.domain]

	def crawl(self, callback = None):
		
		while len(self.links) > 0:

			flag_response, response = self.objReq.request(url=self.links[0])
			if flag_response:
				content = response.read()
				url = self.links[0]
				self.links.pop(0)

				if callback == "LoginForm":
					all_form = htmlAnalyser.getAllForm(content)
					for form_u in all_form:
						input_match, form = self.objHtml.isThereALoginForm(form_u, True)

						if input_match != []:
							self.login_form_link = url
							self.login_form = form
							return
						else:
							self.login_form = None

				tags = htmlAnalyser.extractAllLinks(content)
				#print tags
				for tag in tags:
					tag = tag[0]

					tag = urlparse.urljoin(self.objReq.domain, tag)
					if self.objReq.domain in tag and tag not in self.links_tested:
						self.links.append(tag)
						self.links_tested.append(tag)

		#print self.links_tested

