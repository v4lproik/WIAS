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
    pass
except ImportError, err:
    raise
    print >>sys.stderr, "[X] Unable to import : %s\n" % err
    sys.exit(1)

class faviconDB:

    def __init__(self, favicon_db):
        dic = {}
        for i in favicon_db:
            y = i.split(":")
            dic[y[0]] = y[1]
        self.favicon_db = dic

    def isFaviconInDB(self, favicon):
        if favicon in self.favicon_db:
            return self.favicon_db[favicon]
        else:
            return False








         
