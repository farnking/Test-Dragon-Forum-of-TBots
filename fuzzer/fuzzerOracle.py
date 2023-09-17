from __future__ import print_function    # (at top of module)
import time
import random
import sys
import os
import sys

if sys.version_info[0] < 3:  # Python 2 and 3:

    #  to execute the file, type in the following command in powershell:
    #  % python CnTaaDPackage.py build_ext --inplace
    import future        # pip install future
    import builtins      # pip install future
    import past          # pip install future
    import six           # pip install six

import json 

class oracle: 
    def __init__(self, API): 
        self.__API = API
        
    def makeIssueReportIfNecessary(self):
        if self.__API.projMan.queryAppType() == 'web': 
            self.check404() 

    def check404(self, d=None, depth = 0): 
        if depth > 4: 
            return None 
        
        if depth == 0: 
            d = self.__API.stateAna.queryDomDict() 

        if 'tag' in d: 
            if (type(d['tag']) == str and d['tag'] == 'body')\
            or (type(d['tag']) in (list, tuple) and 'body' in d['tag']): 
                if '_EA@text' in d: 
                    if type(d['_EA@text']) == str: 
                        if '404' in d['_EA@text'] or 'Page not found' in d['_EA@text']:
                            self.__API.issueMan.addIssueReport() 
                            return d['_EA@text']
                    elif type(d['_EA@text']) in (list, tuple): 
                        for txt in d['_EA@text']: 
                            if '404' in txt or 'Page not found' in txt:
                                self.__API.issueMan.addIssueReport() 
                                return txt
                return False 
            
        if 'child' in d: 
            for ci, c in enumerate(d['child']): 
                r = self.check404(c)
                if r == False or type(r) is str: 
                    return r 
        
        return None 

