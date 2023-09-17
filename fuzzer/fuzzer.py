from __future__ import print_function    # (at top of module)

# -------------------------------------------------------------------------------
# fuzzer: a cross-platform and cross-app fuzzer based on Test-Dragon intelligent API 
# 
# Goal: Improving the oracle and fuzzer methods for bombarding the forms and urls with mal-formed input.
#       1. The oracle function is initially for detecting 404 and 503 web errors. 
#           The students need improve the oracle method. 
#       2. The fuzzer function is in three methods: fuzzForm, fuzzGets, fuzzUrls.  
#           The students may improve these or develop other techniques for fuzz testing. 
# 
# Author:      Farn Wang
#
# Created:     5/10/2023
# Copyright:   (c) Farn Wang
# Licence:     <your licence>
# -------------------------------------------------------------------------------

import time
import cv2
import random
import sys
import os.path
import os
import sys
import copy
import numpy as np
'''
from skimage.measure import compare_ssim
import pytesseract
from pytesseract import Output
import threading
'''

if sys.version_info[0] < 3:  # Python 2 and 3:
    #  to execute the file, type in the following command in powershell:
    #  % python CnTaaDPackage.py build_ext --inplace
    import future        # pip install future
    import builtins      # pip install future
    import past          # pip install future
    import six           # pip install six

import json 

addIssueReportExpDict2 = {
    "recordType": 'verdict',
    "verdict": "failure!",
    "component": "network, web server, browser, url",
    "subject": "web server operational error {0}",
    "summary": "web browser {0} on {1}",
    "environment": ['windows'],
    "contents": ["Page not found!"],
    "features": ['404', 'page not found'],
    "diagnosis": "url not processed, could be a user authentication issue",
    "suggestions": "It is better to direct {0} page to the main page with an alert!",
    "severity": "low",
    "priority": 1
}

# The students are expected to implement and improve oracle, fuzzForm, fuzzGets, fuzzUrls. 
class fuzzer: 
    def __init__(self, curAPI, *args): 
        self.API = curAPI 
        self.countStep = 0 

    # After you click to execute fuzzer TBot, Test-Dragon will call this method after analyzing 
    # each screen DOM.  
    # The method is expected to return a test action suggestion, usually as an action index (with test data), 
    # or as a special string for test command.   
    def getTestInput(self): 
        if self.countStep > 3:
            return "exitAlgorithm", "enough!"
        self.countStep += 1 
        # Call test oracle to generate issue report if necessary. 
        self.oracle()  

        # return 'fillForm',  {2: 'Password1234', 1: 'lvo65890@gmail.com', 'submit': 5}
        # Finding a post form to fuzz.
        fms = self.API.stateAna.queryFormDicts() 
        if len(fms) > 0: 
            aff = { }
            for fm in fms: 
                sbi = fm['submitButtons'][0]
                sbi, ff = self.API.testExec.getFormFill(sbi) 
                aff[sbi] = ff 
            ai, ff = self.fuzzForm(aff) # fuzz a randomly chosen form in aff. 
            if ai is not None: 
                return ai, ff 
        
        # See what urls we can fuzz.  
        agets = [ ]  # the candidate get urls to fuzz. 
        urls = [ ] # the candinate ordinary urls to fuzz. 
        laList = self.API.stateAna.queryLegalActionList()
        for ai, a in enumerate(laList): 
            if '_EA@href' in a: 
                if '?' in a['_EA@href']: 
                    agets.append(a['_EA@href'])
                urls.append(a['_EA@href'])

        if len(agets) > 0: 
            fget = self.fuzzGets(agets) # fuzz a randomly chosen get url in agets.  
            if fget is not None: 
                return 'click', fget 
            
        if len(urls) > 0: 
            fUrl = self.fuzzLinks(urls) # fuzz a randomly chosen ordinary url in urls. 
            if fUrl is not None: 
                return 'click', fUrl 

        # If there is nothing to fuzz, try crawling to pages with login or register forms. 
        return "crawl", "action topic [login, register]", "action coverage" 


    # The test oracle
    def oracle(self):
        if self.API.projMan.queryAppType() == 'web': 
            # Now only works for web programs. 
            self.check404() 

    def check404(self, d=None, depth = 0): 
        if depth > 4: 
            return None 
        
        if depth == 0: 
            # You are expected to design and implement your own test oracle that analyzes the dom.
            d = self.API.stateAna.queryDomDict() 

        la = self.API.stateAna.queryLastAction() 
        if type(la) is dict and '_EA@href' in la: 
            browser = self.API.deviceMan.queryBrowserId()
            lastHref = la['_EA@href']
            es = self.API.stateAna.queryDomErrors() 
            for e in es: 
                if '503' in e or 'services unavailable' in e.lower(): 
                    code = '503'
                    contents = e 
                elif '404' in e or 'page not found' in e.lower(): 
                    code = '404'
                    contents = e 
                else: 
                    continue 
                ir = copy.deepcopy(addIssueReportExpDict2) 
                ir["subject"] = ir['subject'].format(code) # "web server operational error {0}",
                ir["summary"] = ir['summary'].format(code, lastHref) # "web browser {0} on {1}",
                ir["environment"].append(browser)
                ir["contents"] = [contents] # ["Page not found!"],
                ir["features"] = [code, contents] # ['404', 'page not found'],
                ir["suggestions"] = ir['suggestions'].format(code) # "It is better to direct {0} page to the main page with an alert!",
                ri = self.API.issueMan.addIssueReport(**ir)


    def fuzzForm(self, ffs): 
        if len(ffs) <= 0: 
            return None, None  
        sbi, ffv = random.choice( list(ffs.items()) )
        ffkeys = ffv.keys() 
        for ffi in ffkeys: 
            if type(ffi) is int:  
                ffv[ffi] = str(ffv[ffi]) + 'XXXXXXXXXXXXXXXXXXXXXX'
        return sbi, ffv
    
    def fuzzGets(self, gs): 
        if len(gs) <= 0: 
            return None, None 
        g = random.choice(gs)
        r = g.replace("?", "????")
        return r

    
    def fuzzLinks(self, lnks): 
        if len(lnks) <= 0: 
            return None, None   
        lnk = random.choice(lnks)
        r = lnk.replace('/', '////////')
        return r

def main():
    pass


if __name__ == '__main__':
    main()
