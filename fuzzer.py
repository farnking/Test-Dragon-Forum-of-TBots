from __future__ import print_function    # (at top of module)
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


# -------------------------------------------------------------------------------
# Name:        ?????1
# Purpose:
#
# Author:      Farn Wang
#
# Created:     08/01/2015
# Copyright:   (c) Farn Wang
# Licence:     <your licence>
# -------------------------------------------------------------------------------

import json 

addIssueReportExpDict = { 
    "recordType": 'verdict', # action, notification, issue, verdict, userInput, comment, ...
    "verdict": "failure!", 
    "component": "what is the module, funciton that the issue is found and concerned.", 
    "subject": "Something funny!  You don't like it.", 
    "summary": "Well, I have no clue!", 
    "environment": ['what is the platform, configuraiton, environment settings, ...', 
        'this is for making sure that repeated observation can be made.'
    ], 
    "contents": ["This is the details!",  "Hope you like it!"], 
    "features": [ "give some feature words of the issue" ], 
    "diagnosis": [ "good test report must suggest the cause."],   
    "suggestions": [ "good test report must give suggestions for remedy."],   
    "severity": "low", 
    "priority": 1
}

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


class fuzzer: 
    def __init__(self, curAPI, *args): 
        self.API = curAPI 
        self.countStep = 0 

    def getTestInput(self): 
        if self.countStep > 5:
            return "exitAlgorithm", "enough!"

        self.makeIssueReportIfNecessary()  
        # return 'fillForm',  {2: 'Password1234', 1: 'lvo65890@gmail.com', 'submit': 5}
        fms = self.API.stateAna.queryFormDicts() 
        if len(fms) > 0: 
            aff = { }
            for fm in fms: 
                sbi = fm['submitButtons'][0]
                sbi, ff = self.API.testExec.getFormFill(sbi) 
                aff[sbi] = ff 
            ai, ff = self.fuzzForm(aff)
            if ai is not None: 
                return ai, ff 
            
        agets = [ ]
        urls = [ ]
        laList = self.API.stateAna.queryLegalActionList()
        for ai, a in enumerate(laList): 
            if '_EA@href' in a: 
                if '?' in a['_EA@href']: 
                    agets.append(a['_EA@href'])
                urls.append(a['_EA@href'])

        if len(agets) > 0: 
            fget = self.fuzzGets(agets)
            if fget is not None: 
                return 'click', fget 
            
        if len(urls) > 0: 
            fUrl = self.fuzzLinks(urls)
            if fUrl is not None: 
                return 'click', fUrl 

        return "crawl", "action topic [login, register]", "action coverage" 


        
    def makeIssueReportIfNecessary(self):
        if self.API.projMan.queryAppType() == 'web': 
            self.check404() 

    def check404(self, d=None, depth = 0): 
        if depth > 4: 
            return None 
        
        if depth == 0: 
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
            return None 
        sbi, ffv = random.choice(ffs.items())
        ffkeys = ffv.keys() 
        for ffi in ffkeys: 
            ffv[ffi] = ffv[ffi] + 'XXXXXXXXXXXXXXXXXXXXXX'
        return sbi, ffv
    
    def fuzzGets(self, gs): 
        if len(gs) <= 0: 
            return None 
        g = random.choice(gs)
        r = g.replace("?", "????")
        return r

    
    def fuzzLinks(self, lnks): 
        if len(lnks) <= 0: 
            return None  
        lnk = random.choice(lnks)
        r = lnk.replace('/', '////////')
        return r

def main():
    pass


if __name__ == '__main__':
    main()
