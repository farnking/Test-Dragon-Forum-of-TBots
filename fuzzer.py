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

logDir = "D:\\研一下\\軟體測試與資安檢測\\Project3\\test\\"
# def flog(name, data):
#     f = open(logDir+name+".txt", "w")
#     if type(data) is dict:
#         abstract = {}
#         for k0,v0 in data.items():
#             if type(data[k0]) is dict:
#                 abstract[k0] = {}
#                 for k1,v1 in data[k0].items():
#                     if type(data[k0][k1]) is dict:
#                         abstract[k0][k1] = {}
#                         for k2,v2 in data[k0][k1].items():
#                             abstract[k0][k1][k2] = "..."
#                     else:
#                         abstract[k0][k1] = str(v1)
#             else:
#                 abstract[k0] = str(v0)
#         json.dump(abstract, f, indent=4)
#     else:
#         f.write(str(data))
#     f.close()

# The students are expected to implement and improve oracle, fuzzForm, fuzzGets, fuzzUrls. 
import math
import string
lowercase = list(string.ascii_lowercase)
uppercase = list(string.ascii_uppercase)
digits = list(string.digits)
alphanumeric = lowercase + uppercase + digits
def r_ascii_str(strLen = random.choice(range(10))): # Random ASCII printable characters. Default length randomized in [0, 9].
    retStr = ""
    for i in range(strLen):
        retStr += chr(random.choice(range(32,127))) # ASCII printable character
    return retStr
def r_alphanumeric_str(strLen = random.choice(range(10))): # Random alphanumeric characters. Default length randomized in [0, 9].
    retStr = ""
    for i in range(strLen):
        retStr += random.choice(alphanumeric) # alphanumeric character
    return retStr
def r_number_str(strLen = random.choice(range(10))): # Random numbers. Default length randomized in [0, 9].
    retStr = ""
    for i in range(strLen):
        retStr += random.choice(digits) # number digit
    return retStr
def mutate_str(baseStr): # Mutate a string char-by-char, preserving the "grammar"(specialASCII/uppercase/lowercase/number) of each char.
    baseStr = list(baseStr)
    for i in range(len(baseStr)):
        c = baseStr[i]
        if('a' <= c and c <= 'z'):
            baseStr[i] = random.choice(lowercase)
        elif('A' <= c and c <= 'Z'):
            baseStr[i] = random.choice(uppercase)
        elif('0' <= c and c <= '9'):
            baseStr[i] = random.choice(digits)
    return "".join(baseStr)

class fuzzer: 
    def __init__(self, curAPI, *args): 
        self.API = curAPI 
        self.countStep = 0 
        self.records = "" 
        self.f = open(logDir+"records.txt", "w")
        self.f.close()

    def myLog(self, logStr):
        print("\n"*10+logStr+"\n"*10)
        self.f = open(logDir+"records.txt", "a")
        self.f.write(logStr+"\n")
        self.f.close()
        self.records += logStr+"\n"

    # After you click to execute fuzzer TBot, Test-Dragon will call this method after analyzing 
    # each screen DOM.  
    # The method is expected to return a test action suggestion, usually as an action index (with test data), 
    # or as a special string for test command.   
    def getTestInput(self): 
        if self.countStep >= 100:
            self.myLog("\nEnough!\n")
            return "exitAlgorithm", "enough!"
        # Call test oracle to generate issue report if necessary. 
        ret = self.oracle()
        if ret != "":
            self.myLog("\nErrors:\n\n"+ret)
            return "exitAlgorithm", "error!"

        self.countStep += 1 
        self.myLog(f"\nAction {self.countStep}:")
        choice = random.choice(range(3))

        if choice == 0:
            self.myLog("Click a random url...")
            agets = [ ]  # the candidate get urls to fuzz. 
            urls = [ ] # the candinate ordinary urls to fuzz. 
            laList = self.API.stateAna.queryLegalActionList()
            for ai, a in enumerate(laList): 
                if '_EA@href' in a: 
                    if '?' in a['_EA@href']: 
                        agets.append(a['_EA@href'])
                    urls.append(a['_EA@href'])
            if len(urls) > 0: 
                url = random.choice(urls)
                if url is not None: 
                    self.myLog(f'Click "{url}"')
                    return 'click', url 
                else:
                    self.myLog("Failed.")

        if choice <= 1:
            self.myLog("Finding a post form to fuzz...")
            fms = self.API.stateAna.queryFormDicts() 
            if len(fms) > 0: 
                aff = { }
                for fm in fms: 
                    sbi = fm['submitButtons'][0]
                    sbi, ff = self.API.testExec.getFormFill(sbi) 
                    aff[sbi] = ff 
                ai, ff = self.fuzzForm(aff) # fuzz a randomly chosen form in aff. 
                if ai is not None: 
                    self.myLog(f'Submit form "{ai}":')
                    for k,v in list(ff.items()):
                        self.myLog(f'{k}: "{v}"')
                    return ai, ff 
                else:
                    self.myLog("Failed.")

        self.myLog("See what urls we can fuzz...")
        agets = [ ]  # the candidate get urls to fuzz. 
        urls = [ ] # the candinate ordinary urls to fuzz. 
        laList = self.API.stateAna.queryLegalActionList()
        for ai, a in enumerate(laList): 
            if '_EA@href' in a: 
                if '?' in a['_EA@href']: 
                    agets.append(a['_EA@href'])
                urls.append(a['_EA@href'])
        choice = random.choice(range(2))
        if choice == 0 and len(agets) > 0: 
            self.myLog("Fuzz a randomly chosen get url...")
            fget = self.fuzzGets(agets)
            if fget is not None: 
                self.myLog(f'Click "{fget}"')
                return 'click', fget 
            else:
                self.myLog("Failed.")
        if len(urls) > 0: 
            self.myLog("Fuzz randomly chosen ordinary urls...")
            fUrl = self.fuzzLinks(urls)
            if fUrl is not None: 
                self.myLog(f'Click "{fUrl}"')
                return 'click', fUrl 
            else:
                self.myLog("Failed.")

        # If there is nothing to fuzz, try crawling to pages with login or register forms. 
        self.myLog("There is nothing to fuzz, try crawling to pages with login or register forms.")
        return "crawl", "action topic [login, register]", "action coverage" 

    # The test oracle
    def oracle(self):
        if self.API.projMan.queryAppType() == 'web': 
            # Now only works for web programs. 
            return self.checkErrs() 

    def checkErrs(self, d=None, depth = 0): 
        Errs = ""

        if depth > 4: 
            return None 
        
        if depth == 0: 
            # You are expected to design and implement your own test oracle that analyzes the dom.
            d = self.API.stateAna.queryDomDict() 
            # flog("d",d)

        la = self.API.stateAna.queryLastAction() 
        # flog("la",la)
        if type(la) is dict and '_EA@href' in la: 
            browser = self.API.deviceMan.queryBrowserId()
            lastHref = la['_EA@href']
            es = self.API.stateAna.queryDomErrors() 
            # flog("es",es)
            for e in es: 
                if '503' in e or 'services unavailable' in e.lower(): 
                    code = '503'
                    contents = e 
                elif '404' in e or 'page not found' in e.lower(): 
                    code = '404'
                    contents = e 
                else: # Any error code starts with 4 or 5.
                    code = ''
                    for i in range(400, 600):
                        if str(i) in e:
                            code = str(i)
                            contents = e
                            break
                    if(code == ''):
                        continue
                Errs += f"{code}: {e}\n"
                ir = copy.deepcopy(addIssueReportExpDict2) 
                ir["subject"] = ir['subject'].format(code) # "web server operational error {0}",
                ir["summary"] = ir['summary'].format(code, lastHref) # "web browser {0} on {1}\ntest process records:\n{2}",
                ir["environment"].append(browser)
                ir["contents"] = ["test process records:\n"+self.records]
                ir["features"] = [code, contents] # ['404', 'page not found'],
                ir["suggestions"] = ir['suggestions'].format(code) # "It is better to direct {0} page to the main page with an alert!",
                ri = self.API.issueMan.addIssueReport(**ir)
        return Errs

    def fuzzForm(self, ffs): 
        if len(ffs) <= 0: 
            return None, None  
        sbi, ffv = random.choice(list(ffs.items()))
        ffkeys = list(ffv.keys()) 
        choice = random.choice(range(3))
        for ffi in ffkeys: 
            if choice == 0: # Random ASCII printable characters.
                ffv[ffi] = r_ascii_str()
            elif choice == 1: # Random alphanumeric characters.
                ffv[ffi] = r_alphanumeric_str()
            else: # Random numbers.
                ffv[ffi] = r_number_str()
        return sbi, ffv
    
    def fuzzGets(self, gs): 
        if len(gs) <= 0: 
            return None, None 
        g = random.choice(list(set(gs)))
        self.myLog(f'"{g}"')
        paramPos = g.find('?')
        url = g[:paramPos]
        params = g[paramPos+1:].split('&')
        if "" in params:
            params.remove("")
        if len(params) > 0:
            choice = random.choice(range(4))
            if choice == 0:
                self.myLog("Mutate a random parameter:")
                choice = random.choice(range(len(params)))
                mutate_param = params[choice].split("=", 1)
                if(len(mutate_param) == 2):
                    mutate_param[1] = mutate_str(mutate_param[1])
                    params[choice] = mutate_param[0]+"="+mutate_param[1]
                else:
                    params[choice] = mutate_str(params[choice])
            elif choice == 1:
                self.myLog("Add an illegal parameter:")
                choice = random.choice(range(3))
                if choice == 0 and len(params) > 1: # Insert an illegal parameter at a random position except [0].
                    choice = random.choice(range(1,len(params)))
                    params.insert(choice, r_alphanumeric_str()+"="+r_alphanumeric_str())
                else:
                    choice = random.choice(range(2))
                    if choice == 0: # Insert an illegal parameter as the first.
                        params.insert(0, r_alphanumeric_str()+"="+r_alphanumeric_str())
                    else: # Append an illegal parameter as the last.
                        params.append(r_alphanumeric_str()+"="+r_alphanumeric_str())
            elif choice == 2:
                self.myLog("Remove all parameters:")
                params = []
            else:
                self.myLog("Repeat everything except the main url:")
                choice = random.choice(range(1,10))
                for i in range(choice):
                    params.insert(random.choice(range(len(params))), random.choice(params))
                return url + "?"*random.choice(range(2,10)) + ("&"*random.choice(range(2,10))).join(params)
        else:
            choice = random.choice(range(2))
            if choice == 0:
                self.myLog("Append an illegal parameter:")
                params = [r_alphanumeric_str()+"="+r_alphanumeric_str()]
            else:
                self.myLog('Repeat "?":')
                return url + "?"*random.choice(range(2,10))
        return url+"?"+"&".join(params)

    def fuzzLinks(self, lnks): 
        if len(lnks) <= 0: 
            return None, None   
        choice = random.choice(range(4))
        if choice in range(3): # Fuzz a randomly chosen url.
            lnk = random.choice(list(set(lnks)))
            self.myLog(f'Fuzz a randomly chosen url:\n"{lnk}"')
            lnkStart = lnk.find("://")+3
            protocol = lnk[:lnkStart]
            if protocol in ["http://","https://"]:
                lnk = lnk[lnkStart:]
            else:
                protocol = ""
            if (protocol == "" or choice == 0) and lnk.count("/") > 0: # Fuzz the "/"-s that are parsed by the server under test. (Not the "://" and the "/" right after the server name.)
                self.myLog('Fuzz "/"s:')
                choice = random.choice(range(2))
                if choice == 0 and lnk.count("/") > 1: # change to "\"
                    return protocol+lnk.replace("/", "\\").replace("\\", "/", 1)
                else: # repeat
                    return protocol+lnk.replace("/", "/"*random.choice(range(2,10)))
            elif choice == 1 and protocol != "":
                self.myLog("https <-> http")
                if protocol == "http://":
                    return "https://"+lnk
                else:
                    return "http://"+lnk
            elif protocol != "":
                self.myLog("www.???.??? <-> ???.???")
                if lnk[:4] == "www.":
                    return protocol+lnk[4:]
                else:
                    return protocol+"www."+lnk
            self.myLog("Failed.")
        # else: Jump to a random common prefix.
        lnks = list(set([lnk[:lnk.find("?")] for lnk in lnks]))
        lnks.sort()
        choice = random.choice(range(len(lnks)-1))
        A = lnks[choice]
        B = lnks[choice+1]
        self.myLog(f'"{A}"\n"{B}"')
        A = A.split("/")
        B = B.split("/")
        prefixLen = 0
        while(prefixLen < len(A) and prefixLen < len(B) and A[prefixLen] == B[prefixLen]):
            prefixLen += 1
        if prefixLen > 0:
            url = "/".join(A[:prefixLen])
            if(url not in ["https://","http://"]):
                self.myLog("Jump to common prefix:")
                return url
        return None, None  

def main():
    pass


if __name__ == '__main__':
    main()
