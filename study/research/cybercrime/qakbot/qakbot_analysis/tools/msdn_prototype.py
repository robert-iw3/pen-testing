#!/usr/bin/env python3
"""
@Author: Hugo Caron ( hca443@gmail.com )
@Date: 2022/03/04
"""
import requests
import logging
import sys, argparse
import json
import re
from bs4 import BeautifulSoup

import requests_cache

class MsdnError(Exception):
    pass
class MsdnFnNotFound(MsdnError):
    def __init__(self, fn):
        self.value = fn
    def __str__(self):
        return(f'{self.value} not found')

class MsdnScrapper:
    def __init__(self):
        self.locale = 'en-us'
        self.s = requests_cache.CachedSession('dev_cache')
        #self.s = requests.Session()

    def search(self, query, previous_version = False):
        params = {
            'search': query,
            'locale': self.locale,
            '$filter': "category eq 'Documentation'",
            '$top': 20,
        }

        if previous_version:
            params['dataSource'] = 'previousVersions'

        url = f"https://docs.microsoft.com/api/search"
        req = self.s.get(url, params=params)
        results = req.json()
        return results['results']
        #json.dump(results, sys.stdout, indent=4)
        
    def _parse_result_fn(self, fn, results):
        r = None
        for result in results:
            title_ = result['title'].split(' ')

            # FindResourceW doesn't have the function word
            #if title_[0] == fn and title_[1] == 'function':
            bl = False
            blacklists_uri = ['/cpp/build',]
            for b in blacklists_uri:
                if result['displayUrl']['content'].startswith(b):
                    bl = True
                    break
            if not bl and title_[0] == fn:
                r = result
                logging.debug(f'{result}')
                break
        return r

    def get_function_info(self, fn):
        results = self.search(fn)
        result = self._parse_result_fn(fn, results)
        if not result:
            results = self.search(fn, previous_version = True)
            result = self._parse_result_fn(fn, results)

        if not result: raise MsdnFnNotFound(fn)
        url = result['url']

        req = self.s.get(url)
        soup = BeautifulSoup(req.content, "html.parser")
        syntax = soup.find("code").get_text(strip=True)
        syntax = re.sub('//.*?$', '', syntax) # remove // comment
        syntax = re.sub('[\[].*?[\]]', ''""'', syntax) # remove [in], [out]...
        syntax = re.sub('\s+',' ', syntax) # clean the spaces
       
        # WINAPI/NTSYSAPI... should be replace with the 
        # correct calling convention keyword instead of removed
        blacklists = [ 'NTSYSAPI', 'NET_API_FUNCTION', 'USERENVAPI',
            'NTSYSCALLAPI', 'WINAPI', 'WSAAPI', '__kernel_entry', 
            '_Frees_ptr_opt_', '_In_opt_', '_In_', '_Out_', 'opt_', '__drv_aliasesMem', 
            'CDECL_NON_WVMPURE']

        for word in blacklists:
            syntax = syntax.replace(word, '')

        type_match = {
            'SHFOLDERAPI': 'DWORD',
            'NET_API_STATUS': 'DWORD',
            'LMSTR': 'WCHAR*',
            'NTSYSCALLAPI': 'DWORD',
            'VOID': 'void',
            'LRESULT LRESULT': 'LRESULT' 
        }

        for k,v in type_match.items():
            syntax = re.sub(rf'\b({k})\b', v, syntax)

        table = soup.find(id='requirements').find_next_sibling()
        req = {} 
        for row in table.select('tr'):
            cells = row.findAll('td')
            if len(cells) != 2: continue
            k = cells[0].text.strip().lower().replace(' ', '_')
            v = cells[1].text.strip()
            req[k] = v 

        result = {
            'name': fn,
            'prototype': syntax,
            'typedef': syntax.replace(fn, f'(__stdcall *{fn})')
        }
        result.update(req)
        logging.info(f"{result.get('dll', '<notfound>')} {result['prototype']}")
        return result
        #print(syntax)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()  
    parser.add_argument('function', nargs='+')
    args = parser.parse_args()

    for fn in args.function:
        msdn = MsdnScrapper()
        try:
            syntax = msdn.get_function_info(fn)
            json.dump(syntax, sys.stdout)
            print()
        except MsdnFnNotFound as ex:
            logging.error(ex)
