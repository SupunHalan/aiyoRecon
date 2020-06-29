#!/usr/bin/env python
# coding: utf-8
# Sublist3r v1.0
# By Ahmed Aboul-Ela - twitter.com/aboul3la

# modules in standard library
import re
import sys
import os
import argparse
import time
import hashlib
import random
import multiprocessing
import threading
import socket
import json
from collections import Counter

# external modules
from subbrute import subbrute
import dns.resolver
import requests

# Python 2.x and 3.x compatiablity
if sys.version > '3':
    import urllib.parse as urlparse
    import urllib.parse as urllib
else:
    import urlparse
    import urllib

# In case you cannot install some of the required development packages
# there's also an option to disable the SSL warning:
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except:
    pass

# Check if we are running this on windows platform
is_windows = sys.platform.startswith('win')

# Console Colors
if is_windows:
    # Windows deserves coloring too :D
    G = '\033[92m'  # green
    Y = '\033[93m'  # yellow
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'   # white
    try:
        import win_unicode_console , colorama
        win_unicode_console.enable()
        colorama.init()
        #Now the unicode will work ^_^
    except:
        print("[!] Error: Coloring libraries not installed, no coloring will be used [Check the readme]")
        G = Y = B = R = W = G = Y = B = R = W = ''


else:
    G = '\033[92m'  # green
    Y = '\033[93m'  # yellow
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'   # white

def no_color():
    global G, Y, B, R, W
    G = Y = B = R = W = ''


def banner():
    print("""%s
                 ____        _     _ _     _   _____
                / ___| _   _| |__ | (_)___| |_|___ / _ __
                \___ \| | | | '_ \| | / __| __| |_ \| '__|
                 ___) | |_| | |_) | | \__ \ |_ ___) | |
                |____/ \__,_|_.__/|_|_|___/\__|____/|_|%s%s

                # Coded By Ahmed Aboul-Ela - @aboul3la
    """ % (R, W, Y))


def parser_error(errmsg):
    banner()
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    print(R + "Error: " + errmsg + W)
    sys.exit()


def parse_args():
    # parse the arguments
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -d google.com")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-d', '--domain', help="Domain name to enumerate it's subdomains", required=True)
    parser.add_argument('-b', '--bruteforce', help='Enable the subbrute bruteforce module', nargs='?', default=False)
    parser.add_argument('-p', '--ports', help='Scan the found subdomains against specified tcp ports')
    parser.add_argument('-v', '--verbose', help='Enable Verbosity and display results in realtime', nargs='?', default=False)
    parser.add_argument('-t', '--threads', help='Number of threads to use for subbrute bruteforce', type=int, default=30)
    parser.add_argument('-e', '--engines', help='Specify a comma-separated list of search engines')
    parser.add_argument('-o', '--output', help='Save the results to text file')
    parser.add_argument('-n', '--no-color', help='Output without color', default=False, action='store_true')
    return parser.parse_args()


def write_file(filename, subdomains):
    # saving subdomains results to output file
    print("%s[-] Saving results to file: %s%s%s%s" % (Y, W, R, filename, W))
    with open(str(filename), 'wt') as f:
        for subdomain in subdomains:
            f.write(subdomain + os.linesep)


def subdomain_sorting_key(hostname):
    """Sorting key for subdomains

    This sorting key orders subdomains from the top-level domain at the right
    reading left, then moving '^' and 'www' to the top of their group. For
    example, the following list is sorted correctly:

    [
        'example.com',
        'www.example.com',
        'a.example.com',
        'www.a.example.com',
        'b.a.example.com',
        'b.example.com',
        'example.net',
        'www.example.net',
        'a.example.net',
    ]

    """
    parts = hostname.split('.')[::-1]
    if parts[-1] == 'www':
        return parts[:-1], 1
    return parts, 0


class enumratorBase(object):
    def __init__(self, base_url, engine_name, domain, subdomains=None, silent=False, verbose=True):
        subdomains = subdomains or []
        self.domain = urlparse.urlparse(domain).netloc
        self.session = requests.Session()
        self.subdomains = []
        self.timeout = 25
        self.base_url = base_url
        self.engine_name = engine_name
        self.silent = silent
        self.verbose = verbose
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.8',
            'Accept-Encoding': 'gzip',
        }
        self.print_banner()

    def print_(self, text):
        if not self.silent:
            print(text)
        return

    def print_banner(self):
        """ subclass can override this if they want a fancy banner :)"""
        self.print_(G + "[-] Searching now in %s.." % (self.engine_name) + W)
        return

    def send_req(self, query, page_no=1):

        url = self.base_url.format(query=query, page_no=page_no)
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
        except Exception:
            resp = None
        return self.get_response(resp)

    def get_response(self, response):
        if response is None:
            return 0
        return response.text if hasattr(response, "text") else response.content

    def check_max_subdomains(self, count):
        if self.MAX_DOMAINS == 0:
            return False
        return count >= self.MAX_DOMAINS

    def check_max_pages(self, num):
        if self.MAX_PAGES == 0:
            return False
        return num >= self.MAX_PAGES

    # override
    def extract_domains(self, resp):
        """ chlid class should override this function """
        return

    # override
    def check_response_errors(self, resp):
        """ chlid class should override this function
        The function should return True if there are no errors and False otherwise
        """
        return True

    def should_sleep(self):
        """Some enumrators require sleeping to avoid bot detections like Google enumerator"""
        return

    def generate_query(self):
        """ chlid class should override this function """
        return

    def get_page(self, num):
        """ chlid class that user different pagnation counter should override this function """
        return num + 10

    def enumerate(self, altquery=False):
        flag = True
        page_no = 0
        prev_links = []
        retries = 0

        while flag:
            query = self.generate_query()
            count = query.count(self.domain)  # finding the number of subdomains found so far

            # if they we reached the maximum number of subdomains in search query
            # then we should go over the pages
            if self.check_max_subdomains(count):
                page_no = self.get_page(page_no)

            if self.check_max_pages(page_no):  # maximum pages for Google to avoid getting blocked
                return self.subdomains
            resp = self.send_req(query, page_no)

            # check if there is any error occured
            if not self.check_response_errors(resp):
                return self.subdomains
            links = self.extract_domains(resp)

            # if the previous page hyperlinks was the similar to the current one, then maybe we have reached the last page
            if links == prev_links:
                retries += 1
                page_no = self.get_page(page_no)

        # make another retry maybe it isn't the last page
                if retries >= 3:
                    return self.subdomains

            prev_links = links
            self.should_sleep()

        return self.subdomains


class enumratorBaseThreaded(multiprocessing.Process, enumratorBase):
    def __init__(self, base_url, engine_name, domain, subdomains=None, q=None, lock=threading.Lock(), silent=False, verbose=True):
        subdomains = subdomains or []
        enumratorBase.__init__(self, base_url, engine_name, domain, subdomains, silent=silent, verbose=verbose)
        multiprocessing.Process.__init__(self)
        self.lock = lock
        self.q = q
        return

    def run(self):
        domain_list = self.enumerate()
        for domain in domain_list:
            self.q.append(domain)


class GoogleEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = "https://google.com/search?q={query}&btnG=Search&hl=en-US&biw=&bih=&gbv=1&start={page_no}&filter=0"
        self.engine_name = "Google"
        self.MAX_DOMAINS = 11
        self.MAX_PAGES = 200
        super(GoogleEnum, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.q = q
        return

    def extract_domains(self, resp):
        links_list = list()
        link_regx = re.compile('<cite.*?>(.*?)<\/cite>')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                link = re.sub('<span.*>', '', link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        return links_list

    def check_response_errors(self, resp):
        if (type(resp) is str or type(resp) is unicode) and 'Our systems have detected unusual traffic' in resp:
            self.print_(R + "[!] Error: Google probably now is blocking our requests" + W)
            self.print_(R + "[~] Finished now the Google Enumeration ..." + W)
            return False
        return True

    def should_sleep(self):
        time.sleep(5)
        return

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS - 2])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain} -www.{domain}".format(domain=self.domain)
        return query


class YahooEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = "https://search.yahoo.com/search?p={query}&b={page_no}"
        self.engine_name = "Yahoo"
        self.MAX_DOMAINS = 10
        self.MAX_PAGES = 0
        super(YahooEnum, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.q = q
        return

    def extract_domains(self, resp):
        link_regx2 = re.compile('<span class=" fz-.*? fw-m fc-12th wr-bw.*?">(.*?)</span>')
        link_regx = re.compile('<span class="txt"><span class=" cite fw-xl fz-15px">(.*?)</span>')
        links_list = []
        try:
            links = link_regx.findall(resp)
            links2 = link_regx2.findall(resp)
            links_list = links + links2
            for link in links_list:
                link = re.sub("<(\/)?b>", "", link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass

        return links_list

    def should_sleep(self):
        return

    def get_page(self, num):
        return num + 10

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -domain:www.{domain} -domain:{found}'
            found = ' -domain:'.join(self.subdomains[:77])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain}".format(domain=self.domain)
        return query


class AskEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'http://www.ask.com/web?q={query}&page={page_no}&qid=8D6EE6BF52E0C04527E51F64F22C4534&o=0&l=dir&qsrc=998&qo=pagination'
        self.engine_name = "Ask"
        self.MAX_DOMAINS = 11
        self.MAX_PAGES = 0
        enumratorBaseThreaded.__init__(self, base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.q = q
        return

    def extract_domains(self, resp):
        links_list = list()
        link_regx = re.compile('<p class="web-result-url">(.*?)</p>')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass

        return links_list

    def get_page(self, num):
        return num + 1

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain} -www.{domain}".format(domain=self.domain)

        return query


class BingEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://www.bing.com/search?q={query}&go=Submit&first={page_no}'
        self.engine_name = "Bing"
        self.MAX_DOMAINS = 30
        self.MAX_PAGES = 0
        enumratorBaseThreaded.__init__(self, base_url, self.engine_name, domain, subdomains, q=q, silent=silent)
        self.q = q
        self.verbose = verbose
        return

    def extract_domains(self, resp):
        links_list = list()
        link_regx = re.compile('<li class="b_algo"><h2><a href="(.*?)"')
        link_regx2 = re.compile('<div class="b_title"><h2><a href="(.*?)"')
        try:
            links = link_regx.findall(resp)
            links2 = link_regx2.findall(resp)
            links_list = links + links2

            for link in links_list:
                link = re.sub('<(\/)?strong>|<span.*?>|<|>', '', link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass

        return links_list

    def generate_query(self):
        if self.subdomains:
            fmt = 'domain:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "domain:{domain} -www.{domain}".format(domain=self.domain)
        return query


class BaiduEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://www.baidu.com/s?pn={page_no}&wd={query}&oq={query}'
        self.engine_name = "Baidu"
        self.MAX_DOMAINS = 2
        self.MAX_PAGES = 760
        enumratorBaseThreaded.__init__(self, base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.querydomain = self.domain
        self.q = q
        return

    def extract_domains(self, resp):
        links = list()
        found_newdomain = False
        subdomain_list = []
        link_regx = re.compile('<a.*?class="c-showurl".*?>(.*?)</a>')
        try:
            links = link_regx.findall(resp)
            for link in links:
                link = re.sub('<.*?>|>|<|&nbsp;', '', link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain.endswith(self.domain):
                    subdomain_list.append(subdomain)
                    if subdomain not in self.subdomains and subdomain != self.domain:
                        found_newdomain = True
                        if self.verbose:
                            self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                        self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        if not found_newdomain and subdomain_list:
            self.querydomain = self.findsubs(subdomain_list)
        return links

    def findsubs(self, subdomains):
        count = Counter(subdomains)
        subdomain1 = max(count, key=count.get)
        count.pop(subdomain1, "None")
        subdomain2 = max(count, key=count.get) if count else ''
        return (subdomain1, subdomain2)

    def check_response_errors(self, resp):
        return True

    def should_sleep(self):
        time.sleep(random.randint(2, 5))
        return

    def generate_query(self):
        if self.subdomains and self.querydomain != self.domain:
            found = ' -site:'.join(self.querydomain)
            query = "site:{domain} -site:www.{domain} -site:{found} ".format(domain=self.domain, found=found)
        else:
            query = "site:{domain} -site:www.{domain}".format(domain=self.domain)
        return query


class NetcraftEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        self.base_url = 'https://searchdns.netcraft.com/?restriction=site+ends+with&host={domain}'
        self.engine_name = "Netcraft"
        self.lock = threading.Lock()
        super(NetcraftEnum, self).__init__(self.base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.q = q
        return

    def req(self, url, cookies=None):
        cookies = cookies or {}
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout, cookies=cookies)
        except Exception as e:
            self.print_(e)
            resp = None
        return resp
    
    def should_sleep(self):
        time.sleep(random.randint(1, 2))
        return    

    def get_next(self, resp):
        link_regx = re.compile('<a.*?href="(.*?)">Next Page')
        link = link_regx.findall(resp)
        url = 'http://searchdns.netcraft.com' + link[0]
        return url

    def create_cookies(self, cookie):
        cookies = dict()
        cookies_list = cookie[0:cookie.find(';')].split("=")
        cookies[cookies_list[0]] = cookies_list[1]
        # hashlib.sha1 requires utf-8 encoded str
        cookies['netcraft_js_verification_response'] = hashlib.sha1(urllib.unquote(cookies_list[1]).encode('utf-8')).hexdigest()
        return cookies

    def get_cookies(self, headers):
        if 'set-cookie' in headers:
            cookies = self.create_cookies(headers['set-cookie'])
        else:
            cookies = {}
        return cookies

    def enumerate(self):
        start_url = self.base_url.format(domain='example.com')
        resp = self.req(start_url)
        cookies = self.get_cookies(resp.headers)
        url = self.base_url.format(domain=self.domain)
        while True:
            resp = self.get_response(self.req(url, cookies))
            self.extract_domains(resp)
            if 'Next Page' not in resp:
                return self.subdomains
                break
            url = self.get_next(resp)
            self.should_sleep()

    def extract_domains(self, resp):
        links_list = list()
        link_regx = re.compile('<a class="results-table__host" href="(.*?)"')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                subdomain = urlparse.urlparse(link).netloc
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        return links_list


class DNSdumpster(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://dnsdumpster.com/'
        self.live_subdomains = []
        self.engine_name = "DNSdumpster"
        self.threads = 70
        self.lock = threading.BoundedSemaphore(value=self.threads)
        self.q = q
        super(DNSdumpster, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        return

    def check_host(self, host):
        is_valid = False
        Resolver = dns.resolver.Resolver()
        Resolver.nameservers = ['8.8.8.8', '8.8.4.4']
        self.lock.acquire()
        try:
            ip = Resolver.query(host, 'A')[0].to_text()
            if ip:
                if self.verbose:
                    self.print_("%s%s: %s%s" % (R, self.engine_name, W, host))
                is_valid = True
                self.live_subdomains.append(host)
        except:
            pass
        self.lock.release()
        return is_valid

    def req(self, req_method, url, params=None):
        params = params or {}
        headers = dict(self.headers)
        headers['Referer'] = 'https://dnsdumpster.com'
        try:
            if req_method == 'GET':
                resp = self.session.get(url, headers=headers, timeout=self.timeout)
            else:
                resp = self.session.post(url, data=params, headers=headers, timeout=self.timeout)
        except Exception as e:
            self.print_(e)
            resp = None
        return self.get_response(resp)

    def get_csrftoken(self, resp):
        csrf_regex = re.compile('<input type="hidden" name="csrfmiddlewaretoken" value="(.*?)">', re.S)
        token = csrf_regex.findall(resp)[0]
        return token.strip()

    def enumerate(self):
        resp = self.req('GET', self.base_url)
        token = self.get_csrftoken(resp)
        params = {'csrfmiddlewaretoken': token, 'targetip': self.domain}
        post_resp = self.req('POST', self.base_url, params)
        self.extract_domains(post_resp)
        for subdomain in self.subdomains:
            t = threading.Thread(target=self.check_host, args=(subdomain,))
            t.start()
            t.join()
        return self.live_subdomains

    def extract_domains(self, resp):
        tbl_regex = re.compile('<a name="hostanchor"><\/a>Host Records.*?<table.*?>(.*?)</table>', re.S)
        link_regex = re.compile('<td class="col-md-4">(.*?)<br>', re.S)
        links = []
        try:
            results_tbl = tbl_regex.findall(resp)[0]
        except IndexError:
            results_tbl = ''
        links_list = link_regex.findall(results_tbl)
        links = list(set(links_list))
        for link in links:
            subdomain = link.strip()
            if not subdomain.endswith(self.domain):
                continue
            if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                self.subdomains.append(subdomain.strip())
        return links


class Virustotal(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://www.virustotal.com/ui/domains/{domain}/subdomains'
        self.engine_name = "Virustotal"
        self.lock = threading.Lock()
        self.q = q
        super(Virustotal, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.url = self.base_url.format(domain=self.domain)
        return

    # the main send_req need to be rewritten
    def send_req(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
        except Exception as e:
            self.print_(e)
            resp = None

        return self.get_response(resp)

    # once the send_req is rewritten we don't need to call this function, the stock one should be ok
    def enumerate(self):
        while self.url != '':
            resp = self.send_req(self.url)
            resp = json.loads(resp)
            if 'error' in resp:
                self.print_(R + "[!] Error: Virustotal probably now is blocking our requests" + W)
                break
            if 'links' in resp and 'next' in resp['links']:
                self.url = resp['links']['next']
            else:
                self.url = ''
            self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        #resp is already parsed as json
        try:
            for i in resp['data']:
                if i['type'] == 'domain':
                    subdomain = i['id']
                    if not subdomain.endswith(self.domain):
                        continue
                    if subdomain not in self.subdomains and subdomain != self.domain:
                        if self.verbose:
                            self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                        self.subdomains.append(subdomain.strip())
        except Exception:
            pass


class ThreatCrowd(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}'
        self.engine_name = "ThreatCrowd"
        self.lock = threading.Lock()
        self.q = q
        super(ThreatCrowd, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        return

    def req(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
        except Exception:
            resp = None

        return self.get_response(resp)

    def enumerate(self):
        url = self.base_url.format(domain=self.domain)
        resp = self.req(url)
        self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        try:
            links = json.loads(resp)['subdomains']
            for link in links:
                subdomain = link.strip()
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            pass


class CrtSearch(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://crt.sh/?q=%25.{domain}'
        self.engine_name = "SSL Certificates"
        self.lock = threading.Lock()
        self.q = q
        super(CrtSearch, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        return

    def req(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
        except Exception:
            resp = None

        return self.get_response(resp)

    def enumerate(self):
        url = self.base_url.format(domain=self.domain)
        resp = self.req(url)
        if resp:
            self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        link_regx = re.compile('<TD>(.*?)</TD>')
        try:
            links = link_regx.findall(resp)
            for link in links:
                link = link.strip()
                subdomains = []
                if '<BR>' in link:
                    subdomains = link.split('<BR>')
                else:
                    subdomains.append(link)

                for subdomain in subdomains:
                    if not subdomain.endswith(self.domain) or '*' in subdomain:
                        continue

                    if '@' in subdomain:
                        subdomain = subdomain[subdomain.find('@')+1:]

                    if subdomain not in self.subdomains and subdomain != self.domain:
                        if self.verbose:
                            self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                        self.subdomains.append(subdomain.strip())
        except Exception as e:
            print(e)
            pass


class PassiveDNS(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://api.sublist3r.com/search.php?domain={domain}'
        self.engine_name = "PassiveDNS"
        self.lock = threading.Lock()
        self.q = q
        super(PassiveDNS, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        return

    def req(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
        except Exception as e:
            resp = None

        return self.get_response(resp)

    def enumerate(self):
        url = self.base_url.format(domain=self.domain)
        resp = self.req(url)
        if not resp:
            return self.subdomains

        self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        try:
            subdomains = json.loads(resp)
            for subdomain in subdomains:
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            pass


class portscan():
    def __init__(self, subdomains, ports):
        self.subdomains = subdomains
        self.ports = ports
        self.threads = 20
        self.lock = threading.BoundedSemaphore(value=self.threads)

    def port_scan(self, host, ports):
        openports = []
        self.lock.acquire()
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((host, int(port)))
                if result == 0:
                    openports.append(port)
                s.close()
            except Exception:
                pass
        self.lock.release()
        if len(openports) > 0:
            print("%s%s%s - %sFound open ports:%s %s%s%s" % (G, host, W, R, W, Y, ', '.join(openports), W))

    def run(self):
        for subdomain in self.subdomains:
            t = threading.Thread(target=self.port_scan, args=(subdomain, self.ports))
            t.start()


def main(domain, threads, savefile, ports, silent, verbose, enable_bruteforce, engines):
    bruteforce_list = set()
    search_list = set()

    if is_windows:
        subdomains_queue = list()
    else:
        subdomains_queue = multiprocessing.Manager().list()

    # Check Bruteforce Status
    if enable_bruteforce or enable_bruteforce is None:
        enable_bruteforce = True

    # Validate domain
    domain_check = re.compile("^(http|https)?[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$")
    if not domain_check.match(domain):
        if not silent:
            print(R + "Error: Please enter a valid domain" + W)
        return []

    if not domain.startswith('http://') or not domain.startswith('https://'):
        domain = 'http://' + domain

    parsed_domain = urlparse.urlparse(domain)

    if not silent:
        print(B + "[-] Enumerating subdomains now for %s" % parsed_domain.netloc + W)

    if verbose and not silent:
        print(Y + "[-] verbosity is enabled, will show the subdomains results in realtime" + W)

    supported_engines = {'baidu': BaiduEnum,
                         'yahoo': YahooEnum,
                         'google': GoogleEnum,
                         'bing': BingEnum,
                         'ask': AskEnum,
                         'netcraft': NetcraftEnum,
                         'dnsdumpster': DNSdumpster,
                         'virustotal': Virustotal,
                         'threatcrowd': ThreatCrowd,
                         'ssl': CrtSearch,
                         'passivedns': PassiveDNS
                         }

    chosenEnums = []

    if engines is None:
        chosenEnums = [
            BaiduEnum, YahooEnum, GoogleEnum, BingEnum, AskEnum,
            NetcraftEnum, DNSdumpster, Virustotal, ThreatCrowd,
            CrtSearch, PassiveDNS
        ]
    else:
        engines = engines.split(',')
        for engine in engines:
            if engine.lower() in supported_engines:
                chosenEnums.append(supported_engines[engine.lower()])

    # Start the engines enumeration
    enums = [enum(domain, [], q=subdomains_queue, silent=silent, verbose=verbose) for enum in chosenEnums]
    for enum in enums:
        enum.start()
    for enum in enums:
        enum.join()

    subdomains = set(subdomains_queue)
    for subdomain in subdomains:
        search_list.add(subdomain)

    if enable_bruteforce:
        if not silent:
            print(G + "[-] Starting bruteforce module now using subbrute.." + W)
        record_type = False
        path_to_file = os.path.dirname(os.path.realpath(__file__))
        subs = os.path.join(path_to_file, 'subbrute', 'names.txt')
        resolvers = os.path.join(path_to_file, 'subbrute', 'resolvers.txt')
        process_count = threads
        output = False
        json_output = False
        bruteforce_list = subbrute.print_target(parsed_domain.netloc, record_type, subs, resolvers, process_count, output, json_output, search_list, verbose)

    subdomains = search_list.union(bruteforce_list)

    if subdomains:
        subdomains = sorted(subdomains, key=subdomain_sorting_key)

        if savefile:
            write_file(savefile, subdomains)

        if not silent:
            print(Y + "[-] Total Unique Subdomains Found: %s" % len(subdomains) + W)

        if ports:
            if not silent:
                print(G + "[-] Start port scan now for the following ports: %s%s" % (Y, ports) + W)
            ports = ports.split(',')
            pscan = portscan(subdomains, ports)
            pscan.run()

        elif not silent:
            for subdomain in subdomains:
                print(G + subdomain + W)
    return subdomains


def interactive():
    args = parse_args()
    domain = args.domain
    threads = args.threads
    savefile = args.output
    ports = args.ports
    enable_bruteforce = args.bruteforce
    verbose = args.verbose
    engines = args.engines
    if verbose or verbose is None:
        verbose = True
    if args.no_color:
        no_color()
    banner()
    res = main(domain, threads, savefile, ports, silent=False, verbose=verbose, enable_bruteforce=enable_bruteforce, engines=engines)


if __name__ == "__main__":
    interactive()

#!/usr/bin/env python
# -*- coding: utf-8 -*-

from modules import zonetransfer
from modules import header
from modules import resolve
from modules import wildcard
from modules import save_report
from modules import virustotal_subdomains

from urlparse import urlparse

import sys
import json
import os.path
import datetime
import argparse

__author__='Gianni \'guelfoweb\' Amato'
__version__='4.1.1'
__url__='https://github.com/guelfoweb/knock'
__description__='''\
___________________________________________

knock subdomain scan
knockpy v.'''+__version__+'''
Author: '''+__author__+'''
Github: '''+__url__+'''
___________________________________________
'''
__epilog__='''
example:
  knockpy domain.com
  knockpy domain.com -w wordlist.txt
  knockpy -r domain.com or IP
  knockpy -c domain.com
  knockpy -j domain.com

For virustotal subdomains support you can setting your API KEY in the
config.json file.
 
'''

def loadfile_wordlist(filename):
    filename = open(filename,'r')
    wlist = filename.read().split('\n')
    filename.close
    return filter(None, wlist)

def print_header():
    print """
  _  __                 _                
 | |/ /                | |   """+__version__+"""            
 | ' / _ __   ___   ___| | ___ __  _   _ 
 |  < | '_ \ / _ \ / __| |/ / '_ \| | | |
 | . \| | | | (_) | (__|   <| |_) | |_| |
 |_|\_\_| |_|\___/ \___|_|\_\ .__/ \__, |
                            | |     __/ |
                            |_|    |___/ 
"""

def print_header_scan():
    print '\nIp Address\tStatus\tType\tDomain Name\t\t\tServer'
    print '----------\t------\t----\t-----------\t\t\t------'

def get_tab(string):
        if len(str(string)) > 23:
            return '\t'
        elif len(str(string)) > 15 and len(str(string)) <= 23:
            return '\t\t'
        else:
            return '\t\t\t'

subdomain_csv_list = []
def print_output(data):
    if data['alias']:
        
        for alias in data['alias']:
            ip_alias = data['ipaddress'][0]
            try:
                server_type = str(data['http_response']['http_headers']['server'])
            except:
                server_type = ''

            row = ip_alias+'\t'+str(data['status'])+'\t'+'alias'+'\t'+str(alias)+get_tab(alias)+str(server_type)
            print (row)
            subdomain_csv_list.append(ip_alias+','+str(data['status'])+','+'alias'+','+str(alias)+','+str(server_type))
        
        for ip in data['ipaddress']:
            try:
                server_type = str(data['http_response']['http_headers']['server'])
            except:
                server_type = ''

            row = ip+'\t'+str(data['status'])+'\t'+'host'+'\t'+str(data['hostname'])+get_tab(data['hostname'])+str(server_type)
            print (row)
            subdomain_csv_list.append(ip+','+str(data['status'])+','+'host'+','+str(data['hostname'])+','+str(server_type))
    else:
        
        for ip in data['ipaddress']:
            try:
                server_type = str(data['http_response']['http_headers']['server'])
            except:
                server_type = ''

            row = ip+'\t'+str(data['status'])+'\t'+'host'+'\t'+str(data['hostname'])+get_tab(data['hostname'])+str(server_type)
            print (row)
            subdomain_csv_list.append(ip+','+str(data['status'])+','+'host'+','+str(data['hostname'])+','+str(server_type))

def init(text, resp=False):
    if resp:
        print(text)
    else:
        print(text),

def main():
    parser = argparse.ArgumentParser(
        version=__version__,
        formatter_class=argparse.RawTextHelpFormatter,
        prog='knockpy',
        description=__description__,
        epilog = __epilog__)

    parser.add_argument('domain', help='target to scan, like domain.com')
    parser.add_argument('-w', help='specific path to wordlist file',
                    nargs=1, dest='wordlist', required=False)
    parser.add_argument('-r', '--resolve', help='resolve single ip or domain name',
                        action='store_true', required=False)
    parser.add_argument('-c', '--csv', help='save output in csv',
                        action='store_true', required=False)
    parser.add_argument('-f', '--csvfields', help='add fields name to the first row of csv output file',
                        action='store_true', required=False)
    parser.add_argument('-j', '--json', help='export full report in JSON',
                        action='store_true', required=False)

                        
    args = parser.parse_args()
    
    target = args.domain
    wlist = args.wordlist
    resolve_host = args.resolve
    save_scan_csv = args.csv
    save_scan_csvfields = args.csvfields
    save_scan_json = args.json

    print_header()

    '''
    start
    '''
    time_start = str(datetime.datetime.now())

    '''
    parse target domain
    '''
    if target.startswith("http") or target.startswith("ftp"):
        parsed_uri = urlparse(target)
        target = '{uri.netloc}'.format(uri=parsed_uri)

    '''
    check for virustotal subdomains
    '''
    init('+ checking for virustotal subdomains:', False)
    subdomain_list = []

    _ROOT = os.path.abspath(os.path.dirname(__file__))
    config_file = os.path.join(_ROOT, '', 'config.json')

    if os.path.isfile(config_file):
        with open(config_file) as data_file:    
            apikey = json.load(data_file)
            try:
                apikey_vt = apikey['virustotal']
                if apikey_vt != '':
                    virustotal_list = virustotal_subdomains.get_subdomains(target, apikey_vt)
                    if virustotal_list:
                        init('YES', True)
                        print(json.dumps(virustotal_list, indent=4, separators=(',', ': ')))
                        for item in virustotal_list:
                            subdomain = item.replace('.'+target, '')
                            if subdomain not in subdomain_list:
                                subdomain_list.append(subdomain)
                    else:
                        init('NO', True)
                else:
                    init('SKIP', True)
                    init('\tVirusTotal API_KEY not found', True)
                    virustotal_list = []
            except:
                init('SKIP', True)
                init('\tVirusTotal API_KEY not found', True)
                virustotal_list = []
    else:
        init('SKIP', True)
        init('\tCONFIG FILE NOT FOUND', True)
        virustotal_list = []

    '''
    check for wildcard
    '''
    init('+ checking for wildcard:', False)
    wildcard_json = json.loads(wildcard.test_wildcard(target))
    if wildcard_json['enabled']:
        init('YES', True)
        print(json.dumps(wildcard_json['detected'], indent=4, separators=(',', ': ')))
    else:
        init('NO', True)

    '''
    check for zonetransfer
    '''
    init('+ checking for zonetransfer:', False)
    zonetransfer_json = json.loads(zonetransfer.zonetransfer(target))
    if zonetransfer_json['enabled']:
        init('YES', True)
        print(json.dumps(zonetransfer_json['list'], indent=4, separators=(',', ': ')))
        for item in zonetransfer_json['list']:
            subdomain = item.replace('.'+target, '')
            if subdomain not in subdomain_list:
                subdomain_list.append(subdomain)
    else:
        init('NO', True)
        
    '''
    optional argument -w WORDLIST
    '''
    if wlist: 
        wordlist = wlist[0]
    else:
        _ROOT = os.path.abspath(os.path.dirname(__file__))
        wordlist = os.path.join(_ROOT, 'wordlist', 'wordlist.txt')
    
    if not os.path.isfile(wordlist): 
        exit('File not found: ' + wordlist)
    
    word_list = loadfile_wordlist(wordlist)
    word_list = [item.lower() for item in word_list]
    subdomain_list = subdomain_list + word_list
    subdomain_list = list(set(subdomain_list))
    subdomain_list = sorted(subdomain_list)
    wordlist_count = len(subdomain_list)
    
    '''
    resolve domain
    '''
    init('+ resolving target:', False)
    response_resolve = json.loads(resolve.resolve(target))
    response_resolve.update({'wildcard': wildcard_json, 'zonetransfer': zonetransfer_json, 'virustotal': virustotal_list})
    response_resolve['ipaddress']
    if response_resolve['hostname']:
        init('YES', True)
    else:
        init('NO', True)
    
    ip_list = []
    try:
        del response_resolve['status']
        for ip in response_resolve['ipaddress']:
            ip_list.append(ip)
    except:
        pass
    
    time_end = str(datetime.datetime.now())
    
    stats = {'time_start': time_start, 'time_end': time_end}

    '''
    optional argument -r RESOLVE DOMAIN
    '''
    if resolve_host: 
        response_resolve = json.dumps(response_resolve, indent=4, separators=(',', ': '))
        print(response_resolve)
        exit()
    
    '''
    scan for subdomain
    '''
    init('- scanning for subdomain...', True)
        
    print_header_scan()

    subdomains_json_list = []

    import sys
    for item in subdomain_list:
        sys.stdout.write("%s\r" % item)
        sys.stdout.flush()
        subdomain_target = item+'.'+target
        subdomain_resolve = json.loads(resolve.resolve(subdomain_target))

        if subdomain_resolve['hostname']:
            try:
                status_code = subdomain_resolve['http_response']['status']['code']
            except:
                status_code = ''

            if wildcard_json['enabled']:
                wildcard_code = wildcard_json['detected']['status_code']
                if str(status_code) != '' and str(wildcard_code) != '' and str(status_code) == str(wildcard_code):
                    try:
                        content_length = str(subdomain_resolve['http_response']['http_headers']['content-length'])
                    except:
                        content_length = ''
                    try:
                        wildcard_content_length = wildcard_json['http_response']['http_headers']['content-length']
                    except:
                        wildcard_content_length = ''
                    '''
                    Experimental:
                    content_length == '0' => This is a work around.
                    '''
                    if content_length == '0' or str(content_length) == str(wildcard_content_length):
                        pass
                    else:
                        print_output(subdomain_resolve)
                        subdomains_json_list.append(subdomain_resolve)
                else:
                    print_output(subdomain_resolve)
                    subdomains_json_list.append(subdomain_resolve)
            else:
                print_output(subdomain_resolve)
                subdomains_json_list.append(subdomain_resolve)      
        sys.stdout.write("%s\r" % ('                               ') )
        sys.stdout.flush()

    subdomain_found = []
    for items in subdomains_json_list:
        try:
            del items['status']
        except:
            pass
        
        if items['hostname'] not in subdomain_found:
            subdomain_found.append(str(items['hostname']))

        for item in items['alias']:
            if item not in subdomain_found:
                subdomain_found.append(str(item))

        for item in items['ipaddress']:
            ip_list.append(str(item))

    ipaddr_list = list(set(ip_list))
    ip_count = len(ipaddr_list)
    subdomain_found = list(set(subdomain_found))
    sub_count = len(subdomain_found)
    
    '''
    optional argument -s SAVE FULL SCAN REPORT
    '''

    stats = {'time_start': time_start, 'time_end': time_end, \
            'sub_count': sub_count, 'ip_count': ip_count, \
            'wordlist': {'filename': wordlist, 'item_count': wordlist_count}, \
            'knockpy': {'version': __version__, 'query': sys.argv, 'url': __url__}}

    try:
        del resolve_host_report['stats']
    except:
        pass

    if not resolve_host:
        if save_scan_csv:
            exit(save_report.export(target, subdomain_csv_list, 'csv'))
        elif save_scan_csvfields:
            exit(save_report.export(target, subdomain_csv_list, 'csv', save_scan_csvfields))
        elif save_scan_json:
            report_json = {'target_response': response_resolve, \
                            'subdomain_response': subdomains_json_list, \
                            'found': {'ipaddress': ipaddr_list, \
                            'subdomain': subdomain_found, \
                            'csv': subdomain_csv_list}, 'info': stats}
            report_json = json.dumps(report_json, indent=4, separators=(',', ': '))
            exit(save_report.export(target, report_json, 'json'))
        else:
            exit()

if __name__ == '__main__':
    main()
