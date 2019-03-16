import os
import signal
import logging
from datetime import datetime
from time import sleep
import functools
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock, Semaphore
from urllib.error import URLError
import json

import requests
import tldextract
from stem import Signal, StreamStatus
from stem.control import Controller, EventType
from selenium import webdriver
from selenium.common import exceptions as selenium_exceptions


"""
 _                            _    _              
| |_  ___   _ __  __ _   ___ | |_ | |_  ___  _ __ 
| __|/ _ \ | '__|/ _` | / _ \| __|| __|/ _ \| '__|
| |_| (_) || |  | (_| ||  __/| |_ | |_|  __/| |   
 \__|\___/ |_|   \__, | \___| \__| \__|\___||_|   
                 |___/                            
                    .-'   `'.
                   /         \
                   |         ;
                   |         |           ___.--,
          _.._     |0) ~ (0) |    _.---'`__.-( (_.
   __.--'`_.. '.__.\    '--. \_.-' ,.--'`     `""`
  ( ,.--'`   ',__ /./;   ;, '.__.'`    __
  _`) )  .---.__.' / |   |\   \__..--""  "'"--.,_
 `---' .'.''-._.-'`_./  /\ '.  \ _.-~~~````~~~-._`-.__.'
       | |  .' _.-' |  |  \  \  '.               `~---`
        \ \/ .'     \  \   '. '-._)
         \/ /        \  \    `=.__`~-.     DATA
   GIVE  / /\         `) )    / / `"".`\
   , _.-'.'\ \   ME   / /    ( ( UR  / /
    `--~`   ) )    .-'.'      '.'.  | (
           (/`    ( (`   ALL    ) )  '-;
            `      '-;         (-'
"""

DEFAULT_DELAY = 5               # delay between requests for each tor client, in seconds
DEFAULT_TIMEOUT = 30            # http request timeout, in seconds
MAX_FAILED_FETCHES = 2          # tor client is allowed to return failure (timeout, connection error, etc) for N requests per batch, before being replaced 
DEFAULT_UA = 'Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0'
DISABLE_IMAGE_LOADING = True
DISABLE_HTTP_KEEP_ALIVE = True
CONNECTION_RETRIES = 1          # if a connection fails, how many times do we retry?


class TorGetter(ABC):
    def __init__(self,
                 urls,                       # urls to fetch
                 tor_client_pool,            # TorClientPool to route requests through
                 delay = DEFAULT_DELAY,      # num seconds between requests, per client, per domain
                 timeout = DEFAULT_TIMEOUT): # num seconds to wait for fetch() to succeed before timeout

        self.urls = urls
        self.tor_client_pool = tor_client_pool

        self.delay = delay         
        self.timeout = timeout 
        
        # {port: number of times fetch has failed on this port ...}
        self.failed_fetch_count = defaultdict(int)    
        
        # each tor SOCKS port maps to dict: {'domain': Lock(), 'domainB': Lock(), ...}
        # to enforce rate limits per domain per port
        self.locks = {}
        for socks_port in tor_client_pool.clients.keys():
            self.locks[socks_port] = defaultdict(Lock)

        self.num_threads = len(self.tor_client_pool.clients.keys())    # one thread per tor client

        self.generateSessions()


    def domainFromURL(self, url):
        tld = tldextract.extract(url)
        domain = tld.domain + "." + tld.suffix
        return domain

    @abstractmethod
    def fetch(self, url, socks_port): pass

    @abstractmethod
    def newSession(self, socks_port): pass

    @abstractmethod
    def killSession(self, port): pass

    def generateSessions(self):
        self.sessions = {}
        for socks_port in self.tor_client_pool.clients.keys():
            self.newSession(socks_port)

    def replaceSession(self, socks_port):
        self.killSession(socks_port)
        self.sessions[socks_port] = self.newSession(socks_port)

    def killAllSessions(self):
        for socks_port in self.sessions.keys():
            self.killSession(socks_port)
            
    def fetchConcurrent(self, num_to_fetch):
        """fetches num_to_fetch urls from self.urls, """
        if num_to_fetch < 0:
            raise ValueError
        if num_to_fetch == 0 or len(self.urls) == 0:
            return ([],[])
            
        results = []
        errors = []
        
        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:

            # This just endlessly rotates through our SOCKS ports, so that below
            # the calls to fetch() are mapped to each socks port about the same # of times
            def _portGenerator():
                ports = deque(self.sessions.keys())
                while True:
                    p = ports.pop()
                    yield p
                    ports.appendleft(p)
            ports = _portGenerator()   
            
            futures = []
            
            for i in range(min(num_to_fetch, len(self.urls))):
                url = self.urls.pop()
                socks_port = next(ports)
                futures.append(executor.submit(self.fetch, url, socks_port))

            for future in as_completed(futures):
                result = future.result()
                socks_port = result['port']
                #TODO: when we get a result from result['port'], submit
                #      the next fetch() for this port to executor ... this means
                #      that only one fetch() per client is in ThreadPoolExecutor
                #      at any given time., and in case of fatal error requiring
                #      restart of client/session, we can do that here with 
                #      guarantee that no other fetches are in progress on this
                #      port at the same time ... 
                if result['error'] or not result['html']:
                    errors.append(result)
                    self.failed_fetch_count[socks_port] += 1

                else:
                    print(f"GOT: {result['url'].strip()} in {result['time']}"
                          f"seconds, using proxy on port {result['port']}")
                    results.append(result)
                    

                # XXXX: how do we cancel the rest of the futures with this session? 
                #    ... then get new tor circuit + session and resubmit?
                if self.failed_fetch_count[socks_port] >= MAX_FAILED_FETCHES:
                    print(f"Too many failed downloads for client @"
                          f"port {socks_port}. Requesting new Tor circuit ...")
                    if result['exit_fingerprint']:
                        self.tor_client_pool.excludeExit(result['exit_fingerprint'])
                    
                    print("... and starting new HTTP session")
                    self.killSession(socks_port)
                    self.newSession(socks_port)
                    self.failed_fetch_count[socks_port] = 0   # reset counter
                    sleep(self.delay)

                #TODO: this is where we will submit the new task for the port we just got result from
    
        return (results, errors)

    
class RequestsTorGetter(TorGetter):
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
    
    def newSession(self, socks_port):
        proxy_address = 'socks5://127.0.0.1:' + socks_port

        s = requests.Session()
        s.headers.update({'User-Agent': DEFAULT_UA})
        s.proxies = {'http': proxy_address, 'https': proxy_address}
        self.sessions[socks_port] =  s
                              
    def killSession(self, port):
        self.sessions[port].close()
            
    def fetch(self, url, port):
        session = self.sessions[port]
        domain = self.domainFromURL(url)

        tor_controller = self.tor_client_pool.clients[port].controller
        exit_fingerprint = None
        
        # Callback passed to controller.add_event_listener(), which
        # extracts the exit fingerprint used for the get() request
        def _stream_event(controller, event):
            nonlocal exit_fingerprint
            if event.status == StreamStatus.SUCCEEDED and event.circ_id:
                circ = controller.get_circuit(event.circ_id)
                exit_fingerprint = circ.path[-1][0]

        stream_listener = functools.partial(_stream_event, tor_controller)

        with self.locks[port][domain]:      
            try:
                start_time = datetime.now()

                tor_controller.add_event_listener(stream_listener, EventType.STREAM)
                r = session.get(url, timeout = self.timeout)
                
                sleep(self.delay)

                return {'url': url, 
                        'html': r.text, 
                        'time': datetime.now() - start_time, 
                        'port': port,
                        'exit_fingerprint': exit_fingerprint,
                        'error': None}

            except requests.exceptions.RequestException as e:
                print("Request of URL " + url + " failed with exception: " + str(e))

                sleep(self.delay)

                print(f"Request of URL {url} failed over port {port} with "
                      f"connection error: {str(e)}")
                self.failed_fetch_count[port] += 1
                
                return {'url': url, 
                        'html': None, 
                        'time': datetime.now() - start_time, 
                        'port': port,
                        'exit_fingerprint': exit_fingerprint,
                        'error': e} 

            finally:
                tor_controller.remove_event_listener(stream_listener)

    def setTimeout(self, t):
        self.timeout = t



class SeleniumTorGetter(TorGetter):
    """Spawn a horde of headless browsers for sites that 
       require rendering JavaScript... buy lots of RAM :)"""
       
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
    def fetch(self, url, port):        
        
        session = self.sessions[port]
        domain = self.domainFromURL(url)

        tor_controller = self.tor_client_pool.clients[port].controller
        exit_fingerprint = None
        
        # Callback passed to controller.add_event_listener(), which
        # extracts the exit fingerprint used for the get() request
        def _stream_event(controller, event):
            nonlocal exit_fingerprint
            if event.status == StreamStatus.SUCCEEDED and event.circ_id:
                circ = controller.get_circuit(event.circ_id)
                exit_fingerprint = circ.path[-1][0]
                #print(f"DEBUG: port {port} --> StreamStatus: {str(event.status)} /// Exit Fingerprint: {exit_fingerprint}")

        stream_listener = functools.partial(_stream_event, tor_controller)
        
        
        # ensure that only one request is happening per domain over this port
        with self.locks[port][domain]:
            try:
                start_time = datetime.now()

                tor_controller.add_event_listener(stream_listener, EventType.STREAM)
                session.get(url)
                
                sleep(self.delay)           
                
                #TODO: replace with FetchResult() attrs class
                return {'url': url, 
                        'html': session.page_source, 
                        'time': datetime.now() - start_time, 
                        'port': port,
                        'exit_fingerprint': exit_fingerprint,
                        'error': None}

            except (ConnectionError, 
                    ConnectionRefusedError, 
                    URLError,
                    selenium_exceptions.WebDriverException) as e:

                print(f"Request of URL {url} failed over port {port}"
                      f"with connection error: {str(e)}")
                self.failed_fetch_count[port] += 1
                
                return {'url': url, 
                        'html': None, 
                        'time': datetime.now() - start_time, 
                        'port': port,
                        'exit_fingerprint': exit_fingerprint,
                        'error': e} 
            finally:
                tor_controller.remove_event_listener(stream_listener)


    def newSession(self, socks_port):
            print(f"Loading headless Chromium browser using proxy port: {socks_port}")
        
            proxy_address = 'socks5://127.0.0.1:' + socks_port

            #########################################################
            #  config/init headless chrome browser
            #########################################################
            chrome_options = webdriver.ChromeOptions()
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--window-size=1420,1080')
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--proxy-server=%s' % proxy_address)

            if DISABLE_IMAGE_LOADING:
                exper_prefs = {}
                chrome_options.experimental_options["prefs"] = exper_prefs
                exper_prefs["profile.default_content_settings"] = {"images": 2}

            driver = webdriver.Chrome(chrome_options=chrome_options)
            if DISABLE_HTTP_KEEP_ALIVE:
                driver.command_executor.keep_alive = False
            else:
                driver.command_executor.keep_alive = True
                
            driver.set_page_load_timeout(self.timeout)

            self.sessions[socks_port] = driver
            
    def killSession(self, port):
        if self.sessions[port].service.process:
            self.sessions[port].quit()
            

    def setTimeout(self, t):
        """Set the timeout (in seconds) per request, and update configs of all persistent sessions"""
        self.timeout = t
        for s in self.sessions.values():
            s.set_page_load_timeout(self.timeout)


