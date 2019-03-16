import os
import shutil
import logging
from time import sleep
from datetime import datetime
from collections import defaultdict
import json

import stem.process
from stem.control import Controller
from stem import CircStatus, Signal

"""
                                                                    
@@@@@@@   @@@@@@   @@@@@@@         @@@@@@@    @@@@@@    @@@@@@   @@@       
@@@@@@@  @@@@@@@@  @@@@@@@@        @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@       
  @@!    @@!  @@@  @@!  @@@        @@!  @@@  @@!  @@@  @@!  @@@  @@!       
  !@!    !@!  @!@  !@!  @!@        !@!  @!@  !@!  @!@  !@!  @!@  !@!       
  @!!    @!@  !@!  @!@!!@!         @!@@!@!   @!@  !@!  @!@  !@!  @!!       
  !!!    !@!  !!!  !!@!@!          !!@!!!    !@!  !!!  !@!  !!!  !!!       
  !!:    !!:  !!!  !!: :!!         !!:       !!:  !!!  !!:  !!!  !!:       
  :!:    :!:  !:!  :!:  !:!        :!:       :!:  !:!  :!:  !:!   :!:      
   ::    ::::: ::  ::   :::         ::       ::::: ::  ::::: ::   :: ::::  
   :      : :  :    :   : :         :         : :  :    : :  :   : :: : :  
                                                                     
"""

MAX_CIRCUIT_DIRTINESS = '1800'
NUM_CLIENTS = 10
DEFAULT_CIRCUIT_LENGTH = 3

TEST_URLS = ['http://httpbin.org/ip' for i in range(20)]  #DEBUG


class TorClient():
    """represents a running tor process with own socks/control port + a stem.Controller()"""
    
    # eventually this is what we will use to replace TorClientPool.clients dict w/ a list of clients 
    def __init__(self, 
                 socks_port, 
                 control_port, 
                 custom_config = None,
                 circuit_pool = None):   # dict of option:value pairs to add to default config
                     
        self.socks_port = str(socks_port)
        self.control_port = str(control_port)

        self.config = {'SOCKSPort': socks_port, 'ControlPort': control_port, 'DataDirectory': './.tordata' + socks_port, 
                         'CookieAuthentication' : '1',  'MaxCircuitDirtiness': MAX_CIRCUIT_DIRTINESS,
                         'StrictNodes': '1', 'GeoIPExcludeUnknown': '1', 'EnforceDistinctSubnets': '0'}
        
        if custom_config:
            for opt, val in custom_config.items():
                self.config[opt] = val
        
        while True:
            try:
                self.process = stem.process.launch_tor_with_config(config = self.config)
                break;
            except OSError as e: # if attempt to bring it up timed out, try again until success
                print(f"Attempt to create circuits failed with error: {e}. Trying again ...")
                continue;  
                    
        self.controller = Controller.from_port(port = int(self.control_port))
        self.controller.authenticate()
        

    def getCircuits(self):
        """Return list of dicts of info re: circuits/paths for this client"""
        circuits = []
        for circ in sorted(self.controller.get_circuits()):
            if circ.status != CircStatus.BUILT:
                continue
            
            circuit_info = {}
            circuit_info['id'] = circ.id
            circuit_info['purpose'] = circ.purpose
            circuit_info['relays'] = []
            
            for fingerprint, nickname in circ.path:
                relay_info = {}
                relay_info['fingerprint'] = fingerprint
                relay_info['nickname'] = nickname
                #TODO: extract all other fields from desc ...
                desc = self.controller.get_network_status(fingerprint, None)
                #print("DEBUG: " + str(desc))
                relay_info['address'] = desc.address if desc else 'unknown'
                circuit_info['relays'].append(relay_info)
            
            circuits.append(circuit_info)
            
        return circuits


    def getExitIPs(self):
        exit_ips = []
        for circ in sorted(self.controller.get_circuits()):
            if circ.status != CircStatus.BUILT:
                continue
            fingerprint, nickname = circ.path[-1]
            desc = self.controller.get_network_status(fingerprint, None)
            exit_ips.append((circ.id, desc.address))
        return exit_ips


    def getExitFingerprints(self):
        fingerprints = []
        for circ in sorted(self.controller.get_circuits()):
            if circ.status != CircStatus.BUILT:
                continue
            fingerprint, nickname = circ.path[-1]
            fingerprints.append((circ.id, fingerprint))
        return fingerprints
 
 
    def destroy(self):
        """shut down this tor client, remove data directory"""
        try:
            print(f"Destroying Tor process listening on SOCKS port:"
                  f"{self.socks_port}) + removing data directory...")
            data_dir = self.config['DataDirectory']            
            self.controller.close()
            self.process.kill()
            self.process.wait()
            shutil.rmtree(data_dir)

        except:
            print(f"destroy() failed for client @ port {self.socks_port}")
            raise


class TorClientPool():
    
    def __init__(self, 
                 num_tor_clients = NUM_CLIENTS, 
                 start_port = 9050, 
                 tor_config = None):
        
        self.clients = {}   # {'socks_port': TorClient(), ...}
        
        # create list of (source_port, control_port) tuples
        tor_ports = [(str(start_port + i), 
                      str(start_port + num_tor_clients + i)) for i in range(num_tor_clients)]
        
    
        self.spawnClients(tor_ports, tor_config)

    def spawnClients(self, tor_ports, config = None):
            
        print(f"Spawning {len(tor_ports)} tor clients ...")
        start_time = datetime.now()
        
        self.clients = {} 
        successes = 0    
        for p in tor_ports:
            """Create a tor process + controller for each port"""
            socks_port = p[0]
            control_port = p[1]
            self.clients[socks_port] = TorClient(socks_port, control_port, config)
            successes += 1
            print(f"Successfully brought up Tor client # {successes}")

        spawning_time = (datetime.now() - start_time).seconds
        print(f"Spawning completed in {spawning_time} seconds.")

    def updateClientConfigs(self, config_dict):
        for client in self.clients.values():
            for opt, val in config_dict.items():
                client.controller.set_conf(key, value)


    def restartClient(self, socks_port):
        """Destroy the tor client @ socks_port, and create a new one to replace it, with same config"""
        tor_client = self.clients[socks_port]

        if not tor_client:
            print(f"Received invalid SOCKS port: no tor client @ port {socks_port} ...")
            raise ValueError
            
        else:
            # Extract the info we need from old client, then kill it
            config = tor_client.config
            control_port = config['ControlPort']

            tor_client.destroy()
            
            print(f"DEBUG: Creating new tor client with tor_config {str(config)}")
            self.clients[socks_port] = TorClient(socks_port, control_port, config)
            

    def excludeExit(self, exit_fingerprint):
        """given a TorRelay object, adds relay to ExcludeExitNodes in config
           but can still be an entry/middle node"""
        for client in self.clients.values():
            # get the current list of excluded exit nodes for this client
            current = client.controller.get_conf('ExcludeExitNodes')
            if current == '{??}':
                client.controller.set_conf('ExcludeExitNodes', exit_fingerprint)
                continue;
            
            if not exit_fingerprint:
                print("ERROR: Received empty exit fingerprint")
                continue
            elif exit_fingerprint in current:
                print("ERROR: currently using an exit that's already been excluded")
                continue
            else:
                new_exclude_list = current +  ', ' + exit_fingerprint
                print(f"Updating client @ socks port {client.socks_port} with ExcludeExitNodes = {str(new_exclude_list)}")
                client.controller.set_conf('ExcludeExitNodes', new_exclude_list)
            
            if exit_fingerprint in client.getExitFingerprints():
                print(f"Sending NEWNYM signal to client @ port {client.socks_port} ...")
                client.controller.signal(Signal.NEWNYM)
                sleep(client.controller.get_newnym_wait())    

            
    def excludeRelay(self, tor_relay):
        """given a TorRelay object, adds relay to ExcludeNodes in config (implies ExcludeExitNode)"""
        pass
        
    def cleanShutdown(self):
        for client in self.clients.values():
            client.destroy()
