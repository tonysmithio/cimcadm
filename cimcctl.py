#!/usr/bin/env python3

import argparse
import yaml
import json
import time
import requests
import urllib.error
import logging
import imcsdk
from threading import Thread
from imcsdk.imcexception import ImcException
from imcsdk.imchandle import ImcHandle
from imcsdk.apis.server.inventory import inventory_get
from imcsdk.apis.server.health import faults_get

logging.basicConfig(format='%(levelname)s | %(asctime)s | %(message)s', level=logging.DEBUG, datefmt='%d-%b-%Y %H:%M:%S')

parser = argparse.ArgumentParser()
parser.add_argument('-c', '--config', help='config file in yaml format', required=True)
parser.add_argument('--test_login', help='Test CIMC login', action='store_true')
parser.add_argument('--get_inv', help='Get Inventory of Chassis', nargs='+', choices=['all','disks','cpu','pci','psu','storage'])
parser.add_argument('--get_faults',help='Get Faults of Chassis', action='store_true')
args = parser.parse_args()

with open(args.config, 'r') as configFile:
        data = yaml.load(configFile, Loader=yaml.FullLoader)


svr_count = len(data['svrs'])


def login_test(ip,user,password):
        try:
            handle = ImcHandle(ip,user,password)
            handle.login()
            logging.debug('cimc_ip: '+handle._ImcSession__ip+' | Connection Successful.')
            handle.logout()
        except urllib.error.URLError as e1:
            logging.error('cimc_ip: '+handle._ImcSession__ip+' | Connection Failure.')
        except imcsdk.imcexception.ImcException as e2:
            logging.error('cimc_ip: '+handle._ImcSession__ip+' | Authentication Failure.')


def grab_faults(ip,user,password):
        try:
            handle = ImcHandle(ip,user,password)
            handle.login()
            faults = faults_get(handle=handle)
            if len(faults) == 0:
              logging.info(handle._ImcSession__ip+': No Faults!')
            elif len(faults) > 0:
               for f in faults:
                   faults_dict = {}
                   for key,value in f.__dict__.items():
                      faults_dict.update({key: value})
                   logging.error('cimc_ip: '+handle._ImcSession__ip+' | '+faults_dict['descr'])
            handle.logout()
        except urllib.error.URLError as e1:
            logging.error('cimc_ip: '+handle._ImcSession__ip+' | Connection Failure.')
        except imcsdk.imcexception.ImcException as e2:
            logging.error('cimc_ip: '+handle._ImcSession__ip+' | Authentication Failure.')



def grab_inventory(ip,user,password):
        try:
           handle = ImcHandle(ip,user,password)
           handle.login()
           inv = inventory_get(handle=handle, component=args.get_inv)
           inv_yaml = yaml.dump(inv, sort_keys=False)
           handle.logout()
           logging.info(inv_yaml)
        except urllib.error.URLError as e1:
            logging.error('cimc_ip: '+handle._ImcSession__ip+' | Connection Failure.')
        except imcsdk.imcexception.ImcException as e2:
            logging.error('cimc_ip: '+handle._ImcSession__ip+' | Authentication Failure.')

        

def main():
    handle=ImcHandle('10.3.1.101','admin','GDTlabs@123!')
    handle.login()
    mgmtif = handle.query_dn('sys/rack-unit-1/mgmt/if-1')
    mgmtif.hostname='test-svr-01'
    handle.set_mo(mgmtif)
    handle.logout()

    


    if args.test_login:
        threads = []
        for z in range(0,svr_count):
            thread = Thread(target=login_test, args=(data['svrs'][z]['cimc_ip'],data['cimc_user'],data['cimc_passwd']))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()
            
    if args.get_inv:
        threads = []
        for z in range(0,svr_count):
            thread = Thread(target=grab_inventory, args=(data['svrs'][z]['cimc_ip'],data['cimc_user'],data['cimc_passwd']))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()

    if args.get_faults:
        threads = []
        for z in range(0,svr_count):
            thread = Thread(target=grab_faults, args=(data['svrs'][z]['cimc_ip'],data['cimc_user'],data['cimc_passwd']))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()


if __name__ == "__main__":
    main()
