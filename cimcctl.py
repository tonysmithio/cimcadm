#!/usr/bin/env python3

import argparse
import yaml
import json
import time
import requests
import urllib.error
import logging
from imcsdk.imcexception import ImcException
from imcsdk.imchandle import ImcHandle
from imcsdk.apis.server.inventory import inventory_get
from imcsdk.apis.server.health import faults_get

logging.basicConfig(format='%(levelname)s | %(asctime)s | %(message)s', level=logging.WARNING, datefmt='%d-%b-%Y %H:%M:%S')

parser = argparse.ArgumentParser()
parser.add_argument('-c', '--config', help='config file in yaml format', required=True)
parser.add_argument('--test_login', help='Test CIMC login', action='store_true')
parser.add_argument('--get_inv', help='Get Inventory of Chassis', nargs='+', choices=['all','disks','cpu','pci','psu','storage'])
parser.add_argument('--get_faults',help='Get Faults of Chassis', action='store_true')
args = parser.parse_args()

with open(args.config, 'r') as configFile:
        data = yaml.load(configFile, Loader=yaml.FullLoader)

hosts = []

cimc_ips= []

svr_count = len(data['svrs'])

for a in data['svrs']:
    hosts.append(a['name'])

for b in data['svrs']:
    cimc_ips.append(b['cimc_ip'])


def login_test():
    for c in cimc_ips:
        handle = ImcHandle(str(c),str(data['cimc_user']),str(data['cimc_passwd']))
        try:
            handle.login()
            logging.debug('SVR IP: '+handle._ImcSession__ip+' | Connection Successful.')
            handle.logout()
        except urllib.error.URLError:
            logging.error('SVR IP: '+handle._ImcSession__ip+' | Connection Failure.')


def grab_inventory():
    for c in cimc_ips:
        handle = ImcHandle(c,data['cimc_user'],data['cimc_passwd'])
        try:
           handle.login()
           inv = inventory_get(handle=handle, component=args.get_inv)
           inv_yaml = yaml.dump(inv, sort_keys=False)
           handle.logout()
           logging.info(inv_yaml)
        except urllib.error.URLError:
            logging.error('SVR IP: '+handle._ImcSession__ip+' | Connection Failure.')

def grab_faults():
    for c in cimc_ips:
        handle = ImcHandle(c,data['cimc_user'],data['cimc_passwd'])
        try:
            handle.login()
            faults = faults_get(handle=handle)
            if len(faults) == 0:
              logging.info(c+': No Faults!')
            elif len(faults) > 0:
               for f in faults:
                   faults_dict = {}
                   for key,value in f.__dict__.items():
                      faults_dict.update({key: value})
                   logging.error('SVR IP: '+c+' | '+faults_dict['descr'])
            handle.logout()
        except urllib.error.URLError:
            logging.error('SVR IP: '+handle._ImcSession__ip+' | Connection Failure.')
        



def main():

    if args.test_login:
        login_test()
            
    if args.get_inv:
        grab_inventory()

    if args.get_faults:
        grab_faults()

if __name__ == "__main__":
    main()
