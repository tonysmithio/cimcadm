#!/usr/bin/env python3

import argparse
import yaml
import json
import time
import requests
import urllib.error
import logging
import imcsdk
import colorlog
from threading import Thread
from imcsdk.imcexception import ImcException
from imcsdk.imchandle import ImcHandle
from imcsdk.apis.server.inventory import inventory_get
from imcsdk.apis.server.health import faults_get

loginLogger = colorlog.getLogger('login_logger')
loginLogger.setLevel(logging.INFO)
loginConsole = colorlog.StreamHandler()
loginConsole.setLevel(logging.INFO)
loginFormat = colorlog.ColoredFormatter('%(log_color)s %(message)s', datefmt='%d-%b-%Y %H:%M:%S')
loginConsole.setFormatter(loginFormat)
loginLogger.addHandler(loginConsole)

faultLogger = colorlog.getLogger('faults_logger')
faultLogger.setLevel(logging.INFO)
faultConsole = colorlog.StreamHandler()
faultConsole.setLevel(logging.INFO)
faultFormat = colorlog.ColoredFormatter('%(log_color)s %(asctime)s | %(message)s', datefmt='%d-%b-%Y %H:%M:%S')
faultConsole.setFormatter(faultFormat)
faultLogger.addHandler(faultConsole)

invLogger = colorlog.getLogger('inv_logger')
invLogger.setLevel(logging.INFO)
invConsole = colorlog.StreamHandler()
invConsole.setLevel(logging.INFO)
invFormat = colorlog.ColoredFormatter('%(log_color)s %(asctime)s | %(message)s', datefmt='%d-%b-%Y %H:%M:%S')
invConsole.setFormatter(invFormat)
invLogger.addHandler(invConsole)

attLogger = colorlog.getLogger('att_logger')
attLogger.setLevel(logging.INFO)
attConsole = colorlog.StreamHandler()
attConsole.setLevel(logging.INFO)
attFormat = colorlog.ColoredFormatter('%(log_color)s %(asctime)s | %(message)s', datefmt='%d-%b-%Y %H:%M:%S')
attConsole.setFormatter(attFormat)
attLogger.addHandler(attConsole)

parser = argparse.ArgumentParser()
parser.add_argument('-c', '--config', help='config file in yaml format', required=True)
parser.add_argument('--test_login', help='Test CIMC login', action='store_true')
parser.add_argument('--get_inv', help='Get Inventory of Chassis', nargs='+', choices=['all','disks','cpu','pci','psu','storage'])
parser.add_argument('--get_faults',help='Get Faults of Chassis', action='store_true')
parser.add_argument('--set_name',help='CIMC Hostname', action='store_true')

args = parser.parse_args()

with open(args.config, 'r') as configFile:
        data = yaml.load(configFile, Loader=yaml.FullLoader)


svr_count = len(data['svrs'])


def login_test(ip,user,password):
        try:
            handle = ImcHandle(ip,user,password)
            handle.login()
            loginLogger.info('cimc-ip: '+handle._ImcSession__ip+' | Login Successful.')
            handle.logout()
        except urllib.error.URLError as e1:
            loginLogger.error('cimc-ip: '+handle._ImcSession__ip+' | Connection Failure.')
        except imcsdk.imcexception.ImcException as e2:
            loginLogger.error('cimc-ip: '+handle._ImcSession__ip+' | Authentication Failure.')


def grab_faults(ip,user,password):
        
        try:
            handle = ImcHandle(ip,user,password)
            handle.login()
            faults = faults_get(handle=handle)
            if len(faults) == 0:
                faultLogger.info('cimc-ip: '+handle._ImcSession__ip+' | No Faults!')
            elif len(faults) > 0:
               for f in faults:
                   faults_dict = {}
                   for key,value in f.__dict__.items():
                      faults_dict.update({key: value})
                   faultLogger.critical('cimc-ip: '+handle._ImcSession__ip+' | '+faults_dict['descr'])
            handle.logout()
        except urllib.error.URLError as e1:
            faultLogger.error('cimc-ip: '+handle._ImcSession__ip+' | Connection Failure.')
        except imcsdk.imcexception.ImcException as e2:
            faultLogger.error('cimc-ip: '+handle._ImcSession__ip+' | Authentication Failure.')


def grab_inventory(ip,user,password):
        try:
           handle = ImcHandle(ip,user,password)
           handle.login()
           inv = inventory_get(handle=handle, component=args.get_inv)
           inv_yaml = yaml.dump(inv, sort_keys=False)
           handle.logout()
           invLogger.info(inv_yaml)
        except urllib.error.URLError as e1:
            invLogger.error('cimc-ip: '+handle._ImcSession__ip+' | Connection Failure.')
        except imcsdk.imcexception.ImcException as e2:
            invLogger.error('cimc-ip: '+handle._ImcSession__ip+' | Authentication Failure.')

        
def set_hostname(ip,user,password,name):
    try:
        handle = ImcHandle(ip,user,password)
        handle.login()
        mgmtif = handle.query_dn('sys/rack-unit-1/mgmt/if-1')
        if mgmtif.hostname == name:
            handle.logout()
            attLogger.info('cimc-ip: '+handle._ImcSession__ip+' | cimc-hostname is already set to "'+mgmtif.hostname+'"')
        elif mgmtif.hostname != name:
            mgmtif.hostname = name
            handle.set_mo(mgmtif)
            handle.logout()
            attLogger.warning('cimc-ip: '+handle._ImcSession__ip+'| cimc-hostname has been changed to "'+name+'"')
    except urllib.error.URLError as e1:
        attLogger.error('cimc-ip: '+handle._ImcSession__ip+' | Connection Failure.')
    except imcsdk.imcexception.ImcException as e2:
        attLogger.error('cimc-ip: '+handle._ImcSession__ip+' | Authentication Failure.')


def main():
    

    if args.set_name:
        threads = []
        for z in range(0,svr_count):
            thread = Thread(target=set_hostname, args=(data['svrs'][z]['cimc_ip'],data['cimc_user'],data['cimc_passwd'],data['svrs'][z]['name']))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()

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
