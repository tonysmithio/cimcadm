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
from imcsdk.utils.imcfirmwareinstall import *
from imcsdk.apis.server.storage import *


log_colors_dict = {'INFO':'white','DEBUG':'cyan','WARNING':'bold_yellow','ERROR':'red','CRITICAL':'bold_red'}

eventLogger = colorlog.getLogger('event_logger')
eventLogger.setLevel(logging.INFO)
eventConsole = colorlog.StreamHandler()
eventConsole.setLevel(logging.INFO)
eventFormat = colorlog.ColoredFormatter('%(log_color)s %(asctime)s | %(message)s', datefmt='%d-%b-%Y %H:%M:%S',log_colors=log_colors_dict)
eventConsole.setFormatter(eventFormat)
eventLogger.addHandler(eventConsole)


parser = argparse.ArgumentParser(prog='cimcadm',formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-c', '--config', help='config file in yaml format', required=True)
parser.add_argument('--test-login', help='Test CIMC login', action='store_true')
invOptions=['all','cpu','disks','pci','psu','storage']
parser.add_argument('--get-inv', metavar='', help='Collect and display inventory for one or more components separated by a space.\nList of inventory options: {%(choices)s}', nargs='+', choices=invOptions)
parser.add_argument('--get-faults', help='Get Faults of Chassis', action='store_true')
parser.add_argument('--set-hostname', help='Update CIMC Hostname', action='store_true')
parser.add_argument('--update-firmware', help='Initiate firmware update', action='store_true')
parser.add_argument('--clean-disks', help='Clear boot-drive, remove all virtual disks, and reset all physical disks', action='store_true')

args = parser.parse_args()


with open(args.config, 'r') as configFile:
        data = yaml.load(configFile, Loader=yaml.FullLoader)


svr_count = len(data['svrs'])


def login_test(ip,user,password):
        try:
            handle = ImcHandle(ip,user,password)
            handle.login()
            eventLogger.info('cimc-ip: '+handle._ImcSession__ip+' | Login Successful.')
            handle.logout()
        except urllib.error.URLError as e1:
            eventLogger.error('cimc-ip: '+handle._ImcSession__ip+' | Connection Failure.')
        except imcsdk.imcexception.ImcException as e2:
            eventLogger.error('cimc-ip: '+handle._ImcSession__ip+' | Authentication Failure.')


def grab_faults(ip,user,password): 
        try:
            handle = ImcHandle(ip,user,password)
            handle.login()
            faults = faults_get(handle=handle)
            if len(faults) == 0:
                eventLogger.info('cimc-ip: '+handle._ImcSession__ip+' | No Faults!')
            elif len(faults) > 0:
               for f in faults:
                   faults_dict = {}
                   for key,value in f.__dict__.items():
                      faults_dict.update({key: value})
                   eventLogger.critical('cimc-ip: '+handle._ImcSession__ip+' | '+faults_dict['descr'])
            handle.logout()
        except urllib.error.URLError as e1:
            eventLogger.error('cimc-ip: '+handle._ImcSession__ip+' | Connection Failure.')
        except imcsdk.imcexception.ImcException as e2:
            eventLogger.error('cimc-ip: '+handle._ImcSession__ip+' | Authentication Failure.')


def grab_inventory(ip,user,password):
        try:
           handle = ImcHandle(ip,user,password)
           handle.login()
           inv = inventory_get(handle=handle, component=args.get_inv)
           inv_yaml = yaml.dump(inv, sort_keys=False)
           handle.logout()
           eventLogger.info(inv_yaml)
        except urllib.error.URLError as e1:
            eventLogger.error('cimc-ip: '+handle._ImcSession__ip+' | Connection Failure.')
        except imcsdk.imcexception.ImcException as e2:
            eventLogger.error('cimc-ip: '+handle._ImcSession__ip+' | Authentication Failure.')

        
def set_hostname(ip,user,password,name):
    try:
        handle = ImcHandle(ip,user,password)
        handle.login()
        mgmtif = handle.query_dn('sys/rack-unit-1/mgmt/if-1')
        if mgmtif.hostname == name:
            handle.logout()
            eventLogger.info('cimc-ip: '+handle._ImcSession__ip+' | cimc-hostname is already set to "'+mgmtif.hostname+'"')
        elif mgmtif.hostname != name:
            mgmtif.hostname = name
            handle.set_mo(mgmtif)
            handle.logout()
            eventLogger.warning('cimc-ip: '+handle._ImcSession__ip+' | cimc-hostname has been changed to "'+name+'"')
    except urllib.error.URLError as e1:
        eventLogger.error('cimc-ip: '+handle._ImcSession__ip+' | Connection Failure.')
    except imcsdk.imcexception.ImcException as e2:
        eventLogger.error('cimc-ip: '+handle._ImcSession__ip+' | Authentication Failure.')


def firmwareUpdate(ip,user,password):
    try:
        handle = ImcHandle(ip,user,password)
        handle.login()
        firmware_update(handle=handle, remote_share=data['huu']['iso'], share_type=data['huu']['protocol'], remote_ip=data['huu']['svr'],
                username=data['huu']['user'], password=data['huu']['passwd'], update_component=data['huu']['component'], stop_on_error='yes', timeout=90, verify_update='yes',
                cimc_secure_boot='no', server_id=1, force=data['huu']['force'], interval=20, backup_fw=False)
        handle.logout()
    except urllib.error.URLError as e1:
        eventLogger.error('cimc-ip: '+handle._ImcSession__ip+' | Connection Failure.')
    except imcsdk.imcexception.ImcException as e2:
        eventLogger.error('cimc-ip: '+handle._ImcSession__ip+' | Authentication Failure.')



def cleanDisks(ip,user,password):
    try:
        handle = ImcHandle(ip,user,password)
        handle.login()
        raid_controller = handle.query_dn('sys/rack-unit-1/board/storage-SAS-MRAID')
        raid_controller.admin_action = 'clear-boot-drive'
        handle.set_mo(raid_controller)
        eventLogger.info('cimc-ip: '+handle._ImcSession__ip+' | Cleared Boot Drive')
        raid_controller.admin_action = 'delete-all-vds-reset-pds'
        handle.set_mo(raid_controller)
        eventLogger.info('cimc-ip: '+handle._ImcSession__ip+' | Removed virtual disks & reset physical disks')
        handle.logout()
    except urllib.error.URLError as e1:
        eventLogger.error('cimc-ip: '+handle._ImcSession__ip+' | Connection Failure.')
    except imcsdk.imcexception.ImcException as e2:
        eventLogger.error('cimc-ip: '+handle._ImcSession__ip+' | Authentication Failure.')


def main():


    if args.clean_disks:
        threads = []
        for z in range(0,svr_count):
            if 'cimc_user' in data['svrs'][z]:
                user = data['svrs'][z]['cimc_user']
            elif 'cimc_user' not in data['svrs'][z] and 'cimc_user' in data:
                user = data['cimc_user']
            elif 'cimc_user' not in data['svrs'][z] and 'cimc_user' not in data:
                raise ValueError(data['svrs'][z]['name']+' is missing "cimc_user" in config file')

            if 'cimc_passwd' in data['svrs'][z]:
                passwd = data['svrs'][z]['cimc_passwd']
            elif 'cimc_passwd' not in data['svrs'][z] and 'cimc_passwd' in data:
                passwd = data['cimc_passwd']
            elif 'cimc_passwd' not in data['svrs'][z] and 'cimc_passwd' not in data:
                raise ValueError(data['svrs'][z]['name']+' is missing "cimc_passwd" in config file')

        for z in range(0,svr_count):
            thread = Thread(target=cleanDisks, args=(data['svrs'][z]['cimc_ip'],user,passwd))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()



    if args.update_firmware:
        threads = []
        for z in range(0,svr_count):
            if 'cimc_user' in data['svrs'][z]:
                user = data['svrs'][z]['cimc_user']
            elif 'cimc_user' not in data['svrs'][z] and 'cimc_user' in data:
                user = data['cimc_user']
            elif 'cimc_user' not in data['svrs'][z] and 'cimc_user' not in data:
                raise ValueError(data['svrs'][z]['name']+' is missing "cimc_user" in config file')

            if 'cimc_passwd' in data['svrs'][z]:
                passwd = data['svrs'][z]['cimc_passwd']
            elif 'cimc_passwd' not in data['svrs'][z] and 'cimc_passwd' in data:
                passwd = data['cimc_passwd']
            elif 'cimc_passwd' not in data['svrs'][z] and 'cimc_passwd' not in data:
                raise ValueError(data['svrs'][z]['name']+' is missing "cimc_passwd" in config file')

        for z in range(0,svr_count):
            thread = Thread(target=firmwareUpdate, args=(data['svrs'][z]['cimc_ip'],user,passwd))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()


    if args.set_hostname:
        threads = []
        for z in range(0,svr_count):
            if 'cimc_user' in data['svrs'][z]:
                user = data['svrs'][z]['cimc_user']
            elif 'cimc_user' not in data['svrs'][z] and 'cimc_user' in data:
                user = data['cimc_user']
            elif 'cimc_user' not in data['svrs'][z] and 'cimc_user' not in data:
                raise ValueError(data['svrs'][z]['name']+' is missing "cimc_user" in config file')

            if 'cimc_passwd' in data['svrs'][z]:
                passwd = data['svrs'][z]['cimc_passwd']
            elif 'cimc_passwd' not in data['svrs'][z] and 'cimc_passwd' in data:
                passwd = data['cimc_passwd']
            elif 'cimc_passwd' not in data['svrs'][z] and 'cimc_passwd' not in data:
                raise ValueError(data['svrs'][z]['name']+' is missing "cimc_passwd" in config file')

        for z in range(0,svr_count):
            thread = Thread(target=set_hostname, args=(data['svrs'][z]['cimc_ip'],user,passwd,data['svrs'][z]['name']))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()


    if args.test_login:
        threads = []
        for z in range(0,svr_count):
            if 'cimc_user' in data['svrs'][z]:
                user = data['svrs'][z]['cimc_user']
            elif 'cimc_user' not in data['svrs'][z] and 'cimc_user' in data:
                user = data['cimc_user']
            elif 'cimc_user' not in data['svrs'][z] and 'cimc_user' not in data:
                raise ValueError(data['svrs'][z]['name']+' is missing "cimc_user" in config file')

            if 'cimc_passwd' in data['svrs'][z]:
                passwd = data['svrs'][z]['cimc_passwd']
            elif 'cimc_passwd' not in data['svrs'][z] and 'cimc_passwd' in data:
                passwd = data['cimc_passwd']
            elif 'cimc_passwd' not in data['svrs'][z] and 'cimc_passwd' not in data:
                raise ValueError(data['svrs'][z]['name']+' is missing "cimc_passwd" in config file')

            thread = Thread(target=login_test, args=(data['svrs'][z]['cimc_ip'],user,passwd))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()


    if args.get_inv:
        threads = []
        for z in range(0,svr_count):
            if 'cimc_user' in data['svrs'][z]:
                user = data['svrs'][z]['cimc_user']
            elif 'cimc_user' not in data['svrs'][z] and 'cimc_user' in data:
                user = data['cimc_user']
            elif 'cimc_user' not in data['svrs'][z] and 'cimc_user' not in data:
                raise ValueError(data['svrs'][z]['name']+' is missing "cimc_user" in config file')

            if 'cimc_passwd' in data['svrs'][z]:
                passwd = data['svrs'][z]['cimc_passwd']
            elif 'cimc_passwd' not in data['svrs'][z] and 'cimc_passwd' in data:
                passwd = data['cimc_passwd']
            elif 'cimc_passwd' not in data['svrs'][z] and 'cimc_passwd' not in data:
                raise ValueError(data['svrs'][z]['name']+' is missing "cimc_passwd" in config file')

        for z in range(0,svr_count):
            thread = Thread(target=grab_inventory, args=(data['svrs'][z]['cimc_ip'],user,passwd))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()


    if args.get_faults:
        threads = []
        for z in range(0,svr_count):
            if 'cimc_user' in data['svrs'][z]:
                user = data['svrs'][z]['cimc_user']
            elif 'cimc_user' not in data['svrs'][z] and 'cimc_user' in data:
                user = data['cimc_user']
            elif 'cimc_user' not in data['svrs'][z] and 'cimc_user' not in data:
                raise ValueError(data['svrs'][z]['name']+' is missing "cimc_user" in config file')

            if 'cimc_passwd' in data['svrs'][z]:
                passwd = data['svrs'][z]['cimc_passwd']
            elif 'cimc_passwd' not in data['svrs'][z] and 'cimc_passwd' in data:
                passwd = data['cimc_passwd']
            elif 'cimc_passwd' not in data['svrs'][z] and 'cimc_passwd' not in data:
                raise ValueError(data['svrs'][z]['name']+' is missing "cimc_passwd" in config file')

        for z in range(0,svr_count):
            thread = Thread(target=grab_faults, args=(data['svrs'][z]['cimc_ip'],user,passwd))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()


if __name__ == "__main__":
    main()
