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
from concurrent.futures import ThreadPoolExecutor
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

vtext = "{'Python':'3.9.7','imcsdk':'0.9.12','cimcadm':'0.0.12'}"

parser = argparse.ArgumentParser(prog='cimcadm',formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('--version', action='version', version=vtext) 
parser.add_argument('-c', '--config', help='config file in yaml format', required=True)
parser.add_argument('--test-login', help='Test CIMC login', action='store_true')
invOptions=['all','cpu','disks','pci','psu','storage']
parser.add_argument('--get-inv', metavar='', help='Collect and display inventory for one or more components separated by a space.\nList of inventory options: {%(choices)s}', nargs='+', choices=invOptions)
parser.add_argument('--get-faults', help='Get Faults of Chassis', action='store_true')
parser.add_argument('--set-hostname', help='Update CIMC Hostname', action='store_true')
parser.add_argument('--update-firmware', help='Initiate firmware update', action='store_true')
parser.add_argument('--clean-disks', help='Clear boot-drive, remove all virtual disks, and reset all physical disks', action='store_true')
parser.add_argument('--make-bootdisk', help='Create "Root" disk', action='store_true')
parser.add_argument('-t','--threads',help='Maximum number threads to be processed at one time; default is %(default)s', default=6)

args = parser.parse_args()


with open(args.config, 'r') as configFile:
		data = yaml.load(configFile, Loader=yaml.FullLoader)


svr_count = len(data['svrs'])


def testLogin(ip,user,password):
		try:
			handle = ImcHandle(ip,user,password)
			handle.login()
			eventLogger.info('cimc-ip: '+handle._ImcSession__ip+' | Login Successful.')
			handle.logout()
		except urllib.error.URLError as e1:
			eventLogger.error('cimc-ip: '+handle._ImcSession__ip+' | Connection Failure.')
		except imcsdk.imcexception.ImcException as e2:
			eventLogger.error('cimc-ip: '+handle._ImcSession__ip+' | Authentication Failure.')


def getFaults(ip,user,password): 
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


def getInventory(ip,user,password):
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

		
def setHostname(ip,user,password,name):
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
		raid_controller = handle.query_dn('sys/rack-unit-1/board/storage-'+data['storage']['ctlr_type']+'-'+data['storage']['ctlr_slot'])
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




def createBootDisk(ip,user,password):
	try:
		handle = ImcHandle(ip,user,password)
		drive_list = []
		drive_list.append(data['storage']['bootdisk']['pd_grp'])
		cleanDisks(ip,user,password)
		handle.login()
		virtual_drive_create(handle=handle,virtual_drive_name=data['storage']['bootdisk']['vd_name'],
				raid_level=data['storage']['bootdisk']['raid_lvl'],
				drive_group=drive_list,
				size=data['storage']['bootdisk']['size'],
				controller_type=data['storage']['ctlr_type'],
				controller_slot=data['storage']['ctlr_slot'])
		handle.logout()
		eventLogger.info('cimc-ip: '+handle._ImcSession__ip+' | Created "'+data['storage']['bootdisk']['vd_name']+'" virtual disk.')
		handle.login()
		virtual_drive_set_boot_drive(handle=handle,
				controller_type=data['storage']['ctlr_type'],
				controller_slot=data['storage']['ctlr_slot'],
				name=data['storage']['bootdisk']['vd_name'])
		handle.logout()
		eventLogger.info('cimc-ip: '+handle._ImcSession__ip+' | Set "Boot Drive" parameter to "true".')
	except urllib.error.URLError as e1:
		eventLogger.error('cimc-ip: '+handle._ImcSession__ip+' | Connection Failure.')
	except imcsdk.imcexception.ImcException as e2:
		eventLogger.error('cimc-ip: '+handle._ImcSession__ip+' | Authentication Failure.')    


def main():

	svr_ips = []
	svr_users = []
	svr_passwds = []
	svr_names = []

	for z in range(svr_count):

		svr_ips.append(data['svrs'][z]['cimc_ip'])

		svr_names.append(data['svrs'][z]['name'])

		if 'cimc_user' in data['svrs'][z]:
			user = data['svrs'][z]['cimc_user']
			svr_users.append(user)
		elif 'cimc_user' not in data['svrs'][z] and 'cimc_user' in data:
			user = data['cimc_user']
			svr_users.append(user)
		elif 'cimc_user' not in data['svrs'][z] and 'cimc_user' not in data:
			raise ValueError(data['svrs'][z]['name']+' is missing "cimc_user" in config file')

		if 'cimc_passwd' in data['svrs'][z]:
			passwd = data['svrs'][z]['cimc_passwd']
			svr_passwds.append(passwd)
		elif 'cimc_passwd' not in data['svrs'][z] and 'cimc_passwd' in data:
			passwd = data['cimc_passwd']
			svr_passwds.append(passwd)
		elif 'cimc_passwd' not in data['svrs'][z] and 'cimc_passwd' not in data:
			raise ValueError(data['svrs'][z]['name']+' is missing "cimc_passwd" in config file')

	if args.make_bootdisk:
		with ThreadPoolExecutor(args.threads) as ex:
			for s in range(svr_count):
				ex.submit(createBootDisk, svr_ips[s],svr_users[s],svr_passwds[s])


	if args.clean_disks:
		with ThreadPoolExecutor(args.threads) as ex:
			for s in range(svr_count):  
				ex.submit(cleanDisks, svr_ips[s],svr_users[s],svr_passwds[s])


	if args.update_firmware:
		with ThreadPoolExecutor(args.threads) as ex:
			for s in range(svr_count):
				ex.submit(firmwareUpdate, svr_ips[s],svr_users[s],svr_passwds[s])


	if args.set_hostname:
		with ThreadPoolExecutor(args.threads) as ex:
			for s in range(svr_count):
				ex.submit(setHostname, svr_ips[s],svr_users[s],svr_passwds[s],svr_names[s])


	if args.test_login:
		with ThreadPoolExecutor(args.threads) as ex:
			for s in range(svr_count):
				ex.submit(testLogin, svr_ips[s],svr_users[s],svr_passwds[s])


	if args.get_inv:
		with ThreadPoolExecutor(args.threads) as ex:
			for s in range(svr_count):
				ex.submit(getInventory, svr_ips[s],svr_users[s],svr_passwds[s])


	if args.get_faults:
		with ThreadPoolExecutor(args.threads) as ex:
			for s in range(svr_count):
				ex.submit(getFaults, svr_ips[s],svr_users[s],svr_passwds[s]) 




if __name__ == "__main__":
	main()
