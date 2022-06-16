#!/usr/bin/env python3

import argparse
import yaml
import imcsdk
import time
from imcsdk.imchandle import ImcHandle
from imcsdk.apis.server.inventory import inventory_get

parser = argparse.ArgumentParser()
parser.add_argument('-c', '--config', help='config file in yaml format', required=True)
parser.add_argument('--test_login', help='Test CIMC login', action='store_true')
parser.add_argument('--get_inv', help='Get Inventory of Chassis', nargs='+', choices=['all','disks','cpu','pci','psu','storage'])
args = parser.parse_args()

with open(args.config, 'r') as configFile:
        data = yaml.load(configFile, Loader=yaml.FullLoader)

hosts = []

cimc_ips= []

svr_count = len(data['svrs'])

i = 0

while i < svr_count:

    for a in data['svrs'][i]:
        hosts.append(a)

    for b in data['svrs'][i]:
        cimc_ips.append(data['svrs'][i][b]['cimc_ip'])

    i += 1

def grab_inventory():
    for c in cimc_ips:
        handle = ImcHandle(c,data['cimc_user'],data['cimc_passwd'])
        handle.login()
        inv_json = inventory_get(handle=handle, component=args.get_inv)
        inv_yaml = yaml.dump(inv_json, sort_keys=False)
        handle.logout()
        print(inv_yaml)


def main():
    print(hosts)
    print(cimc_ips)

    if args.test_login:
#        for c in cimc_ips:
#            handle = ImcHandle(str(c),str(data['cimc_user']),str(data['cimc_passwd']))
        handle=ImcHandle('10.3.1.101','admin','GDTlabs@123!')
        handle.login()  
        handle.logout()

    if args.get_inv:
        grab_inventory()

if __name__ == "__main__":
    main()
