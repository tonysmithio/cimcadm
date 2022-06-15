#!/usr/bin/env python3

import argparse
import yaml
from imcsdk.imchandle import ImcHandle


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', help='config file in yaml format')

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

    print(hosts)
    print(cimc_ips)

if __name__ == "__main__":
    main()
