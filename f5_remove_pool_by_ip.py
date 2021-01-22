#!/usr/bin/python3
# f5_remove_pool_by_ip.py
# Author: Chad Jenison (c.jenison at f5.com)
# Version 1.0
#
# Script that uses F5 BIG-IP iControl REST API to search all pools for a member by IP address (a node) and remove the member from pools and remove node
# Version 1.0 changed member delete code so that it works with members where a node was given a name rather than using the auto-generated node/pool name based on IP address. Code also added to delete the node.

import argparse
import sys
import requests
import json
import getpass
import time
from datetime import datetime

requests.packages.urllib3.disable_warnings()

# Taken from http://code.activestate.com/recipes/577058/
def query_yes_no(question, default="no"):
    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    if default == None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)
    while 1:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid.keys():
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")

#Setup command line arguments using Python argparse
parser = argparse.ArgumentParser(description='A tool to measure bulk pool adds/removes')
parser.add_argument('--bigip', help='IP or hostname of BIG-IP Management or Self IP', required=True)
parser.add_argument('--user', help='username to use for authentication', required=True)
parser.add_argument('--password', help='password for BIG-IP REST authentication')
parser.add_argument('--nodetoremove', help='Number of members to add or remove', default=10, required=True)
parser.add_argument('--noprompt', help='Do not prompt for each pool deletion', action='store_true')
parser.add_argument('--saveonexit', help='Issue a \'save sys config\' command after modifying config', action='store_true')

args = parser.parse_args()
contentJsonHeader = {'Content-Type': "application/json"}

def get_auth_token(bigip, username, password):
    authbip = requests.session()
    authbip.verify = False
    payload = {}
    payload['username'] = username
    payload['password'] = password
    payload['loginProviderName'] = 'tmos'
    authurl = 'https://%s/mgmt/shared/authn/login' % (bigip)
    authPost = authbip.post(authurl, headers=contentJsonHeader, data=json.dumps(payload))
    if authPost.status_code == 404:
        print ('attempt to obtain authentication token failed; will fall back to basic authentication; remote LDAP auth will require configuration of local user account')
        token = None
    elif authPost.status_code == 401:
        print ('attempt to obtain authentication token failed due to invalid credentials')
        token = 'Fail'
    elif authPost.json().get('token'):
        token = authPost.json()['token']['token']
        print ('Got Auth Token: %s' % (token))
    else:
        print ('Unexpected error attempting POST to get auth token')
        quit()
    return token

def deleteMember(poolFullPath, memberFullPath):
    global configChanged
    global poolMemberDeletes
    memberDelete = bip.delete('%s/ltm/pool/%s/members/%s' % (url_base, convert_bigip_path(poolFullPath), convert_bigip_path(memberFullPath)))
    if memberDelete.status_code == 200:
        print ("Successfully deleted %s from %s" % (memberFullPath, poolFullPath))
        configChanged = True
        poolMemberDeletes += 1
    else:
        print ("Delete Response: %s" % (memberDelete.message))

def convert_bigip_path(path_to_replace):
    return path_to_replace.replace("/", "~")


user = args.user
if args.password == '' or args.password == None:
    password = getpass.getpass("Password for " + user + ":")
else:
    password = args.password
bip = requests.session()
token = get_auth_token(args.bigip, args.user, password)
if token and token != 'Fail':
    bip.headers.update({'X-F5-Auth-Token': token})
else:
    bip.auth = (args.user, password)
bip.verify = False
requests.packages.urllib3.disable_warnings()
url_base = ('https://%s/mgmt/tm' % (args.bigip))

poolMemberMatches = 0
poolMemberDeletes = 0
configChanged = False
print ("Searching Pools for Node: %s and will remove members and node" % (args.nodetoremove))
pools = bip.get('%s/ltm/pool?expandSubcollections=true' % (url_base)).json()
for pool in pools['items']:
    print ("Pool Name: %s" % (pool['name']))
    if pool['membersReference'].get('items'):
        for member in pool['membersReference']['items']:
            print ("Member Name: %s" % (member['name']))
            node = member['address']
            print ("Node: %s" % (node))
            if node == args.nodetoremove:
                nodename = member['name'].split(":")[0]
                nodeFullPath = member['fullPath'].split(":")[0]
                poolMemberMatches += 1
                if args.noprompt:
                    deleteMember(pool['fullPath'], member['fullPath'])
                else:
                    if query_yes_no("Delete %s from pool %s" % (member['name'], pool['name']), default="no"):
                        print ("poolFullPath: %s" % (pool['fullPath']))
                        deleteMember(pool['fullPath'], member['fullPath'])

if configChanged:
    if poolMemberMatches == poolMemberDeletes:
        nodeDelete = bip.delete('%s/ltm/node/%s' % (url_base, convert_bigip_path(nodeFullPath)))
        if nodeDelete.status_code == 200:
            print ("Successfully deleted node %s" % (args.nodetoremove))
        else:
            print ("Unable to delete node % s" % (args.nodetoremove))
            print ("Error Message: %s" % (nodeDelete.message))
    if args.saveonexit:
        saveSysConfigPayload = { 'command' : 'run', 'utilCmdArgs': 'save sys config'}
        bip.post('%s/util/bash' % (url_base), headers=contentJsonHeader, data=json.dumps(saveSysConfigPayload))
    else:
        print ('Configuration was changed but not saved; remember to validate and save from config or alter config with WebUI')