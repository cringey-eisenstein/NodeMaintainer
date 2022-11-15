#!/usr/bin/env python3

# NodeMaintainer.py
# This script is intended to run continuously inside a virtual machine, and
# thereby help maintain a mesh wireguard network
# comprised of the host VM and many other hosts accessible via the public
# internet.

# Authors: Cringey_Eisenstein,
# last update: 11/15/2022
# "nolite te bastardes carborundorum"

# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

# The last part of this file should contain version 3 of the GNU General Public License as published by the Free Software Foundation.


# when used with Ubuntu 22.04, THE FOLLOWING STEPS SHOULD HAVE ALREADY HAPPENED:

#sudo apt update; sudo apt install -y python3-pip; pip3 install pyOpenSSL --upgrade
#python3 -m pip install pyOpenSSL --upgrade; python3 -m pip install "tornado==6.2"; python3 -m pip install "ntplib==0.4.0"; python3 -m pip install "autobahn==22.7.1"; python3 -m pip install "websockets==10.3"; python3 -m pip install "psutil==5.9.4"
#sudo apt install -y net-tools fwknop-server=2.6.10-13build1 fwknop-client=2.6.10-13build1 wireguard=1.0.20210914-1ubuntu2; sudo apt autoremove -y

#gpg --full-generate-key
   #Select (1) RSA and RSA (default)
   #What keysize do you want? (3072) 2048    #fwknop does not like larger than 2048
   #Key is valid for? (0)   [key does not expire]
   #Is this correct? (y/N) y
   #Real name: [username_nodeN]
   #Email address:
   #Comment:
   #Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? O
   #At passphrase prompts, leave blank, press enter, confirm
#gpg -a --export username_nodeN > username_nodeN.asc


# when used with Ubuntu 22.04, the BELOW STEPS WILL BE DONE BY THE USER
# cat username_nodeN.asc
# copy/paste it into the web interface
# download node_file.json and transfer it to the VM -- to the same directory as this script
# update lines 102-106 of this script, as needed
# these ports need to be exposed to the internet for ingress
# tcp/websocket_port
# udp/wireguard_port
# udp/62201

# tmux
# python3 NodeMaintainer.py [node_file.json] [$HOME/.gnupg] [uri-for-ipcheck-server]
# detach from tmux
# install k3s

import os
import os.path
from os import system, name
import sys
import signal    # https://stackoverflow.com/questions/1112343/how-do-i-capture-sigint-in-python
import subprocess
import re
import asyncio    # https://realpython.com/async-io-python/
import tornado.ioloop
import tornado.locks
import tornado.options
import tornado.web
import tornado.websocket
import tornado.log
from tornado.log import enable_pretty_logging
import logging
import random
import time
import json
import websockets  # other websocket client https://websockets.readthedocs.io/en/stable/

from collections import deque
from ntplib import NTPClient
from datetime import datetime, timezone, timedelta
from autobahn.asyncio.websocket import WebSocketServerProtocol, WebSocketServerFactory
# https://github.com/crossbario/autobahn-python/blob/master/examples/asyncio/websocket/echo/server.py
# also of interest https://github.com/tripzero/python-wss/blob/master/wss/wssserver.py

import ssl
import ipaddress

import psutil

nodeFilePath = "nodes_small.json"
gpg_home_dir = "/home/user/.gnupg"
ipcheck_server = "http://ifconfig.co/"  # not sure whether ifconfig.co will work given how frequently the script pings
                                        # this address, so probably better to run your own.

if len(sys.argv) >= 2:
    temp = str(sys.argv[1])
    if os.path.isfile(temp):
        nodeFilePath = temp
if len(sys.argv) >= 3:
    temp = str(sys.argv[2])
    if os.path.isdir(temp):
        gpg_home_dir = temp
if len(sys.argv) == 4:
    temp = str(sys.argv[3])
    if "http" in temp:
        ipcheck_server = temp


print("nodeFilePath: " + str(nodeFilePath))
time.sleep(2)

# You'll want to UPDATE THESE as needed.
websocket_port = 51942
wireguard_port = 51943
nameOfThisScript = "NodeMaintainer.py"

# Default values are what seem sensible to me.
target_wspingpong_bandwidth = 2   # upload bandwidth targets in KB/s
target_icmp_bandwidth = 2
target_gossip_bandwidth = 4
fwknopd_refresh_interval = 240

# These are parameters with initial values that seem reasonable, 
# but they will fluctuate as the program runs, depending on whether upload rates are above/below target.
nodeSampleSize = 5  
maxHops = 6
dict_of_intervals = dict()
dict_of_intervals["ws_connection_check_interval"] = 20  # seconds
dict_of_intervals["heartbeatInterval"] = 30

ws_dampenFactor = 1.8
ws_undampenFactor = 1.5
icmp_dampenFactor = 1.8
icmp_undampenFactor = 1.5
gossip_dampenFactor = 1.8
gossip_undampenFactor = 1.5
nodeIncrement = 1.0
nodeDecrement = 1.0

# These parameters will also adjust as the program runs, but within constraints 
# to avoid silliness like closing websocket connections right after opening them.
websocket_stale_threshold = 4*dict_of_intervals["ws_connection_check_interval"]
wireguard_stale_threshold = websocket_stale_threshold
wireguard_refresh_interval = fwknopd_refresh_interval/2
backupInterval = fwknopd_refresh_interval*2

# These probably don't need to be tinkered with.
bandwidth_regulator_interval = 4  # seconds
wireguardConfigFileName = "p2p-virtual-lan.conf"
wg_bigconf_filename = "wg0.conf"
commLogFile = "commLog.txt"
meshStatsLogFile = "meshStatsLog.csv"

if not os.path.isfile(meshStatsLogFile):
    outfile = open(meshStatsLogFile, "a")
    line = "timestamp,nonarchived nodes (num),nonarchived nodes with lastPongWS (num),nonarchived nodes with ICMPreceived (num),send gossip data rate (KB/s) short window,send gossip data rate (KB/s) long window,gossip dampen,gossip undampen,nodeDecrement (num nodes),nodeIncrement (num nodes),nodeSampleSize (num nodes),websocket stale threshold (s),wireguard stale threshold (s),heartbeatInterval (s),wireguard start count,sysload1min,memTotal_MB,memAvailable_MB\n"
    outfile.write(line)
    outfile.close()

# Even less reason to tinker with these.
actual_wspingpong_bandwidth = 0
actual_icmp_bandwidth = 0
actual_gossip_bandwidth = 0
bigwindow_wspingpong_bandwidth = 0
bigwindow_icmp_bandwidth = 0
bigwindow_gossip_bandwidth = 0
wireguardStartCount = 0
gpg_lookup = dict()
keyname_lookup = dict()
historical_byteAndTimestampStats = deque()
total_wspingpong_bytes_sent = 0
total_icmp_bytes_sent = 1
total_gossip_bytes_sent = 0
continuous_ping_output = dict()
healthyOverall = True

thisScriptPath = os.path.realpath(__file__)
my_regex = r"(.+)/" + re.escape(nameOfThisScript) + r"$"
m1 = re.search(my_regex, thisScriptPath)
containingDir = m1.group(1) if m1 else None


# Specializing JSON object decoding
def as_datetime(arg):
    #print("as_datetime " + str(arg))
    answer = dict()
    for kv in arg:
        if kv[0] in ("lastPing", "lastPong", "last_wg_icmp_send_timestamp", "last_wg_icmp_receive_timestamp"):
            if kv[1]:
                answer[kv[0]] = datetime.strptime(kv[1], "%Y-%m-%d %H:%M:%S.%f%z")
        elif kv[0] in ("hop"):
            answer[kv[0]] = int(kv[1])
        else:
            answer[kv[0]] = kv[1]
    return answer


infile = open(nodeFilePath, "r")
node_dict = json.load(infile, object_pairs_hook=as_datetime)
infile.close()
for k, v in node_dict.items():
    node_dict[k]["strikeCount"] = 0

archived_nodes_dict = dict()

scriptShouldBeRunning = True

commLogBuffer = deque()


def CommLog(ts, desc, proto, sourceIP, destIP, port):
    global commLogBuffer
    line = ts.strftime("%Y-%m-%d %H:%M:%S.%f%z") + "," + desc + "," + proto + "," + str(sourceIP) + "," + str(destIP) + "," + str(port) + "\n"
    commLogBuffer.append(line)


async def WriteCommLogBufferToDisk():
    global commLogBuffer
    while True:
        await asyncio.sleep(5)
        #outfile = open(commLogFile, "a")  #uncomment to enable
        while len(commLogBuffer) > 0:
            line = commLogBuffer.popleft()
            #outfile.write(line)   # uncomment to enable. the file gets big.
        #outfile.close()   # uncomment to enable


def ArchiveNode(fwknop_gpg_pubkey, nodevals):
    global archived_nodes_dict
    #print("inside ArchiveNode")
    #print(str(type(nodevals)))
    #print(str(nodevals))
    try:
        archived_nodes_dict[fwknop_gpg_pubkey] = dict(nodevals)
        archived_nodes_dict[fwknop_gpg_pubkey]["archive_ts"] = GetUTC_timestamp_as_datetime_synchronous()
    except Exception as e:
        print("exception in ArchiveNode")
        print(e)
        time.sleep(10)


def GetHostIfaceName():
    if not os.path.isdir(f"{containingDir}/NodeMaintainer_scratch"):
        os.system(f"mkdir {containingDir}/NodeMaintainer_scratch/")
    os.system(f"ifconfig -a > {containingDir}/NodeMaintainer_scratch/ifconfig_output.txt")
    with open(f"{containingDir}/NodeMaintainer_scratch/ifconfig_output.txt") as file:
        for line in file:
            m1 = re.search('^(.+):\sflags=\d+<(.+)>\s+mtu\s.+$', line)
            if m1:
                name = m1.group(1)
                flags_string = m1.group(2).lower()
                flags = set(flags_string.split(","))
                if "up" in flags and "broadcast" in flags and "running" in flags and "multicast" in flags:
                    print("interface name is " + name)
                    return name
    return None


async def NewNodeKeyMonitor(node_dict):
    if not os.path.isdir(f"{containingDir}/inbox_for_gpg_pubkeys"):
        os.system(f"mkdir {containingDir}/inbox_for_gpg_pubkeys/")
    if not os.path.isdir(f"{containingDir}/outbox_for_gpg_pubkeys"):
        os.system(f"mkdir {containingDir}/outbox_for_gpg_pubkeys/")
    # public keys of new nodes should be moved/copied to the inbox_for_gpg_pubkeys/ dir
    # the filename for each key should have this format:
    # 123.4.5.6_keyname.asc   [123.4.5.6 in the internet IP address of the new node]
    # NodeMaintainer.py will monitor the inbox dir and process any keys added.
    # if processing succeeds, it will copy the input file to the outbox with 
    # "p." prepended to the filename, and remove the file from inbox
    # e.g.: p.123.4.5.6_keyname.asc
    # if processing fails, the same thing happens, but with "E." prepended
    # e.g.: E.123.6.6.6_keyn6me.asc
    while True:
        for filename in os.listdir(f"{containingDir}/inbox_for_gpg_pubkeys"):
            pubkey = Ingest_asc_file(f"{containingDir}/inbox_for_gpg_pubkeys/{filename}")
            ip, nodeName = ParseAndCheckKey(filename, pubkey)
            if ip:
                # copy to outbox #change name to preprended p.
                os.system(f"cp {containingDir}/inbox_for_gpg_pubkeys/{filename} {containingDir}/outbox_for_gpg_pubkeys/p.{filename}")
                node_dict[pubkey] = dict()
                node_dict[pubkey]["internetIP"] = ip
                node_dict[pubkey]["strikeCount"] = 0
            else:
                # copy to outbox #change name to preprended E.
                print("ingestion of new node info failed")
                time.sleep(2)
                os.system(f"cp {containingDir}/inbox_for_gpg_pubkeys/{filename} {containingDir}/outbox_for_gpg_pubkeys/E.{filename}")
            #remove from inbox
            os.system(f"rm {containingDir}/inbox_for_gpg_pubkeys/{filename}")
        await asyncio.sleep(10)


def ParseAndCheckKey(filename, pubkey):
    ip_candidate, nodename = None, None
    m1 = re.search('^(\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?)\_(.+)\.asc$', filename)
    if m1:
        ip_candidate = m1.group(1)
        nodename = m1.group(2)
    m2 = re.search('[^\S]+', pubkey)
    if m2:
        return None, nodename
    try:
        preAns = ipaddress.ip_address(ip_candidate)
    except:
        return None, nodename
    return ip_candidate, nodename


def gpg_is_installed():
    result = subprocess.run(['which', 'gpg'], stdout=subprocess.PIPE)
    if len(result.stdout.decode('utf-8')) > 0:
        return True
    else:
        return False


def GetGPG_fingerprints():
    temp_fingerprint_dict = dict()
    os.system(f"rm {containingDir}/NodeMaintainer_scratch/*")
    with open(f"{containingDir}/NodeMaintainer_scratch/keylist.txt", "w") as outfile:
        subprocess.run(["gpg", "--list-keys", "--with-colons"], stdout=outfile, stderr=subprocess.PIPE)
    pubFlag = False
    fingerprintFlag = False
    uid = None
    with open(f"{containingDir}/NodeMaintainer_scratch/keylist.txt") as file:
        for line in file:
            m1 = re.search('pub', line)
            if m1:
                pubFlag = True
            if pubFlag:
                m1 = re.search('fpr:::::::::(.+):', line)
                if m1:
                    fingerprint = m1.group(1)
                    fingerprintFlag = True
            if fingerprintFlag:
                m1 = re.search('uid:(.+)::::(.+)::(.+)::(.+)::::::::::(.+):', line)
                if m1:
                    uid = m1.group(4)
            if pubFlag and fingerprintFlag and uid:
                temp_fingerprint_dict[uid] = fingerprint
                pubFlag = False
                fingerprintFlag = False
                uid = None
                fingerprint = None
    return temp_fingerprint_dict


def GetGPG_pubkey(keyname):
    try:
        key_fp = keyname_lookup[keyname][1]
    except:
        key_fp = keyname
    with open(f"{containingDir}/NodeMaintainer_scratch/tempPubGpg.asc", "w") as outfile:
        subprocess.run(["gpg", "--export", "-a", key_fp], stdout=outfile, stderr=subprocess.PIPE)
    cmd = "gpg --export -a " + key_fp + f" > {containingDir}/NodeMaintainer_scratch/tempPubGpg.asc"
    print("executed: " + str(cmd))
    return Ingest_asc_file(f"{containingDir}/NodeMaintainer_scratch/tempPubGpg.asc")


def Ingest_asc_file(filepath):
    with open(filepath, 'r') as infile:
        lines = infile.readlines()
        lines = [line.rstrip() for line in lines]
    concatKey = ""
    for line in lines:
        if "BEGIN PGP" not in line and "END PGP" not in line and (line != ''):
            concatKey = concatKey + line
    return concatKey


def fwknop_is_installed():
    result = subprocess.run(['which', 'fwknop'], stdout=subprocess.PIPE)
    result2 = subprocess.run(['which', 'fwknopd'], stdout=subprocess.PIPE)
    if len(result.stdout.decode('utf-8')) > 0 and len(result2.stdout.decode('utf-8')) > 0:
        return True
    else:
        return False


def ConfigureFwknopd(node_dict=node_dict):
    global host_iface_name
    global host_fwknopd_pubkey_name      # ingest username_nodeN.asc and label this file name (without the .asc) as the name of the host's public key - this is the key your node will be using to sign the other keys
    global websocket_port
    global wireguard_port
    global gpg_home_dir
    global gpg_lookup
    global keyname_lookup
    for filename in os.listdir(containingDir):
        if filename[-4:] == ".asc":
            host_fwknopd_pubkey_name = filename[:-4]
            break
    if gpg_is_installed():
        temp_fingerprint_dict = GetGPG_fingerprints()
        for keyname, fingerprint in temp_fingerprint_dict.items():
            if keyname != host_fwknopd_pubkey_name:
                subprocess.run(["sudo", "-E", "gpg", "--quiet", "--batch", "--delete-keys", fingerprint], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                cmd = 'sudo -E gpg --quiet --batch --delete-keys ' + fingerprint
                print("executed: " + cmd)
        i = 1
        for pubkey, nodeInfo in node_dict.items():
            filepath = f"{containingDir}/NodeMaintainer_scratch/reserved_temp_pubkey_filename" + str(i) + ".asc"
            with open(filepath, 'w') as outfile:
                outfile.write('-----BEGIN PGP PUBLIC KEY BLOCK-----\n')
                outfile.write('\n')
                outfile.write(pubkey + '\n')
                outfile.write('-----END PGP PUBLIC KEY BLOCK-----\n')
            i += 1
        cmd = f'sudo -E gpg --quiet --import {containingDir}/NodeMaintainer_scratch/*.asc'    # https://www.gnupg.org/documentation/manuals/gnupg.pdf
        subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("executed: " + cmd)
        #time.sleep(20)
        temp_fingerprint_dict = GetGPG_fingerprints()
        print("temp_fingerprint_dict:  " + str(temp_fingerprint_dict))
        time.sleep(5)
        for keyname, fingerprint in temp_fingerprint_dict.items():
            pubkey = GetGPG_pubkey(keyname)
            gpg_lookup[pubkey] = (keyname, fingerprint)
            keyname_lookup[keyname] = (pubkey, fingerprint)
        filepath = f"{containingDir}/NodeMaintainer_scratch/sign_script.sh"
        with open(filepath, 'w') as outfile:
            outfile.write("#!/bin/bash\n")
            for keyname, fingerprint in temp_fingerprint_dict.items():
                if keyname != host_fwknopd_pubkey_name:
                    cmd = 'echo -e "y\nsave\n" | sudo -E gpg --command-fd 0 --edit-key ' + keyname + ' sign'
                    c2 = cmd.encode('unicode_escape').decode()
                    outfile.write(c2)
                    outfile.write("\n")
        cmd = "chmod 755 " + filepath
        os.system(cmd)
        os.system(filepath)
        print("signed all the gpg keys (except for the host's key) with the host's key")   # https://raymii.org/s/articles/GPG_noninteractive_batch_sign_trust_and_send_gnupg_keys.html
    else:
        print("cannot find gpg; terminating script.")
        sys.exit()
    if fwknop_is_installed():
        if host_iface_name:
            os.system("sudo -E cp /etc/fwknop/fwknopd.conf /etc/fwknop/fwknopd.conf.old")
            os.system(f"sudo -E head -n -1 /etc/fwknop/fwknopd.conf > {containingDir}/NodeMaintainer_scratch/tmp.txt")
            for_appending = "PCAP_INTF " + host_iface_name + ";\n"
            with open(f"{containingDir}/NodeMaintainer_scratch/tmp.txt", 'a') as outfile:
                outfile.write(for_appending)
                outfile.write("VERBOSE 3;\n")
                outfile.write("##EOF###\n")
            os.system(f"sudo -E mv {containingDir}/NodeMaintainer_scratch/tmp.txt /etc/fwknop/fwknopd.conf")
            os.system("sudo -E chmod 0600 /etc/fwknop/fwknopd.conf")
            os.system("sudo -E mv /etc/fwknop/access.conf /etc/fwknop/access.conf.old")
            GPG_REMOTE_ID = ""
            for keyname, fingerprint in temp_fingerprint_dict.items():
                if keyname != host_fwknopd_pubkey_name:
                    GPG_REMOTE_ID = GPG_REMOTE_ID + keyname + "," + fingerprint[-8:] + ","
            if len(GPG_REMOTE_ID) > 0:
                GPG_REMOTE_ID = GPG_REMOTE_ID[:-1]
            with open(f"{containingDir}/NodeMaintainer_scratch/fwknop_access.conf", 'w') as outfile:    # create new file fwknop_access.conf with the contents:
                outfile.write("#stanza\n")
                outfile.write("SOURCE      ANY\n")
                t = "OPEN_PORTS      tcp/" + str(websocket_port) + ", udp/" + str(wireguard_port) + "\n"
                outfile.write(t)
                outfile.write("FW_ACCESS_TIMEOUT       30\n")
                outfile.write("REQUIRE_SOURCE_ADDRESS      Y\n")
                outfile.write("GPG_ALLOW_NO_PW         Y\n")
                t = "GPG_DECRYPT_ID      " + str(host_fwknopd_pubkey_name) + "\n"
                outfile.write(t)
                t = "GPG_HOME_DIR        " + str(gpg_home_dir) + "\n"
                outfile.write(t)
                outfile.write("GPG_REQUIRE_SIG                    Y\n")
                outfile.write("GPG_IGNORE_SIG_VERIFY_ERROR        N\n")
                t = "GPG_REMOTE_ID       " + GPG_REMOTE_ID + "\n"
                outfile.write(t)
                outfile.write("#end stanza\n")
            os.system(f"sudo -E cp {containingDir}/NodeMaintainer_scratch/fwknop_access.conf /etc/fwknop/access.conf")
            os.system("sudo -E chmod 0600 /etc/fwknop/access.conf")
            # https://www.digitalocean.com/community/tutorials/how-to-use-fwknop-to-enable-single-packet-authentication-on-ubuntu-12-04
            # https://www.cipherdyne.org/fwknop/
            # First, we need to allow our current connection. This rule will allow already established connections and associated data:
            cmd = "sudo iptables -A INPUT -i " + host_iface_name + " -p tcp --dport " + str(websocket_port) + " -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
            os.system(cmd)
            cmd = "sudo iptables -A INPUT -i " + host_iface_name + " -p udp --dport " + str(wireguard_port) + " -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
            os.system(cmd)
            # Next, directly after, we’ll restrict all other access to the port by dropping all non-established connection attempts:
            cmd = "sudo iptables -A INPUT -i " + host_iface_name + " -p tcp --dport " + str(websocket_port) + " -j DROP"
            os.system(cmd)
            cmd = "sudo iptables -A INPUT -i " + host_iface_name + " -p udp --dport " + str(wireguard_port) + " -j DROP"
            os.system(cmd)
            # Now that we have a basic firewall restricting access to that port, we can implement our configuration. Restart the fwknop server by typing:
            cmd = "sudo service fwknop-server restart"
            print("Waiting 5 seconds to let fwknopd finish startup...")
            os.system(cmd)
            time.sleep(5)
            print("Done waiting.")
            # Now, the fwknop service will begin monitoring our server for packets that match rules we configured.
        else:
            print("could not find this machine's network interface name; terminating script")
            sys.exit()
    else:
        print("cannot find BOTH fwknop AND fwknopd; terminating script")
        sys.exit()


def aFewSecs(minimum=1, maximum=3) -> float:
    return random.uniform(minimum, maximum)


def CalcTimeOffset() -> float:
    ans = 0.0
    response = None
    t = None
    t_seconds = None
    client = NTPClient()
    time.sleep(aFewSecs(1,3))
    t_sys=datetime.now(tz=timezone.utc)
    print("trying time.nist.gov")
    try:
        response = client.request('time.nist.gov', version=3)
    except:
        print("trying pool.ntp.org")
        try:
            response = client.request('pool.ntp.org', version=3)
        except:
            print("trying ntp.nict.jp")
            try:
                response = client.request('ntp.nict.jp', version=3)
            except:
                print("trying ntp.metas.ch")
                try:
                    response = client.request('ntp.metas.ch', version=3)
                except:
                    print("trying 216.239.35.12 (ip for time.google.com)")
                    try:
                        response = client.request('216.239.35.12', version=3)
                    except:
                        print("could not get UTC timestamp from internet")
    if response:
        t = datetime.fromtimestamp(response.tx_time, tz=timezone.utc)
        t_seconds = t.timestamp()
        t_sys_seconds = t_sys.timestamp()
        ans = t_sys_seconds - t_seconds
    print("time offset: " + str(ans))
    return ans


# current_time = await GetUTC_timestamp_as_datetime()
async def GetUTC_timestamp_as_datetime() -> datetime:
    theTime = None
    global offsetFromInternetTime
    nineteenSeventy = datetime(1970, 1, 1, tzinfo=timezone.utc)
    t_sys = datetime.now(tz=timezone.utc)
    t_sys_seconds = t_sys.timestamp()
    t_seconds = t_sys_seconds - offsetFromInternetTime
    timeDeltaSinceNineteenSeventy = timedelta(seconds=t_seconds)
    theTime = nineteenSeventy + timeDeltaSinceNineteenSeventy
    return theTime


# current_time = GetUTC_timestamp_as_datetime_synchronous()
def GetUTC_timestamp_as_datetime_synchronous() -> datetime:
    theTime = None
    global offsetFromInternetTime
    nineteenSeventy = datetime(1970, 1, 1, tzinfo=timezone.utc)
    t_sys = datetime.now(tz=timezone.utc)
    t_sys_seconds = t_sys.timestamp()
    t_seconds = t_sys_seconds - offsetFromInternetTime
    timeDeltaSinceNineteenSeventy = timedelta(seconds=t_seconds)
    theTime = nineteenSeventy + timeDeltaSinceNineteenSeventy
    return theTime


def GetHostInternetIP() -> str:
    global ipcheck_server
    global host_externalIP
    ans = "0.0.0.0"
    complProc = subprocess.run(["curl", ipcheck_server], capture_output=True, text=True)
    ans = complProc.stdout
    ans = ans.strip()
    print("GetHostInternetIP " + ipcheck_server + " returned " + ans)
    time.sleep(1)
    CommLog(GetUTC_timestamp_as_datetime_synchronous(), "ip_addr_check_outgoing", "HTTP", host_externalIP, ipcheck_server, "?")
    return ans


def CheckConfigFileForPresets(wireguardConfigFileName) -> tuple:
    privatekey = None
    ip = None
    if os.path.exists(wireguardConfigFileName):
        with open(wireguardConfigFileName, "r") as f:
            content = f.read()
            m1 = re.search('wireguard_private_key\s(.+)\n((.|\n)+)', content)
            privatekey = m1.group(1) if m1 else None
            remaining_content = m1.group(2) if m1 else None
            m1 = re.search('wireguard_ipv4_address\s(.+)((.|\n)*)', remaining_content)
            ip = m1.group(1) if m1 else None
    return privatekey, ip


async def WG_first_steps() -> tuple:
    alt_shellScriptText = """#!/bin/bash
sudo ip link add dev wg0 type wireguard
umask 077
cat privatekey | wg pubkey > publickey
cat privatekey
cat publickey
"""
    shellScriptText = """#!/bin/bash
sudo ip link add dev wg0 type wireguard
umask 077
wg genkey | tee privatekey | wg pubkey > publickey
cat privatekey
cat publickey
"""
    privatekey, placeholderVar = CheckConfigFileForPresets(wireguardConfigFileName)
    if privatekey:
        with open("privatekey", "w") as f:
            f.write(str(privatekey) + "\n")
        with open("tempScript.sh", "w") as f:
            f.write(alt_shellScriptText)
    else:
        with open("tempScript.sh", "w") as f:
            f.write(shellScriptText)
    complProc1 = subprocess.run(["chmod", "700", "tempScript.sh"], capture_output=True, text=True)
    complProc2 = subprocess.run(["./tempScript.sh"], capture_output=True, text=True)
    m1 = re.search('(.+)\n(.+)', complProc2.stdout)
    privatekey = m1.group(1)
    publickey = m1.group(2)
    return (privatekey, publickey)


async def GenerateRandomIP4addr() -> str:
    placeholderVar, ip = CheckConfigFileForPresets(wireguardConfigFileName)
    #198.18.0.0/15 is 131072 IPv4 addresses reserved for benchmark testing of inter-network communications between two separate subnets.
    #https://en.wikipedia.org/wiki/Reserved_IP_addresses
    #So it should be fine for AFKS to use for the time being until IPv6.
    if not ip:
        a = 198
        b = random.randint(18, 19)
        c = random.randint(0, 255)
        d = random.randint(0, 255)
        ip = str(a) + "." + str(b) + "." + str(c) + "." + str(d)
    return ip


async def CheckForWireguardIP() -> str:
    ans = None
    complProc = subprocess.run(["ifconfig", "-a"], capture_output=True, text=True)
    m1 = re.search('wg0\:((.|\n)+)', complProc.stdout)
    if m1:
        excerpt = str(m1.group(1))
        m2 = re.search('inet\s(.+)\s\snetmask', excerpt)
        if m2:
            ans = str(m2.group(1))
    return ans


async def SelfAssignWireguardIP_collision_allowed() -> str:
    preAns = await CheckForWireguardIP()
    while not preAns:
        preAns = await GenerateRandomIP4addr()
    return preAns


async def FirstWireguardThings():
    global host_externalIP
    enclosingDir = os.path.dirname(os.path.realpath(__file__))
    wg_bigconf_path = enclosingDir + "/wg0.conf"
    if os.path.exists(wg_bigconf_path):
        complProc = subprocess.run(["sudo", "wg-quick", "down", wg_bigconf_path], capture_output=True, text=True)
        #print("shut down any pre-existing wireguard interface" + "\n")
    global wgPrivateKey
    global offsetFromInternetTime
    wgPrivateKey, pub = await WG_first_steps()
    host_externalIP = GetHostInternetIP()
    b = await SelfAssignWireguardIP_collision_allowed()
    offsetFromInternetTime = CalcTimeOffset()
    #print("almost done with FirstWireguardThings() ")  # shows up at very beginning of stdout
    await asyncio.sleep(10)


def OpenSSL_is_installed():
    result = subprocess.run(['which', 'openssl'], stdout=subprocess.PIPE)
    if len(result.stdout.decode('utf-8')) > 0:
        return True
    else:
        return False


def SSL_files_exist(*filenames):
    for filename in filenames:
        if os.path.isfile(filename):
            return True
    return False


offsetFromInternetTime = CalcTimeOffset()  # setup
asyncio.ensure_future(FirstWireguardThings())

host_fwknopd_pubkey_name = None
host_iface_name = GetHostIfaceName()
ConfigureFwknopd(node_dict=node_dict)
host_externalIP = None
host_externalIP = GetHostInternetIP()
host_fwknopd_pubkey = keyname_lookup[host_fwknopd_pubkey_name][0]

myWireguardIP = None
myWireguardPublicKey = None
wireguardNeedsPriming = True

if OpenSSL_is_installed():
    if not SSL_files_exist("autobahn_server.key", "autobahn_server.csr", "autobahn_server.crt"):
        #print("about to issue command: openssl genrsa -out autobahn_server.key 2048")
        os.system("openssl genrsa -out autobahn_server.key 2048")
        #print("command issued")
        time.sleep(0.5)
        #print("about to issue command: openssl rsa -in autobahn_server.key -out autobahn_server.key")
        os.system("openssl rsa -in autobahn_server.key -out autobahn_server.key")
        #print("command issued")
        time.sleep(0.5)
        cmd = "openssl req -nodes -sha256 -new -key autobahn_server.key -out autobahn_server.csr -subj '/CN=" + host_externalIP +"'"
        #print("about to issue command: " + cmd)
        os.system(cmd)
        #print("command issued")
        time.sleep(0.5)
        #print("about to issue command: openssl x509 -req -days 365 -in autobahn_server.csr -signkey autobahn_server.key -out autobahn_server.crt")
        os.system("openssl x509 -req -days 365 -in autobahn_server.csr -signkey autobahn_server.key -out autobahn_server.crt")
        #print("command issued")
        #print("done issuing ssl commands")
        time.sleep(0.5)
    else:
        print("one or more SSL files already exists; terminating script")
        sys.exit()
else:
    print("can't find openssl; terminating script")
    sys.exit()


sslcontext_forserver = ssl.SSLContext(ssl.PROTOCOL_TLS)
sslcontext_forserver.load_cert_chain("autobahn_server.crt", "autobahn_server.key")
print("loaded sslcontext_forserver")

#log_file_filename = 'Test_server.log'
#logging.basicConfig(filename=log_file_filename, filemode='a', format='%(name)s - %(levelname)s - %(message)s')

#handler = logging.FileHandler(log_file_filename)
app_log = logging.getLogger("tornado.application")
access_log = logging.getLogger("tornado.access")
gen_log = logging.getLogger("tornado.general")

#enable_pretty_logging()
#app_log.addHandler(handler)
#access_log.addHandler(handler)
#gen_log.addHandler(handler)


#Extending JSONEncoder
class TimestampEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime("%Y-%m-%d %H:%M:%S.%f%z")
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


async def Maintain_backup_file_of_nodes(path, node_dict=node_dict):
    global backupInterval
    global archived_nodes_dict
    while True:
        try:
            local_node_dict = dict(node_dict)
            for k, v in archived_nodes_dict.items():  # WIP probably want to use "archive_ts" field so that archived nodes can be deleted after some grace period
                local_node_dict[k] = v

            t = dict()
            for k, v in local_node_dict.items():
                v1 = dict()
                for k2, v2 in v.items():
                    if k2 != "wsclient":   # we don't want to be messing with duplicate websocket-client objects and trying to pickle them, etc
                        v1[k2] = v2
                t[k] = v1
            #print("Maintain_backup_file_of_nodes ")
            outputString = json.dumps(t, sort_keys=True, indent=4, cls=TimestampEncoder)
            outfile = open(path, "w")
            outfile.write(outputString)
            outfile.close()
        except Exception as e:
            print("exception in Maintain_backup_file_of_nodes")
            print(e)
            time.sleep(15)
        #print("backupInterval is " + str(backupInterval))
        #time.sleep(2)
        await asyncio.sleep(backupInterval)


def PortKnock(gpg_keyname, destIP, sourceIP, port, protocol):
    global gpg_home_dir
    global host_fwknopd_pubkey_name
    try:
        assert (gpg_home_dir and host_fwknopd_pubkey_name and gpg_keyname and len(destIP)>4 and len(sourceIP)>4 and len(str(port))>0 and len(protocol)>2), f"gpg_home_dir: {gpg_home_dir}, host_fwknopd_pubkey_name: {host_fwknopd_pubkey_name}, gpg_keyname: {gpg_keyname}, destIP: {destIP}, sourceIP: {sourceIP}, port: {port}, protocol: {protocol}"
    except Exception as e:
        print(e)
        time.sleep(10)
    
    try:
        recip_fp = keyname_lookup[gpg_keyname][1]
    except:
        recip_fp = gpg_keyname

    try:
        signer_fp = keyname_lookup[host_fwknopd_pubkey_name][1]
    except:
        signer_fp = host_fwknopd_pubkey_name

    cmd = "sudo fwknop -g --gpg-no-signing-pw --gpg-home-dir=" + gpg_home_dir + " --access=" + protocol + "/" + str(port) + " --gpg-recipient=" + recip_fp + " --gpg-signer-key=" + signer_fp + " --allow-ip=" + sourceIP + " --destination=" + destIP + " --fw-timeout=45"
    print("PortKnock: " + cmd)
    #app_log.warning("PortKnock: " + cmd)
    CommLog(GetUTC_timestamp_as_datetime_synchronous(), "port_knock_outgoing", protocol, sourceIP, destIP, str(port))
    os.system(cmd)


class WSCwarehouse:
    def __init__(self):
        self.client_dict = dict()
        self.highest_pkey = 0

    def store(self, client):
        self.client_dict[self.highest_pkey] = client
        ans = self.highest_pkey
        self.highest_pkey += 1
        return ans


MyWebsocketClientWarehouse = WSCwarehouse()


# https://stackoverflow.com/questions/71384132/best-approach-to-multiple-websocket-client-connections-in-python
class CustomWebsocketClient:
    def __init__(self, destIP, wsport, fwknop_pubkey, node_dict):
        self.destIP = destIP
        self.wsport = wsport
        self.url = "wss://" + self.destIP + ":" + str(self.wsport)
        self.fwknop_pubkey = fwknop_pubkey
        self.sslclientcontext = ssl.SSLContext(ssl.PROTOCOL_TLS)
        self.sslclientcontext.verify_mode = ssl.CERT_NONE
        self.sslclientcontext.verify_flags = ssl.VERIFY_DEFAULT
        self.node_dict = node_dict

    async def destroy(self):
        try:
            if self.websocket.open:
                await self.websocket.close()  # Terminates any recv() in wait_for_incoming()
                try:
                    await self.incoming_message_task  # keep asyncio happy by awaiting the "background" task
                except:
                    pass
        except:
            pass

    async def start(self):    # https://websockets.readthedocs.io/en/stable/intro/quickstart.html
        try:
            await asyncio.sleep(aFewSecs(3, 5))
            self.websocket = await websockets.connect(self.url, ssl=self.sslclientcontext)   # Connect to wss://destIP:wsport
            self.incoming_message_task = asyncio.create_task(self.wait_for_incoming())   # Set up a "background" task for further streaming reads of the web socket
            CommLog(GetUTC_timestamp_as_datetime_synchronous(), "wss_handshake_outgoing", "WSS", host_externalIP, self.destIP, self.wsport)
            return True
        except Exception as e:
            CommLog(GetUTC_timestamp_as_datetime_synchronous(), "wss_handshake_outgoing_ERR", "WSS", host_externalIP, self.destIP, self.wsport)
            print(e)
            time.sleep(5)
            return False   # Connection failed (or some unexpected error)

    async def wait_for_incoming(self):
        while self.websocket.open:
            try:
                update_message = await self.websocket.recv()
                asyncio.create_task(self.process_update_message(update_message))
            except:
                pass   # Presumably, socket closure

    async def process_update_message(self, update_message):
        update_message = str(update_message)
        #print("message received: " + update_message)
        if update_message == "pong":
            current_time = GetUTC_timestamp_as_datetime_synchronous()
            self.node_dict[self.fwknop_pubkey]["lastPong"] = current_time
            CommLog(current_time, "wss_pong_incoming", "WSS", "?", host_externalIP, str(websocket_port))
        else:
            CommLog(current_time, "wss_unknown_incoming", "WSS", "?", host_externalIP, str(websocket_port))


async def OpenWebsocketClientConnectionToNode(gpg_keyname, destIP, sourceIP, node_dict):
    global host_fwknopd_pubkey_name
    global websocket_port
    global keyname_lookup
    global MyWebsocketClientWarehouse
    global total_gossip_bytes_sent
    #print("OpenWebsocketClientConnectionToNode")
    #app_log.warning("OpenWebsocketClientConnectionToNode")
    if gpg_keyname != host_fwknopd_pubkey_name:
        try:
            PortKnock(gpg_keyname, destIP, sourceIP, websocket_port, "tcp")
            total_gossip_bytes_sent += 1460  # assuming SPA uses full packet size
            time.sleep(5)
            fwknop_pubkey=keyname_lookup[gpg_keyname][0]
            new_ws_client_instance = CustomWebsocketClient(destIP=destIP, wsport=websocket_port, fwknop_pubkey=fwknop_pubkey, node_dict=node_dict)
            t = asyncio.create_task(new_ws_client_instance.start())
            asyncio.gather(t)
            total_gossip_bytes_sent += 215   # guesstimate based on googling about the WSS handshake
            ref = MyWebsocketClientWarehouse.store(new_ws_client_instance)
            node_dict[keyname_lookup[gpg_keyname][0]]["wsclient"] = ref
        except Exception as e:
            app_log.warning("error opening websocket connection to " + destIP)
            app_log.warning(e)
            time.sleep(3)


async def Maintain_fwknopd_ws_connections_stats(node_dict):
    global websocket_stale_threshold
    global wireguard_stale_threshold
    global gpg_lookup
    global keyname_lookup
    global host_externalIP
    global host_fwknopd_pubkey_name
    global total_wspingpong_bytes_sent
    done = None
    pending = None
    while True:
        try:
            await AsyncResponsiveSleep("ws_connection_check_interval")
            print("Maintain_fwknopd_ws_connections_stats")
            print("Maintain_fwknopd_ws_connections_stats host_externalIP: " + host_externalIP)
            for fwknop_gpg_pubkey, nodeValues in list(node_dict.items()):
                current_time = await GetUTC_timestamp_as_datetime()
                #print("nodeValues: " + str(nodeValues))
                if "wsclient" in nodeValues:
                    print("wsclient in nodeValues")
                    if "lastPing" not in nodeValues:
                        print("lastPing NOT in nodeValues therefore sending a ping")
                        try:
                            CommLog(current_time, "wss_ping_outgoing", "WSS", host_externalIP, nodeValues["internetIP"], "?")  #print("line 710")
                            await MyWebsocketClientWarehouse.client_dict[nodeValues["wsclient"]].websocket.send("ping")                            
                            node_dict[fwknop_gpg_pubkey]["lastPing"] = current_time
                            total_wspingpong_bytes_sent += 4
                        except Exception as e:
                            #print(e)
                            #print("assigning a lastPing anyway, despite exception")
                            node_dict[fwknop_gpg_pubkey]["lastPing"] = current_time
                        continue
                    elif "lastPong" not in nodeValues:
                        await MyWebsocketClientWarehouse.client_dict[node_dict[fwknop_gpg_pubkey]["wsclient"]].destroy()
                        del node_dict[fwknop_gpg_pubkey]["wsclient"]  # flush "wsclient" entry
                        del node_dict[fwknop_gpg_pubkey]["lastPing"]
                        print("line 944 - destroyed ws - but it should get recreated in a moment")
                        if node_dict[fwknop_gpg_pubkey]["strikeCount"] < 3:
                            node_dict[fwknop_gpg_pubkey]["strikeCount"] += 1
                            print("stale based on absent pong so strike " + str(node_dict[fwknop_gpg_pubkey]["strikeCount"]) + " -- recreating ws client but not flushing yet")
                        else:
                            print("stale based on absent pong and strike " + str(node_dict[fwknop_gpg_pubkey]["strikeCount"]) + " -- this node is out (archived)")
                            node_dict[fwknop_gpg_pubkey]["strikeCount"] = 0
                            v = node_dict[fwknop_gpg_pubkey]
                            ArchiveNode(fwknop_gpg_pubkey, v)
                            del node_dict[fwknop_gpg_pubkey]  # flush node
                            print("line 954 - deleted node")
                    elif (nodeValues["lastPing"] is None) or (nodeValues["lastPong"] is None):
                        await MyWebsocketClientWarehouse.client_dict[node_dict[fwknop_gpg_pubkey]["wsclient"]].destroy()
                        del node_dict[fwknop_gpg_pubkey]["wsclient"]  # flush "wsclient" entry
                        del node_dict[fwknop_gpg_pubkey]["lastPing"]
                        print("line 959 - destroyed ws - but it should get recreated in a moment")
                        if node_dict[fwknop_gpg_pubkey]["strikeCount"] < 3:
                            node_dict[fwknop_gpg_pubkey]["strikeCount"] += 1
                            print("stale based on a null value for lastPing or lastPong so strike " + str(node_dict[fwknop_gpg_pubkey]["strikeCount"]) + " -- recreating ws client but not flushing yet")
                        else:
                            print("stale based on a null value for lastPing or lastPong and strike " + str(node_dict[fwknop_gpg_pubkey]["strikeCount"]) + " -- this node is out (archived)")
                            node_dict[fwknop_gpg_pubkey]["strikeCount"] = 0
                            v = node_dict[fwknop_gpg_pubkey]
                            ArchiveNode(fwknop_gpg_pubkey, v)
                            del node_dict[fwknop_gpg_pubkey]  # flush node
                            print("line 969 - deleted node")
                    elif (nodeValues["lastPing"] - nodeValues["lastPong"]).total_seconds() > websocket_stale_threshold:
                        await MyWebsocketClientWarehouse.client_dict[node_dict[fwknop_gpg_pubkey]["wsclient"]].destroy()
                        del node_dict[fwknop_gpg_pubkey]["wsclient"]  # flush "wsclient" entry
                        del node_dict[fwknop_gpg_pubkey]["lastPing"]
                        print("line 974 - destroyed ws - but it should get recreated in a moment")
                        if node_dict[fwknop_gpg_pubkey]["strikeCount"] < 3:
                            node_dict[fwknop_gpg_pubkey]["strikeCount"] += 1
                            print("stale based on ws ping pong so strike " + str(node_dict[fwknop_gpg_pubkey]["strikeCount"]) + " -- recreating ws client but not flushing yet")
                        else:
                            print("stale based on ws ping pong and strike " + str(node_dict[fwknop_gpg_pubkey]["strikeCount"]) + " -- this node is out (archived)")
                            node_dict[fwknop_gpg_pubkey]["strikeCount"] = 0
                            v = node_dict[fwknop_gpg_pubkey]
                            ArchiveNode(fwknop_gpg_pubkey, v)
                            del node_dict[fwknop_gpg_pubkey]  # flush node
                            print("line 984 - deleted node")
                    elif (current_time - nodeValues["lastPong"]).total_seconds() > websocket_stale_threshold:
                        print("sending a ping")
                        try:
                            await MyWebsocketClientWarehouse.client_dict[node_dict[fwknop_gpg_pubkey]["wsclient"]].websocket.send("ping")
                            CommLog(current_time, "wss_ping_outgoing", "WSS", host_externalIP, nodeValues["internetIP"], "?")
                            node_dict[fwknop_gpg_pubkey]["lastPing"] = current_time
                            total_wspingpong_bytes_sent += 4
                        except Exception as e:
                            #print(e)
                            #print("assigning a lastPing anyway, despite exception")
                            node_dict[fwknop_gpg_pubkey]["lastPing"] = current_time
                        continue
                elif (fwknop_gpg_pubkey in gpg_lookup):
                    if gpg_lookup[fwknop_gpg_pubkey][0] != host_fwknopd_pubkey_name:    # note this only works if the pubkey names are very unique, which they will be
                        enoughSecondsElapsed = False
                        print("we are about to call OpenWebsocketClientConnectionToNode")
                        t1 = asyncio.create_task(OpenWebsocketClientConnectionToNode(gpg_lookup[fwknop_gpg_pubkey][0], nodeValues["internetIP"], host_externalIP, node_dict))
                        t2 = asyncio.create_task(asyncio.sleep(dict_of_intervals["ws_connection_check_interval"]/4))
                        if done or pending:
                            #print("   done: " + str(done))
                            #print("pending: " + str(pending))
                            for t in done:
                                if "sleep" in str(t):
                                    enoughSecondsElapsed = True
                            if enoughSecondsElapsed:
                                for t in pending:
                                    if "OpenWebsocketClientConnectionToNode" in str(t):
                                        print("it's been enough seconds and connection still pending, so cancelling task")
                                        t.cancel()
                                        await asyncio.sleep(0.5)
                                        done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
                        else:
                            print("nothing done or pending so beginning wait for t1 and t2")
                            done, pending = await asyncio.wait({t1,t2},return_when=asyncio.FIRST_COMPLETED)
                        print("we FINISHED CALLING OpenWebsocketClientConnectionToNode")
                        await asyncio.sleep(3.0)
                        if MyWebsocketClientWarehouse.client_dict[node_dict[fwknop_gpg_pubkey]["wsclient"]].websocket.open:
                            print("WSS connection is open so strikeCount gets set to 0")
                            node_dict[fwknop_gpg_pubkey]["strikeCount"] = 0   # the strike counter should only be reset if the WSS connection succeeded
                else:
                    print("we are doing nothing for some reason.")
                    #print(fwknop_gpg_pubkey)
                    #print(str(gpg_lookup))
                    #print("maybe the above will explain why we are doing nothing")
            #print(node_dict)
            #print()
        except Exception as e:
            print("exception in Maintain_fwknopd_ws_connections_stats")
            #time.sleep(10)
            print(e)
            #time.sleep(10)
            #raise type(e)(str(e) + ' happens at ').with_traceback(sys.exc_info()[2])
            #time.sleep(10)
            if "dictionary changed size" in str(e):
                print("actually no big deal the dict changed size is all")
                continue
            elif "dictionary keys changed" in str(e):
                print("actually no big deal the dict keys changed is all")
                continue
            elif "\'CustomWebsocketClient\' object has no attribute \'websocket\'" in str(e):
                print("actually no big deal one of the websocket clients failed is all")
                continue
            else:
                print("not sure what happened but lets try to keep going")
                #sys.exit()
                time.sleep(2)


async def Refresh_fwknopd(node_dict):      # similar to ConfigureFwknopd() but we assume more stuff is already initialized 
    global host_fwknopd_pubkey_name
    global host_fwknopd_pubkey
    global websocket_port
    global wireguard_port
    global gpg_home_dir
    global gpg_lookup
    global keyname_lookup
    global fwknopd_refresh_interval
    while True:
        print("Refresh_fwknopd")
        temp_fingerprint_dict = GetGPG_fingerprints()
        for keyname, fingerprint in temp_fingerprint_dict.items():
            if keyname != host_fwknopd_pubkey_name:
                subprocess.run(["sudo", "-E", "gpg", "--quiet", "--batch", "--delete-keys", fingerprint], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                cmd = 'sudo -E gpg --quiet --batch --delete-keys ' + fingerprint    #
                print("executed: " + cmd)                                   # here we are clearing out all the gpg keys EXCEPT for that of the host
        i = 1
        # recreate the .asc files for the current list of nodes
        for pubkey, nodeInfo in node_dict.items():
            filepath = f"{containingDir}/NodeMaintainer_scratch/reserved_temp_pubkey_filename" + str(i) + ".asc"
            with open(filepath, 'w') as outfile:
                outfile.write('-----BEGIN PGP PUBLIC KEY BLOCK-----\n')
                outfile.write('\n')
                outfile.write(pubkey + '\n')
                outfile.write('-----END PGP PUBLIC KEY BLOCK-----\n')
            i += 1
        # and also do this for the seed nodes, so that the door is always open to them
        # note that the seed node keys might include the host key. I think this is OK; I don't think the original name of the host key would get lost.
        infile = open(nodeFilePath, "r")
        seed_dict = json.load(infile, object_pairs_hook=as_datetime)
        infile.close()
        for pubkey, nodeInfo in seed_dict.items():
            if pubkey not in node_dict:
                filepath = f"{containingDir}/NodeMaintainer_scratch/reserved_temp_pubkey_filename" + str(i) + ".asc"
                with open(filepath, 'w') as outfile:
                    outfile.write('-----BEGIN PGP PUBLIC KEY BLOCK-----\n')
                    outfile.write('\n')
                    outfile.write(pubkey + '\n')
                    outfile.write('-----END PGP PUBLIC KEY BLOCK-----\n')
                i += 1
        cmd = f'sudo -E gpg --quiet --import {containingDir}/NodeMaintainer_scratch/*.asc'    # https://www.gnupg.org/documentation/manuals/gnupg.pdf
        subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("executed: " + str(cmd))
        temp_fingerprint_dict = GetGPG_fingerprints()
        for keyname, fingerprint in temp_fingerprint_dict.items():
            pubkey = GetGPG_pubkey(keyname)
            gpg_lookup[pubkey] = (keyname, fingerprint)
            keyname_lookup[keyname] = (pubkey, fingerprint)
        host_fwknopd_pubkey = keyname_lookup[host_fwknopd_pubkey_name][0]
        filepath = f"{containingDir}/NodeMaintainer_scratch/sign_script.sh"
        with open(filepath, 'w') as outfile:
            outfile.write("#!/bin/bash\n")
            for keyname, fingerprint in temp_fingerprint_dict.items():
                if keyname != host_fwknopd_pubkey_name:
                    try:
                        key_fp = keyname_lookup[keyname][1]
                    except:
                        key_fp = keyname
                    cmd = 'echo -e "y\nsave\n" | sudo -E gpg --command-fd 0 --edit-key ' + key_fp + ' sign'
                    c2 = cmd.encode('unicode_escape').decode()
                    outfile.write(c2)
                    outfile.write("\n")
        cmd = "chmod 755 " + filepath
        os.system(cmd)
        os.system(filepath)
        print("signed all the gpg keys (except for the host's key) with the host's key")   # https://raymii.org/s/articles/GPG_noninteractive_batch_sign_trust_and_send_gnupg_keys.html
        GPG_REMOTE_ID = ""
        for keyname, fingerprint in temp_fingerprint_dict.items():
            if keyname != host_fwknopd_pubkey_name:
                GPG_REMOTE_ID = GPG_REMOTE_ID + keyname + "," + fingerprint[-8:] + ","
        if len(GPG_REMOTE_ID) > 0:
            GPG_REMOTE_ID = GPG_REMOTE_ID[:-1]
        with open(f"{containingDir}/NodeMaintainer_scratch/fwknop_access.conf", 'w') as outfile:    # create new file fwknop_access.conf with the contents:
            outfile.write("#stanza\n")
            outfile.write("SOURCE      ANY\n")
            t = "OPEN_PORTS      tcp/" + str(websocket_port) + ", udp/" + str(wireguard_port) + "\n"
            outfile.write(t)
            outfile.write("FW_ACCESS_TIMEOUT       30\n")
            outfile.write("REQUIRE_SOURCE_ADDRESS      Y\n")
            outfile.write("GPG_ALLOW_NO_PW         Y\n")
            t = "GPG_DECRYPT_ID      " + str(host_fwknopd_pubkey_name) + "\n"
            outfile.write(t)
            t = "GPG_HOME_DIR        " + str(gpg_home_dir) + "\n"
            outfile.write(t)
            outfile.write("GPG_REQUIRE_SIG                    Y\n")
            outfile.write("GPG_IGNORE_SIG_VERIFY_ERROR        N\n")
            t = "GPG_REMOTE_ID       " + GPG_REMOTE_ID + "\n"
            outfile.write(t)
            outfile.write("#end stanza\n")
        os.system(f"sudo -E cp {containingDir}/NodeMaintainer_scratch/fwknop_access.conf /etc/fwknop/access.conf")
        os.system("sudo -E chmod 0600 /etc/fwknop/access.conf")
        cmd = "sudo service fwknop-server restart"
        print("Waiting 5 seconds to let fwknopd restart...")
        os.system(cmd)
        time.sleep(5)
        print("Done waiting.")
        await asyncio.sleep(fwknopd_refresh_interval)


async def DoThePings(input):
    global total_icmp_bytes_sent
    global continuous_ping_output
    parallel_ping_procs = dict()
    send_times = dict()
    for k, v in input.items():
        cmd, byteCount, current_time = v
        parallel_ping_procs[k] = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        send_times[k] = current_time
        total_icmp_bytes_sent += byteCount
    await asyncio.sleep(15)
    output = dict()
    continuous_ping_output = dict()
    for k, p in parallel_ping_procs.items():
        out, err = p.communicate()
        #print("DoThePings raw result of ping: " + str(out))
        p = re.compile(r'\s(\d{1,3})%\spacket\sloss')
        m2 = p.search(str(out))
        if m2:
            pctPacketLoss = int(m2.group(1))
            #print(str(pctPacketLoss))
            if (pctPacketLoss < 50):
                if k in send_times:
                    current_time = await GetUTC_timestamp_as_datetime()
                    output[k] = (send_times[k], current_time)
                    continuous_ping_output[k] = (send_times[k], current_time)
            elif pctPacketLoss >= 50:
                if k in send_times:
                    output[k] = (send_times[k], None)
                    continuous_ping_output[k] = (send_times[k], None)
        elif not m2:
            if k in send_times:
                output[k] = (send_times[k], None)
                continuous_ping_output[k] = (send_times[k], None)
    #print("DoThePings here is the output:")
    #print(output)
    return output


async def Maintain_wireguard_stats(node_dict):
    global wireguard_refresh_interval
    global wireguard_stale_threshold
    global host_fwknopd_pubkey
    while True:
        try:
            #print("Maintain_wireguard_stats id(node_dict)= " + str(id(node_dict)))
            await asyncio.sleep(wireguard_refresh_interval)
            input = dict()
            for fwknop_gpg_pubkey, nodeValues in node_dict.items():
                #print("Maintain_wireguard_stats: iterating through node_dict")
                current_time = await GetUTC_timestamp_as_datetime()
                if (host_fwknopd_pubkey != fwknop_gpg_pubkey) and ("wg_ip" in nodeValues) and nodeValues["wg_ip"]:
                    #print("Maintain_wireguard_stats: at current item, node is not self and wg_ip is defined")
                    if "last_wg_icmp_receive_timestamp" not in nodeValues:
                        #print("Maintain_wireguard_stats: at current item, no ICMP response recvd so sending ping")
                        cmd = ["ping", "-w", "10", nodeValues["wg_ip"]]
                        input[fwknop_gpg_pubkey] = (cmd, 10*64, current_time)  # each icmp packet is 64 bytes and we sent 10 packets
                    elif ("last_wg_icmp_receive_timestamp" in nodeValues) and (nodeValues["last_wg_icmp_receive_timestamp"]):
                        #print("Maintain_wireguard_stats: at current item, an ICMP response WAS received")
                        if (current_time - nodeValues["last_wg_icmp_receive_timestamp"]).total_seconds() > wireguard_stale_threshold:
                            #print("icmp last received was a while ago so sending ping")
                            cmd = ["ping", "-w", "10", nodeValues["wg_ip"]]
                            input[fwknop_gpg_pubkey] = (cmd, 10*64, current_time)  # each icmp packet is 64 bytes and we sent 10 packets
                        if ("last_wg_icmp_send_timestamp" in nodeValues) and (nodeValues["last_wg_icmp_send_timestamp"] - nodeValues["last_wg_icmp_receive_timestamp"]).total_seconds() > wireguard_stale_threshold:
                            #print("icmp last sent is way after last recvd so flushing")
                            await MyWebsocketClientWarehouse.client_dict[node_dict[fwknop_gpg_pubkey]["wsclient"]].destroy()
                            v = node_dict[fwknop_gpg_pubkey]
                            ArchiveNode(fwknop_gpg_pubkey, v)
                            del node_dict[fwknop_gpg_pubkey]  # flush node
                            #print("line 1007 - deleted node")
                            #print("Maintain_wireguard_stats id(node_dict)= " + str(id(node_dict)))
            output = await DoThePings(input)
        except Exception as e:
            print("exception in Maintain_wireguard_stats")
            print(e)
            if "dictionary changed size" in str(e):
                print("actually no big deal the dict changed size is all")
                continue
            elif "dictionary keys changed" in str(e):
                print("actually no big deal the dict keys changed is all")
                continue
            else:
                print("halting")
                sys.exit()


async def BroadcastHeartbeat(node_dict):
    global nodeSampleSize
    global host_externalIP
    global total_gossip_bytes_sent
    while True:
        try:
            #print("BroadcastHeartbeat")
            # send heartbeat to nodeSampleSize random nodes over websocket
            population = list(node_dict.keys())
            if nodeSampleSize > len(population):
                nodeSampleSize = len(population)
            targetNodes = random.sample(population, int(nodeSampleSize))
            #print(str(targetNodes))
            for k in targetNodes:
                if (k in node_dict) and ("wsclient" in node_dict[k]):
                    try:
                        heartbeatContent = dict()
                        heartbeatContent["internetIP"] = host_externalIP
                        heartbeatContent["fwknop_gpg_pubkey"] = host_fwknopd_pubkey
                        heartbeatContent["lastPing"] = await GetUTC_timestamp_as_datetime()
                        heartbeatContent["wg_ip"] = myWireguardIP
                        heartbeatContent["wg_pubkey"] = myWireguardPublicKey
                        heartbeatContent["strikeCount"] = 0
                        heartbeatContent_s = json.dumps(heartbeatContent, cls=TimestampEncoder)
                        await MyWebsocketClientWarehouse.client_dict[node_dict[k]["wsclient"]].websocket.send(heartbeatContent_s)
                        #print()
                        #print(heartbeatContent_s)
                        #print()
                        CommLog(GetUTC_timestamp_as_datetime_synchronous(), "wss_heartbeat_outgoing", "WSS", host_externalIP, node_dict[k]["internetIP"], "?")
                        total_gossip_bytes_sent += len(heartbeatContent_s)   # seems safe to assume utf8 will in this scenario almost always be 1 byte per character
                    except Exception as e:
                        print("BroadcastHeartbeat failed to send heartbeat to one of the nodes:")
                        exception_s = str(e)
                        exception_s = exception_s.replace('\n', ' ').replace('\r', ' ')
                        m = "WSS " + exception_s
                        print(exception_s)
                        CommLog(GetUTC_timestamp_as_datetime_synchronous(), "wss_heartbeat_outgoing_ERR", m, host_externalIP, "?", "?")
                        await asyncio.sleep(2)
            await AsyncResponsiveSleep("heartbeatInterval")
        except Exception as e:
            print("exception in BroadcastHeartbeat")
            print(e)


async def AsyncResponsiveSleep(k):
    global dict_of_intervals
    secondsElapsed = 0
    secondsAlotted = dict_of_intervals[k]
    while secondsElapsed < secondsAlotted:
        newSecondsAlotted = dict_of_intervals[k]
        if newSecondsAlotted != secondsAlotted:
            print("for " + k + " revising secondsAlotted to: " + str(newSecondsAlotted))
            secondsAlotted = newSecondsAlotted
        await asyncio.sleep(1)
        secondsElapsed += 1
    print("for " + k + " finished async sleeping after this many seconds: " + str(secondsElapsed))


def FindByteCountsFromXminAgo(current_time, historical_byteAndTimestampStats, x):
    local_byteAndTimestampStats = deque(historical_byteAndTimestampStats)
    #print(str(x))
    xMinuteAgo = current_time - timedelta(minutes=x)
    #print(current_time.strftime("%Y-%m-%d %H:%M:%S.%f"))
    #print(xMinuteAgo.strftime("%Y-%m-%d %H:%M:%S.%f"))
    #print()
    #time.sleep(1)
    temp = deque()
    cursor = local_byteAndTimestampStats.pop()
    #print(str(cursor))
    while cursor[0] > xMinuteAgo:
        #print("yes cursor[0] > xMinuteAgo")
        ts, wspingpong_bytes_Xmin_ago, icmp_bytes_Xmin_ago, gossip_bytes_Xmin_ago = cursor
        temp.append(cursor)
        if len(local_byteAndTimestampStats)>0:
            cursor = local_byteAndTimestampStats.pop()
        else:
            cursor = None
            break
    #print("after while loop " + str(cursor))   
    while len(temp)>0:
        local_byteAndTimestampStats.append(temp.pop())
    exactTimeDelta = (current_time - ts).total_seconds()
    #print("exactTimeDelta  " + str(exactTimeDelta))
    return wspingpong_bytes_Xmin_ago, icmp_bytes_Xmin_ago, gossip_bytes_Xmin_ago, exactTimeDelta


async def RegulateBandwidth():
    global nodeSampleSize
    global websocket_stale_threshold
    global wireguard_stale_threshold
    global maxHops
    global dict_of_intervals
    global target_wspingpong_bandwidth
    global target_icmp_bandwidth
    global target_gossip_bandwidth

    global historical_byteAndTimestampStats
    global total_wspingpong_bytes_sent
    global total_icmp_bytes_sent
    global total_gossip_bytes_sent

    global actual_wspingpong_bandwidth
    global actual_icmp_bandwidth
    global actual_gossip_bandwidth

    global ws_dampenFactor
    global ws_undampenFactor
    global icmp_dampenFactor
    global icmp_undampenFactor
    global gossip_dampenFactor
    global gossip_undampenFactor
    global nodeIncrement
    global nodeDecrement

    while True:
        #print("RegulateBandwidth ")
        current_time = await GetUTC_timestamp_as_datetime()
        instantaneous_byteAndTimestamp = (current_time, total_wspingpong_bytes_sent, total_icmp_bytes_sent, total_gossip_bytes_sent)
        historical_byteAndTimestampStats.append(instantaneous_byteAndTimestamp)
        # let's try 8 seconds (0.133 minutes) ago
        wspingpong_bytes_Xmin_ago, icmp_bytes_Xmin_ago, gossip_bytes_Xmin_ago, exactTimeDelta = FindByteCountsFromXminAgo(current_time, historical_byteAndTimestampStats, 0.133)
        #print("exactTimeDelta: " + str(exactTimeDelta))
        #print(str([wspingpong_bytes_Xmin_ago, icmp_bytes_Xmin_ago, gossip_bytes_Xmin_ago, exactTimeDelta]))
        if exactTimeDelta and wspingpong_bytes_Xmin_ago and icmp_bytes_Xmin_ago and gossip_bytes_Xmin_ago:
            #print(str([wspingpong_bytes_Xmin_ago, icmp_bytes_Xmin_ago, gossip_bytes_Xmin_ago, exactTimeDelta]))
            actual_wspingpong_bandwidth = (total_wspingpong_bytes_sent - wspingpong_bytes_Xmin_ago)/exactTimeDelta
            actual_icmp_bandwidth = (total_icmp_bytes_sent - icmp_bytes_Xmin_ago)/exactTimeDelta
            actual_gossip_bandwidth = (total_gossip_bytes_sent - gossip_bytes_Xmin_ago)/exactTimeDelta
            actual_wspingpong_bandwidth /= 1000
            actual_icmp_bandwidth /= 1000
            actual_gossip_bandwidth /= 1000
            #print(str([actual_wspingpong_bandwidth, actual_icmp_bandwidth, actual_gossip_bandwidth]))

            if actual_wspingpong_bandwidth/target_wspingpong_bandwidth > 1.05:
                websocket_stale_threshold *= ws_dampenFactor
                dict_of_intervals["ws_connection_check_interval"] *= ws_dampenFactor
            elif actual_wspingpong_bandwidth/target_wspingpong_bandwidth < 0.2:
                websocket_stale_threshold /= ws_undampenFactor
                dict_of_intervals["ws_connection_check_interval"] /= ws_undampenFactor
            if dict_of_intervals["ws_connection_check_interval"] < 5:
                dict_of_intervals["ws_connection_check_interval"] = 5

            if dict_of_intervals["ws_connection_check_interval"] > 200:
                dict_of_intervals["ws_connection_check_interval"] = 200

            if websocket_stale_threshold < 4*dict_of_intervals["ws_connection_check_interval"]:
                websocket_stale_threshold = 4*dict_of_intervals["ws_connection_check_interval"]

            if actual_icmp_bandwidth/target_icmp_bandwidth > 1.05:
                wireguard_stale_threshold *= icmp_dampenFactor
            elif actual_icmp_bandwidth/target_icmp_bandwidth < 0.2:
                wireguard_stale_threshold /= icmp_undampenFactor
            if wireguard_stale_threshold < 4*dict_of_intervals["ws_connection_check_interval"]:
                wireguard_stale_threshold = 4*dict_of_intervals["ws_connection_check_interval"]

            if actual_gossip_bandwidth/target_gossip_bandwidth > 1.05:
                nodeSampleSize -= nodeDecrement
                dict_of_intervals["heartbeatInterval"] = dict_of_intervals["heartbeatInterval"]*gossip_dampenFactor
                maxHops -= nodeDecrement
            elif actual_gossip_bandwidth/target_gossip_bandwidth < 0.1:
                nodeSampleSize += nodeIncrement
                dict_of_intervals["heartbeatInterval"] = dict_of_intervals["heartbeatInterval"]/gossip_undampenFactor
                maxHops += nodeIncrement
            if nodeSampleSize < 1:
                nodeSampleSize = 1
            if dict_of_intervals["heartbeatInterval"] < 4:
                dict_of_intervals["heartbeatInterval"] = 4
            elif dict_of_intervals["heartbeatInterval"] > 300:
                dict_of_intervals["heartbeatInterval"] = 300
            if maxHops < 1:
                maxHops = 1
            if maxHops > 6:
                maxHops = 6
            if nodeSampleSize < 1:
                nodeSampleSize = 1
            if nodeSampleSize > min(5, len(node_dict.keys())):
                nodeSampleSize = min(5, len(node_dict.keys()))

        # now let's also try 2 mins ago
        wspingpong_bytes_20min_ago, icmp_bytes_20min_ago, gossip_bytes_20min_ago, exactTimeDelta20 = FindByteCountsFromXminAgo(current_time, historical_byteAndTimestampStats, 2)
        #print("exactTimeDelta20: " + str(exactTimeDelta20))
        #time.sleep(2)
        if exactTimeDelta20 and wspingpong_bytes_20min_ago and icmp_bytes_20min_ago and gossip_bytes_20min_ago:
            temp_wspingpong_bandwidth = (total_wspingpong_bytes_sent - wspingpong_bytes_20min_ago)/exactTimeDelta20
            temp_icmp_bandwidth = (total_icmp_bytes_sent - icmp_bytes_20min_ago)/exactTimeDelta20
            temp_gossip_bandwidth = (total_gossip_bytes_sent - gossip_bytes_20min_ago)/exactTimeDelta20
            temp_wspingpong_bandwidth /= 1000
            temp_icmp_bandwidth /= 1000
            temp_gossip_bandwidth /= 1000
            global bigwindow_wspingpong_bandwidth
            bigwindow_wspingpong_bandwidth = temp_wspingpong_bandwidth
            global bigwindow_icmp_bandwidth
            bigwindow_icmp_bandwidth = temp_icmp_bandwidth
            global bigwindow_gossip_bandwidth
            bigwindow_gossip_bandwidth = temp_gossip_bandwidth
            #print()
            #print("    ws dampen, undampen: " + "{:.2f}".format(ws_dampenFactor) + "  " + "{:.2f}".format(ws_undampenFactor))
            if (temp_wspingpong_bandwidth/target_wspingpong_bandwidth) > 1.05:
                ws_dampenFactor *= ((temp_wspingpong_bandwidth/target_wspingpong_bandwidth) - 0.3)
                ws_undampenFactor /= ((temp_wspingpong_bandwidth/target_wspingpong_bandwidth) - 0.3)
                #print("increased ws_dampenFactor")
            elif (temp_wspingpong_bandwidth/target_wspingpong_bandwidth) < 0.2:
                ws_undampenFactor *= ((0.8 - (temp_wspingpong_bandwidth/target_wspingpong_bandwidth)) + 1)
                ws_dampenFactor /= ((0.8 - (temp_wspingpong_bandwidth/target_wspingpong_bandwidth)) + 1)
                #print("increased ws_undampenFactor")
            #print(str(temp_wspingpong_bandwidth))
            #print(str(target_wspingpong_bandwidth))
            #print(str(temp_wspingpong_bandwidth/target_wspingpong_bandwidth))
            #print("    ws dampen, undampen: " + "{:.2f}".format(ws_dampenFactor) + "  " + "{:.2f}".format(ws_undampenFactor))
            #print()

            #print("  icmp dampen, undampen: " + "{:.2f}".format(icmp_dampenFactor) + "  " + "{:.2f}".format(icmp_undampenFactor))
            if (temp_icmp_bandwidth/target_icmp_bandwidth) > 1.05:
                icmp_dampenFactor *= ((temp_icmp_bandwidth/target_icmp_bandwidth) - 0.3)
                icmp_undampenFactor /= ((temp_icmp_bandwidth/target_icmp_bandwidth) - 0.3)
                #print("increased icmp_dampenFactor")
            elif (temp_icmp_bandwidth/target_icmp_bandwidth) < 0.2:
                icmp_undampenFactor *= ((0.8 - (temp_icmp_bandwidth/target_icmp_bandwidth)) + 1)
                icmp_dampenFactor /= ((0.8 - (temp_icmp_bandwidth/target_icmp_bandwidth)) + 1)
                #print("increased icmp_undampenFactor")
            #print(str(temp_icmp_bandwidth))
            #print(str(target_icmp_bandwidth))
            #print(str(temp_icmp_bandwidth/target_icmp_bandwidth))
            #print("  icmp dampen, undampen: " + "{:.2f}".format(icmp_dampenFactor) + "  " + "{:.2f}".format(icmp_undampenFactor))
            #print()

            #print("gossip dampen, undampen: " + "{:.2f}".format(gossip_dampenFactor) + "  " + "{:.2f}".format(gossip_undampenFactor))
            if (temp_gossip_bandwidth/target_gossip_bandwidth) > 1.05:
                gossip_dampenFactor *= ((temp_gossip_bandwidth/target_gossip_bandwidth) - 0.3)
                nodeDecrement *= ((temp_gossip_bandwidth/target_gossip_bandwidth) - 0.3)
                gossip_undampenFactor /= ((temp_gossip_bandwidth/target_gossip_bandwidth) - 0.3)
                nodeIncrement /= ((temp_gossip_bandwidth/target_gossip_bandwidth) - 0.3)
                #print("increased gossip_dampenFactor")
            elif (temp_gossip_bandwidth/target_gossip_bandwidth) < 0.2:
                gossip_undampenFactor *= ((0.8 - (temp_gossip_bandwidth/target_gossip_bandwidth)) + 1)
                nodeIncrement *= ((0.8 - (temp_gossip_bandwidth/target_gossip_bandwidth)) + 1)
                gossip_dampenFactor /= ((0.8 - (temp_gossip_bandwidth/target_gossip_bandwidth)) + 1)
                nodeDecrement /= ((0.8 - (temp_gossip_bandwidth/target_gossip_bandwidth)) + 1)
                #print("increased gossip_undampenFactor")
            #print(str(temp_gossip_bandwidth))
            #print(str(target_gossip_bandwidth))
            #print(str(temp_gossip_bandwidth/target_gossip_bandwidth))
            #print("gossip dampen, undampen: " + "{:.2f}".format(gossip_dampenFactor) + "  " + "{:.2f}".format(gossip_undampenFactor))
            #print()
            if ws_dampenFactor > 4:
                ws_dampenFactor = 4
            if ws_undampenFactor > 2:
                ws_undampenFactor = 2
            if icmp_dampenFactor > 4:
                icmp_dampenFactor = 4
            if icmp_undampenFactor > 2:
                icmp_undampenFactor = 2
            if gossip_dampenFactor > 4:
                gossip_dampenFactor = 4
            if gossip_undampenFactor > 2:
                gossip_undampenFactor = 2
            if nodeIncrement > 3:
                nodeIncrement = 3
            if nodeDecrement > 5:
                nodeDecrement = 5

            if ws_dampenFactor < 1.01:
                ws_dampenFactor = 1.01
            if ws_undampenFactor < 1.01:
                ws_undampenFactor = 1.01
            if icmp_dampenFactor < 1.01:
                icmp_dampenFactor = 1.01
            if icmp_undampenFactor < 1.01:
                icmp_undampenFactor = 1.01
            if gossip_dampenFactor < 1.01:
                gossip_dampenFactor = 1.01
            if gossip_undampenFactor < 1.01:
                gossip_undampenFactor = 1.01
            if nodeIncrement < 0.001:
                nodeIncrement = 0.001
            if nodeDecrement < 0.001:
                nodeDecrement = 0.001

        while len(historical_byteAndTimestampStats) > 1000:
            historical_byteAndTimestampStats.popleft()
        await asyncio.sleep(bandwidth_regulator_interval)


def clear():
    # For Windows
    if name == 'nt':
        _ = system('cls')
    # For Mac and Linux(here, os.name is 'posix')
    else:
        _ = system('clear')


async def pull_wg_ping_results_into_node_dict(node_dict):
    while True:
        await asyncio.sleep(1)
        global continuous_ping_output
        try:
            for k, v in continuous_ping_output.items():
                sendtime, recvtime = v
                if k in node_dict:
                    node_dict[k]["last_wg_icmp_send_timestamp"] = sendtime
                    node_dict[k]["last_wg_icmp_receive_timestamp"] = recvtime
        except Exception as e:
            print("exception in pull_wg_ping_results_into_node_dict")
            print(e)


async def display_node_dict(node_dict):
    global healthyOverall
    global actual_wspingpong_bandwidth
    global actual_icmp_bandwidth
    global actual_gossip_bandwidth
    global bigwindow_wspingpong_bandwidth
    global bigwindow_icmp_bandwidth
    global bigwindow_gossip_bandwidth

    global websocket_stale_threshold
    global wireguard_stale_threshold
    global nodeSampleSize
    global dict_of_intervals

    global continuous_ping_output

    while True:
        #clear()
        numNonarchivedNodes = 0
        numNonarchivedNodesWithLastPongWS = 0
        numNonarchivedNodesWithICMPreceived = 0
        keys = node_dict.keys()
        keys_s = sorted(keys)
        #print("display_node_dict id(node_dict)= " + str(id(node_dict)))
        print("..key   internetIP   lastPingWS   lastPongWS   ..wgkey  wg_ip  ICMPsent   ICMPrecvd")
        for k in keys_s:
            numNonarchivedNodes += 1
            k_short = "..." + str(k[-5:])
            wk_short = "None"
            vals = node_dict[k]
            lPing = "None"
            lPong = "None"
            iip = "None"
            wgip = "None"
            icmpR = "None"
            icmpS = "None"
            try:
                lPing = vals["lastPing"].strftime("%Y-%m-%d %H:%M:%S.%f")
            except:
                msg = "display_node_dict missing lPing"
                #print(msg)

            try:
                lPong = vals["lastPong"].strftime("%Y-%m-%d %H:%M:%S.%f")
                numNonarchivedNodesWithLastPongWS += 1
            except:
                msg = "display_node_dict missing lPong"
                #print(msg)

            try:
                iip = vals["internetIP"]
            except:
                msg = "display_node_dict missing internetIP"
                #print(msg)

            try:
                wk_short = "..." + vals["wg_pubkey"][-5:]
            except:
                msg = "display_node_dict missing wg_pubkey"
                #print(msg)

            try:
                wgip = vals["wg_ip"]
            except:
                msg = "display_node_dict missing wg_ip"
                #print(msg)

            try:
                icmpS = vals["last_wg_icmp_send_timestamp"].strftime("%Y-%m-%d %H:%M:%S.%f")
            except Exception as e:
                msg = "display_node_dict missing icmpS"
                #print(msg)
                #print(e)

            try:
                icmpR = vals["last_wg_icmp_receive_timestamp"].strftime("%Y-%m-%d %H:%M:%S.%f")
                numNonarchivedNodesWithICMPreceived += 1
            except Exception as e:
                msg = "display_node_dict missing icmpR"
                #print(msg)
                #print(e)

            print(k_short + "  " + iip + "  " + lPing + "  " + lPong + "  " + wk_short + "  " + wgip + "  " + icmpS + "  " + icmpR)
        print()
        print()
        print("outbound data (KB/s)")
        print("WSping     ICMP    Gossip")
        print("{:.2f}".format(actual_wspingpong_bandwidth) + "       " + "{:.2f}".format(actual_icmp_bandwidth) + "     " + "{:.2f}".format(actual_gossip_bandwidth))
        print()
        print("outbound data longer window (KB/s)")
        print("WSping     ICMP    Gossip")
        print("{:.2f}".format(bigwindow_wspingpong_bandwidth) + "       " + "{:.2f}".format(bigwindow_icmp_bandwidth) + "     " + "{:.2f}".format(bigwindow_gossip_bandwidth))
        print()
        print("free parameters")
        print("websocket_stale_threshold (s)      wireguard_stale_threshold (s)      nodeSampleSize (#)       heartbeatInterval (s)")
        print("                     " + "{:.2f}".format(websocket_stale_threshold) + "                       " + "{:.2f}".format(wireguard_stale_threshold) + "                       " + str(nodeSampleSize) + "                       " + "{:.2f}".format(dict_of_intervals["heartbeatInterval"]))
        print()
        print("ws_connection_check_interval " + "{:.2f}".format(dict_of_intervals["ws_connection_check_interval"]))
        print()
        print("    ws dampen, undampen: " + "{:.2f}".format(ws_dampenFactor) + "  " + "{:.2f}".format(ws_undampenFactor))
        print("  icmp dampen, undampen: " + "{:.2f}".format(icmp_dampenFactor) + "  " + "{:.2f}".format(icmp_undampenFactor))
        print("gossip dampen, undampen: " + "{:.2f}".format(gossip_dampenFactor) + "  " + "{:.2f}".format(gossip_undampenFactor))
        print("nodeDecrement, nodeIncrement: " + "{:.3f}".format(nodeDecrement) + "  " + "{:.3f}".format(nodeIncrement))
        print()
        print("wireguardStartCount " + str(wireguardStartCount))
        print()
        print("healthy overall? " + str(healthyOverall))
        print()
        #print("continuous_ping_output")
        icmpsend_ts_mismatch_flag = False
        icmprecv_ts_mismatch_flag = False
        for k, v in continuous_ping_output.items():
            #print(str(v))
            if k not in node_dict:
                icmpsend_ts_mismatch_flag = True
                icmprecv_ts_mismatch_flag = True
            elif ("last_wg_icmp_send_timestamp" not in node_dict[k]) or ("last_wg_icmp_receive_timestamp" not in node_dict[k]):
                if "last_wg_icmp_send_timestamp" not in node_dict[k]:
                    icmpsend_ts_mismatch_flag = True
                if "last_wg_icmp_receive_timestamp" not in node_dict[k]:
                    icmprecv_ts_mismatch_flag = True
            else:
                icmpsend_ts_mismatch_flag = icmpsend_ts_mismatch_flag or (node_dict[k]["last_wg_icmp_send_timestamp"] != v[0])
                icmprecv_ts_mismatch_flag = icmprecv_ts_mismatch_flag or (node_dict[k]["last_wg_icmp_receive_timestamp"] != v[1])
        print()
        if icmpsend_ts_mismatch_flag:
            print("out-of-sync: timestamp for icmp sent")
        if icmprecv_ts_mismatch_flag:
            print("out-of-sync: timestamp for icmp received")

        proc = psutil.Process()
        numOpenFiles = proc.open_files()
        print("num open files for this proc: " + str(numOpenFiles))

        sysload1min, sysload5min, sysload15min = os.getloadavg()
        memTotal_MB = int(psutil.virtual_memory().total/1000000)
        memAvailable_MB = int(psutil.virtual_memory().available/1000000)

        entry_timestamp_dt = await GetUTC_timestamp_as_datetime() 
        entry_timestamp = entry_timestamp_dt.strftime("%Y-%m-%d %H:%M:%S.%f")
        line = entry_timestamp + "," + str(numNonarchivedNodes) + "," +\
            str(numNonarchivedNodesWithLastPongWS) + "," +\
            str(numNonarchivedNodesWithICMPreceived) + "," +\
            "{:.2f}".format(actual_gossip_bandwidth) + "," +\
            "{:.2f}".format(bigwindow_gossip_bandwidth) + "," +\
            "{:.2f}".format(gossip_dampenFactor) + "," +\
            "{:.2f}".format(gossip_undampenFactor) + "," +\
            "{:.3f}".format(nodeDecrement) + "," +\
            "{:.3f}".format(nodeIncrement) + "," +\
            str(nodeSampleSize) + "," +\
            "{:.2f}".format(websocket_stale_threshold) + "," +\
            "{:.2f}".format(wireguard_stale_threshold) + "," +\
            "{:.2f}".format(dict_of_intervals["heartbeatInterval"]) + "," +\
            str(wireguardStartCount) + "," +\
            "{:.3f}".format(sysload1min) + "," +\
            "{:.3f}".format(memTotal_MB) + "," +\
            "{:.3f}".format(memAvailable_MB) + "\n"
        outfile = open(meshStatsLogFile, "a")
        outfile.write(line)
        outfile.close()
        await asyncio.sleep(10)
        print()


def Update_node_dict_extern(source_dict, node_dict=node_dict):
    global archived_nodes_dict
    #print("nodeInfo INSIDE: " + str(source_dict))
    try:
        if "fwknop_gpg_pubkey" in source_dict:
            fwknop_gpg_pubkey = source_dict["fwknop_gpg_pubkey"]
            if fwknop_gpg_pubkey in node_dict:
                if ("lastPing" in node_dict[fwknop_gpg_pubkey]) and ("lastPing" in source_dict) and node_dict[fwknop_gpg_pubkey]["lastPing"] and source_dict["lastPing"]:
                    if source_dict["lastPing"] > node_dict[fwknop_gpg_pubkey]["lastPing"]:
                        source_dict["lastPong"] = GetUTC_timestamp_as_datetime_synchronous()
                        if "wsclient" in node_dict[fwknop_gpg_pubkey]:
                            t = MyWebsocketClientWarehouse.client_dict[node_dict[fwknop_gpg_pubkey]["wsclient"]]
                            if hasattr(t, 'websocket'):
                                if t.websocket.open:
                                    source_dict["wsclient"] = node_dict[fwknop_gpg_pubkey]["wsclient"]
                        node_dict[fwknop_gpg_pubkey] = dict(source_dict)
            else:
                node_dict[fwknop_gpg_pubkey] = dict(source_dict)

            if fwknop_gpg_pubkey in archived_nodes_dict:
                del archived_nodes_dict[fwknop_gpg_pubkey]
    except Exception as e:
        print("exception in Update_node_dict_extern")
        print(e)
        time.sleep(10)


async def ForwardInfoToNRandomNodes_extern(info, n, node_dict=node_dict):
    global total_gossip_bytes_sent
    global actual_gossip_bandwidth
    global target_gossip_bandwidth
    info_local_copy = dict(info)
    if "wsclient" in info_local_copy:
        del info_local_copy["wsclient"]
    #use ws connection, as ws client, to forward the info to n random nodes
    info_s = json.dumps(info_local_copy, cls=TimestampEncoder)
    population_temp = list(node_dict.keys())
    n_adj = int(n)
    if n > len(population_temp):
        n_adj = len(population_temp)
    #print("population_temp: " + str(population_temp))
    #print("n_adj: " + str(n_adj))
    targetNodes = random.sample(population_temp, n_adj)
    for k in targetNodes:
        if actual_gossip_bandwidth < 1.3*target_gossip_bandwidth:  # a circuit-breaker
            #print("inside ForwardInfoToNRandomNodes_extern and will forward")
            try:
                if "wsclient" in node_dict[k]:
                    await MyWebsocketClientWarehouse.client_dict[node_dict[k]["wsclient"]].websocket.send(info_s)
                    total_gossip_bytes_sent += len(info_s)
                    CommLog(GetUTC_timestamp_as_datetime_synchronous(), "wss_heartbeat_fwd", "WSS", host_externalIP, node_dict[k]["internetIP"], "?")
            except:
                #print("failed to forward heartbeat to one of the nodes")
                CommLog(GetUTC_timestamp_as_datetime_synchronous(), "wss_heartbeat_fwd_ERR", "WSS", host_externalIP, "?", "?")


class MyServerProtocol(WebSocketServerProtocol):
    def onConnect(self, request):
        #print("Client connecting: {0}".format(request.peer))
        CommLog(GetUTC_timestamp_as_datetime_synchronous(), "wss_handshake_incoming", "WSS", request.peer, host_externalIP, "?")

    def onOpen(self):
        print("[server] WebSocket connection open.")
        app_log.info("[server] WebSocket connection open.")

    #message format:
    #'ping'
    #or
    #'{"internetIP": "73.74.75.76", "wg_pubkey": "ghjdsfrsf787ytf7847f78wgbf6w4gr6784g6f4", "wg_ip": "10.1.2.3", "hop": 1}'
    async def onMessage(self, payload, isBinary):
        global total_wspingpong_bytes_sent
        global actual_gossip_bandwidth
        global target_gossip_bandwidth
        if isBinary:
            #print("Binary message received: {0} bytes".format(len(payload)))
            CommLog(GetUTC_timestamp_as_datetime_synchronous(), "wss_binary_incoming", "WSS", "?", host_externalIP, websocket_port)
        else:
            #print("(server) Text message received: {0}".format(payload.decode('utf8')))
            #await asyncio.sleep(2)
            if payload.decode('utf8') == "ping":
                try:
                    CommLog(GetUTC_timestamp_as_datetime_synchronous(), "wss_ping_incoming", "WSS", "?", host_externalIP, websocket_port)
                    self.sendMessage("pong".encode('utf8'), False)
                    #print("received ping and sent pong")
                    total_wspingpong_bytes_sent += 4
                    CommLog(GetUTC_timestamp_as_datetime_synchronous(), "wss_pong_outgoing", "WSS", host_externalIP, "?", "?")
                except Exception as e:
                    print("failed to send pong")
                    print(e)
                    CommLog(GetUTC_timestamp_as_datetime_synchronous(), "wss_pong_outgoing_ERR", "WSS", host_externalIP, "?", "?")
            elif payload.decode('utf8')[0] == "{":
                message = payload.decode('utf8')
                nodeInfo = json.loads(message, object_pairs_hook=as_datetime)
                #print("nodeInfo OUTSIDE: " + str(nodeInfo))
                snapshot_nodeInfo = dict(nodeInfo)
                temp_descr = "wss_heartbeat_incoming"
                if "hop" in snapshot_nodeInfo:
                    temp_descr = temp_descr + "_hop_" + str(snapshot_nodeInfo["hop"])
                #print("snapshot_nodeInfo: " + str(snapshot_nodeInfo))
                Update_node_dict_extern(source_dict=snapshot_nodeInfo)  # I think using dict() to pass a copy rather than the original is important
                CommLog(GetUTC_timestamp_as_datetime_synchronous(), temp_descr, "WSS", "?", host_externalIP, websocket_port)
                if actual_gossip_bandwidth < 1.3*target_gossip_bandwidth:  # a circuit-breaker
                    if ("hop" not in snapshot_nodeInfo) or (not isinstance(snapshot_nodeInfo["hop"], int)):
                        #print("ADDED HOP KEY")
                        snapshot_nodeInfo["hop"] = 1
                        #print("snapshot_nodeInfo: " + str(snapshot_nodeInfo))
                        await ForwardInfoToNRandomNodes_extern(info=snapshot_nodeInfo, n=nodeSampleSize)
                    elif snapshot_nodeInfo["hop"] < maxHops:
                        #print("INCREMENTED HOP KEY")
                        snapshot_nodeInfo["hop"] += 1
                        #print("snapshot_nodeInfo: " + str(snapshot_nodeInfo))
                        await ForwardInfoToNRandomNodes_extern(info=snapshot_nodeInfo, n=nodeSampleSize)
            else:
                #print("(server) Text message received but not processed: {0}".format(payload.decode('utf8')))
                CommLog(GetUTC_timestamp_as_datetime_synchronous(), "wss_unknown_incoming", "WSS", "?", host_externalIP, websocket_port)

    def onClose(self, wasClean, code, reason):
        print("[server] WebSocket connection closed: {0}".format(reason))
        app_log.info("[server] WebSocket closed")


async def maintainIP(node_dict):
    global host_externalIP
    global host_fwknopd_pubkey
    #while True: #not sure if I left this out by mistake?
    host_externalIP = GetHostInternetIP()
    node_dict[host_fwknopd_pubkey]["internetIP"] = host_externalIP
    await asyncio.sleep(180 + aFewSecs(1, 3))


async def IPcollision(addr, node_dict=node_dict) -> bool: 
    print("testing for IPcollision")
    # check whether addr already exists on wireguard virtual LAN
    for k, v in node_dict.items():
        if k != host_fwknopd_pubkey:
            if "wg_ip" in v:
                if v["wg_ip"] == addr:
                    return True
    return False


async def SelfAssignWireguardIP() -> str:
    preAns = await CheckForWireguardIP()
    while not preAns:
        preAns = await GenerateRandomIP4addr()
        while await IPcollision(addr=preAns):
            preAns = str(ipaddress.ip_address(preAns) + 1)
            #print("SelfAssignWireguardIP finding an available IP one at a time. trying " + preAns + "\n")
            if preAns == "198.20.0.0":  # in the unlikely case where we go above the upper limit of 198.19.255.255...
                preAns = "198.18.0.0"   # ...start over at the lower limit
        return preAns
    while await IPcollision(addr=preAns):
        preAns = str(ipaddress.ip_address(preAns) + 1)
        #print("SelfAssignWireguardIP finding an available IP one at a time. trying " + preAns + "\n")
        if preAns == "198.20.0.0":  # in the unlikely case where we go above the upper limit of 198.19.255.255...
            preAns = "198.18.0.0"   # ...start over at the lower limit
    return preAns


def ValuesAreReasonable(v):
    if ("wg_pubkey" in v) and ("wg_ip" in v) and ("internetIP" in v):
        if len(str(v["wg_pubkey"])) > 4:
            if len(str(v["wg_ip"])) > 4:
                if len(str(v["internetIP"])) > 4:
                    return True


async def BuildWireguardConfFile(confFileName, privateKey, node_dict): 
    global host_fwknopd_pubkey
    global host_externalIP
    global myWireguardIP
    global wireguard_port
    while len(node_dict.keys()) < 1:
        await asyncio.sleep(2)
    with open(confFileName, 'w') as f:
        f.write("[Interface]\n")
        f.write("PrivateKey = " + str(privateKey) + "\n")
        f.write("ListenPort = " + str(wireguard_port) + "\n")
        f.write("\n")
        for fwknop_pubkey, v in node_dict.items():
            if (fwknop_pubkey != host_fwknopd_pubkey) and ValuesAreReasonable(v):
                f.write("[Peer]\n")
                f.write("PublicKey = " + str(v["wg_pubkey"]) + "\n")
                f.write("AllowedIPs = " + str(v["wg_ip"]) + "/32\n")
                f.write("Endpoint = " + str(v["internetIP"]) + ":" + str(wireguard_port) + "\n")
                f.write("PersistentKeepalive = 25\n")
                f.write("\n")
    subprocess.run(["sudo", "chmod", "600", confFileName], capture_output=True, text=True)
    await asyncio.sleep(aFewSecs(1, 3))


async def StartWireguard(node_dict):
    global myWireguardIP
    global wgPrivateKey
    global host_externalIP
    global wg_bigconf_filename
    wg_bigconf_filename_path = "./" + wg_bigconf_filename
    global wireguard_port
    global gpg_lookup
    global wireguardStartCount
    global total_icmp_bytes_sent
    print("StartWireguard")
    try:
        subprocess.run(["sudo", "ip", "address", "add", "dev", "wg0", str(myWireguardIP + "/8")], capture_output=True, text=True)
        await BuildWireguardConfFile(wg_bigconf_filename, wgPrivateKey, node_dict)
        subprocess.run(["sudo", "wg", "setconf", "wg0", wg_bigconf_filename_path], capture_output=True, text=True)

        for k, v in node_dict.items():    # I think the port knock should happen here, against all non-localhost nodes
            if (k != host_fwknopd_pubkey) and (k in gpg_lookup):
                PortKnock(gpg_lookup[k][0], v["internetIP"], host_externalIP, wireguard_port, "udp")
                total_icmp_bytes_sent += 1460

        await asyncio.sleep(aFewSecs(3, 5))
        subprocess.run(["sudo", "ip", "link", "set", "up", "dev", "wg0"], capture_output=True, text=True)
        await asyncio.sleep(0.2)
        subprocess.run(["sudo", "ip", "route", "add", "10.0.0.0/8", "dev", "wg0"], capture_output=True, text=True)
        wireguardStartCount += 1
    except Exception as e:
        print("StartWireguard exception:")
        print(e)


async def GetWireguardPublicKey(primeFlag, node_dict) -> str:
    ans = None
    wireguardActive = False
    while not wireguardActive:
        complProc = subprocess.run(["sudo", "wg", "show"], capture_output=True, text=True)
        m1 = re.search('public\skey\:\s(.+)\n', complProc.stdout)
        wireguardActive = bool(m1)
        if (not wireguardActive) or primeFlag:
            await StartWireguard(node_dict)
            await asyncio.sleep(5 + aFewSecs(1, 3))
        if wireguardActive:
            ans = str(m1.group(1))
    return ans


def UpdateConfigFile(wireguardConfigFileName) -> None:
    global myWireguardIP
    global wgPrivateKey
    with open(wireguardConfigFileName, "w") as f:
        f.write("wireguard_private_key " + str(wgPrivateKey) + "\n")
        f.write("wireguard_ipv4_address " + str(myWireguardIP))


async def PrimeWireguard(node_dict):  # garauntees we rebuild the conf file every time
    global myWireguardIP
    global myWireguardPublicKey
    global wireguardNeedsPriming

    await asyncio.sleep(3 + aFewSecs(1,3))
    while not myWireguardIP:
        myWireguardIP = await SelfAssignWireguardIP()
        await asyncio.sleep(3 + aFewSecs(1,3))
    myWireguardPublicKey = await GetWireguardPublicKey(True, node_dict)
    UpdateConfigFile(wireguardConfigFileName)
    await asyncio.sleep(3 + aFewSecs(1,3))

    while True:
        await asyncio.sleep(180 + aFewSecs(1,3))
        while not myWireguardIP:
            myWireguardIP = await SelfAssignWireguardIP()
            await asyncio.sleep(5 + aFewSecs(1,3))
        myWireguardPublicKey = await GetWireguardPublicKey(wireguardNeedsPriming, node_dict)
        await asyncio.sleep(5 + aFewSecs(1,3))
        UpdateConfigFile(wireguardConfigFileName)


async def DetectOverallHealth(node_dict):
    nodeCount_5minsago = 0
    nodeCount_now = 0
    global healthyOverall
    while True:
        nodeCount_now = len(node_dict.keys())
        if nodeCount_5minsago > 10:
            if (nodeCount_now/nodeCount_5minsago) < 0.5:
                healthyOverall = False
        nodeCount_5minsago = nodeCount_now
        await asyncio.sleep(300)


async def CheckWireguardHealth(node_dict):
    global host_fwknopd_pubkey
    global wireguardNeedsPriming
    global myWireguardPublicKey 
    await asyncio.sleep(200)
    while True:
        await asyncio.sleep(15)
        complProc = subprocess.run(["sudo", "wg", "show"], capture_output=True, text=True)
        m1 = re.search('public\skey\:\s(.+)\n((.|\n)+)', complProc.stdout)
        publickey = m1.group(1) if m1 else None
        remaining_output = m1.group(2) if m1 else None
        actual_wg_peers = dict()
        loopFlag = True if remaining_output else False
        while loopFlag:
            m1 = re.search('peer\:\s(.+)\n((.|\n)+)', remaining_output)
            if not m1:
                loopFlag=False
                continue
            publickey_t = m1.group(1)
            remaining_output = m1.group(2)
            m2 = re.search('allowed\sips\:\s(.+)\/32\n((.|\n)+)', remaining_output)
            if not m2:
                loopFlag=False
                continue
            wgIP = m2.group(1)
            actual_wg_peers[publickey_t] = wgIP
            remaining_output = m2.group(2)
        desiredNodeCount = len(node_dict.keys())
        desiredNodeCount_adj = desiredNodeCount - 1  # subtract 1 to discount self
        actualNodeCount = len(actual_wg_peers.keys())
        matches=0
        mismatches=0
        if desiredNodeCount > 1:
            print("desiredNodeCount > 1")
            wireguardNeedsPriming = True
            if abs(desiredNodeCount_adj - actualNodeCount) < 1:
                print("desiredNodeCount_adj close to actualNodeCount")
                if myWireguardPublicKey == publickey:
                    print("publickey is correct")
                    for k,v in node_dict.items():
                        if k != host_fwknopd_pubkey:  # don't count self
                            desired_ip = v["wg_ip"]
                            desired_pubkey = v["wg_pubkey"]
                            if desired_pubkey in actual_wg_peers:
                                if actual_wg_peers[desired_pubkey] == desired_ip:
                                    matches += 1
                                else:
                                    mismatches += 1
                            else:
                                mismatches += 1
                    if (mismatches+matches) > 0:
                        mismatch_fraction = mismatches/(mismatches+matches)
                        print("mismatch_fraction " + str(mismatch_fraction))
                        if mismatch_fraction < 0.05:
                            wireguardNeedsPriming = False
                else:
                    print("this host's wireguard public key has an issue")
        print("wireguardNeedsPriming " + str(wireguardNeedsPriming))


def RestartWholeComputer():
    os.system("rm $HOME/autobahn_server.key")
    os.system("rm $HOME/autobahn_server.csr")
    os.system("rm $HOME/autobahn_server.crt")
    os.system("sudo mv /etc/fwknop/fwknopd.conf.old /etc/fwknop/fwknopd.conf")
    os.system("sudo mv /etc/fwknop/access.conf.old /etc/fwknop/access.conf")
    os.system("sudo iptables -F")
    print("restarting whole computer goodbye")
    os.system("sudo shutdown -r now")


async def main():
    print("entered method main")
    factory = WebSocketServerFactory("wss://127.0.0.1:" + str(websocket_port))
    factory.protocol = MyServerProtocol
    loop = asyncio.get_event_loop()
    coro = loop.create_server(factory, '0.0.0.0', websocket_port, ssl=sslcontext_forserver)
    asyncio.gather(
        Maintain_backup_file_of_nodes(path=nodeFilePath),
        Maintain_fwknopd_ws_connections_stats(node_dict=node_dict),
        Refresh_fwknopd(node_dict=node_dict),
        Maintain_wireguard_stats(node_dict=node_dict),
        BroadcastHeartbeat(node_dict=node_dict),
        RegulateBandwidth(),
        coro,
        display_node_dict(node_dict=node_dict),
        maintainIP(node_dict),
        PrimeWireguard(node_dict=node_dict),
        CheckWireguardHealth(node_dict=node_dict),
        pull_wg_ping_results_into_node_dict(node_dict=node_dict),
        DetectOverallHealth(node_dict=node_dict),
        NewNodeKeyMonitor(node_dict=node_dict),
        WriteCommLogBufferToDisk())
    #print("kicked off all the async functions. we are running.")
    #app_log.info("kicked off all the async functions. we are running.")

    shutdown_event = tornado.locks.Event()

    def signal_handler(sig, frame):
        global scriptShouldBeRunning
        print('You pressed Ctrl+C!')
        print("cleaning up...")
        os.system("rm $HOME/autobahn_server.key")
        os.system("rm $HOME/autobahn_server.csr")
        os.system("rm $HOME/autobahn_server.crt")
        os.system("sudo -E mv /etc/fwknop/fwknopd.conf.old /etc/fwknop/fwknopd.conf")
        os.system("sudo -E mv /etc/fwknop/access.conf.old /etc/fwknop/access.conf")
        os.system("sudo iptables -F")
        scriptShouldBeRunning = False
        print("done cleaning up.")
        shutdown_event.set()
    signal.signal(signal.SIGINT, signal_handler)   # enables Ctrl-C to cause graceful shut down I think.
    await shutdown_event.wait()
    print("we are shutting down")
    app_log.info("SHUTDOWN")

if __name__ == "__main__":
    tornado.ioloop.IOLoop.current().run_sync(main)  # it probably isn't necessary to use 
                                                    # tornado here
                                                    # I'm just working from some example
                                                    # and when I started it made sense
                                                    # but now this script isn't doing anything with
                                                    # a tornado server, so it doesn't make sense
                                                    # but it works


# GNU GENERAL PUBLIC LICENSE
#                        Version 3, 29 June 2007
# 
#  Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
#  Everyone is permitted to copy and distribute verbatim copies
#  of this license document, but changing it is not allowed.
# 
#                             Preamble
# 
#   The GNU General Public License is a free, copyleft license for
# software and other kinds of works.
# 
#   The licenses for most software and other practical works are designed
# to take away your freedom to share and change the works.  By contrast,
# the GNU General Public License is intended to guarantee your freedom to
# share and change all versions of a program--to make sure it remains free
# software for all its users.  We, the Free Software Foundation, use the
# GNU General Public License for most of our software; it applies also to
# any other work released this way by its authors.  You can apply it to
# your programs, too.
# 
#   When we speak of free software, we are referring to freedom, not
# price.  Our General Public Licenses are designed to make sure that you
# have the freedom to distribute copies of free software (and charge for
# them if you wish), that you receive source code or can get it if you
# want it, that you can change the software or use pieces of it in new
# free programs, and that you know you can do these things.
# 
#   To protect your rights, we need to prevent others from denying you
# these rights or asking you to surrender the rights.  Therefore, you have
# certain responsibilities if you distribute copies of the software, or if
# you modify it: responsibilities to respect the freedom of others.
# 
#   For example, if you distribute copies of such a program, whether
# gratis or for a fee, you must pass on to the recipients the same
# freedoms that you received.  You must make sure that they, too, receive
# or can get the source code.  And you must show them these terms so they
# know their rights.
# 
#   Developers that use the GNU GPL protect your rights with two steps:
# (1) assert copyright on the software, and (2) offer you this License
# giving you legal permission to copy, distribute and/or modify it.
# 
#   For the developers' and authors' protection, the GPL clearly explains
# that there is no warranty for this free software.  For both users' and
# authors' sake, the GPL requires that modified versions be marked as
# changed, so that their problems will not be attributed erroneously to
# authors of previous versions.
# 
#   Some devices are designed to deny users access to install or run
# modified versions of the software inside them, although the manufacturer
# can do so.  This is fundamentally incompatible with the aim of
# protecting users' freedom to change the software.  The systematic
# pattern of such abuse occurs in the area of products for individuals to
# use, which is precisely where it is most unacceptable.  Therefore, we
# have designed this version of the GPL to prohibit the practice for those
# products.  If such problems arise substantially in other domains, we
# stand ready to extend this provision to those domains in future versions
# of the GPL, as needed to protect the freedom of users.
# 
#   Finally, every program is threatened constantly by software patents.
# States should not allow patents to restrict development and use of
# software on general-purpose computers, but in those that do, we wish to
# avoid the special danger that patents applied to a free program could
# make it effectively proprietary.  To prevent this, the GPL assures that
# patents cannot be used to render the program non-free.
# 
#   The precise terms and conditions for copying, distribution and
# modification follow.
# 
#                        TERMS AND CONDITIONS
# 
#   0. Definitions.
# 
#   "This License" refers to version 3 of the GNU General Public License.
# 
#   "Copyright" also means copyright-like laws that apply to other kinds of
# works, such as semiconductor masks.
# 
#   "The Program" refers to any copyrightable work licensed under this
# License.  Each licensee is addressed as "you".  "Licensees" and
# "recipients" may be individuals or organizations.
# 
#   To "modify" a work means to copy from or adapt all or part of the work
# in a fashion requiring copyright permission, other than the making of an
# exact copy.  The resulting work is called a "modified version" of the
# earlier work or a work "based on" the earlier work.
# 
#   A "covered work" means either the unmodified Program or a work based
# on the Program.
# 
#   To "propagate" a work means to do anything with it that, without
# permission, would make you directly or secondarily liable for
# infringement under applicable copyright law, except executing it on a
# computer or modifying a private copy.  Propagation includes copying,
# distribution (with or without modification), making available to the
# public, and in some countries other activities as well.
# 
#   To "convey" a work means any kind of propagation that enables other
# parties to make or receive copies.  Mere interaction with a user through
# a computer network, with no transfer of a copy, is not conveying.
# 
#   An interactive user interface displays "Appropriate Legal Notices"
# to the extent that it includes a convenient and prominently visible
# feature that (1) displays an appropriate copyright notice, and (2)
# tells the user that there is no warranty for the work (except to the
# extent that warranties are provided), that licensees may convey the
# work under this License, and how to view a copy of this License.  If
# the interface presents a list of user commands or options, such as a
# menu, a prominent item in the list meets this criterion.
# 
#   1. Source Code.
# 
#   The "source code" for a work means the preferred form of the work
# for making modifications to it.  "Object code" means any non-source
# form of a work.
# 
#   A "Standard Interface" means an interface that either is an official
# standard defined by a recognized standards body, or, in the case of
# interfaces specified for a particular programming language, one that
# is widely used among developers working in that language.
# 
#   The "System Libraries" of an executable work include anything, other
# than the work as a whole, that (a) is included in the normal form of
# packaging a Major Component, but which is not part of that Major
# Component, and (b) serves only to enable use of the work with that
# Major Component, or to implement a Standard Interface for which an
# implementation is available to the public in source code form.  A
# "Major Component", in this context, means a major essential component
# (kernel, window system, and so on) of the specific operating system
# (if any) on which the executable work runs, or a compiler used to
# produce the work, or an object code interpreter used to run it.
# 
#   The "Corresponding Source" for a work in object code form means all
# the source code needed to generate, install, and (for an executable
# work) run the object code and to modify the work, including scripts to
# control those activities.  However, it does not include the work's
# System Libraries, or general-purpose tools or generally available free
# programs which are used unmodified in performing those activities but
# which are not part of the work.  For example, Corresponding Source
# includes interface definition files associated with source files for
# the work, and the source code for shared libraries and dynamically
# linked subprograms that the work is specifically designed to require,
# such as by intimate data communication or control flow between those
# subprograms and other parts of the work.
# 
#   The Corresponding Source need not include anything that users
# can regenerate automatically from other parts of the Corresponding
# Source.
# 
#   The Corresponding Source for a work in source code form is that
# same work.
# 
#   2. Basic Permissions.
# 
#   All rights granted under this License are granted for the term of
# copyright on the Program, and are irrevocable provided the stated
# conditions are met.  This License explicitly affirms your unlimited
# permission to run the unmodified Program.  The output from running a
# covered work is covered by this License only if the output, given its
# content, constitutes a covered work.  This License acknowledges your
# rights of fair use or other equivalent, as provided by copyright law.
# 
#   You may make, run and propagate covered works that you do not
# convey, without conditions so long as your license otherwise remains
# in force.  You may convey covered works to others for the sole purpose
# of having them make modifications exclusively for you, or provide you
# with facilities for running those works, provided that you comply with
# the terms of this License in conveying all material for which you do
# not control copyright.  Those thus making or running the covered works
# for you must do so exclusively on your behalf, under your direction
# and control, on terms that prohibit them from making any copies of
# your copyrighted material outside their relationship with you.
# 
#   Conveying under any other circumstances is permitted solely under
# the conditions stated below.  Sublicensing is not allowed; section 10
# makes it unnecessary.
# 
#   3. Protecting Users' Legal Rights From Anti-Circumvention Law.
# 
#   No covered work shall be deemed part of an effective technological
# measure under any applicable law fulfilling obligations under article
# 11 of the WIPO copyright treaty adopted on 20 December 1996, or
# similar laws prohibiting or restricting circumvention of such
# measures.
# 
#   When you convey a covered work, you waive any legal power to forbid
# circumvention of technological measures to the extent such circumvention
# is effected by exercising rights under this License with respect to
# the covered work, and you disclaim any intention to limit operation or
# modification of the work as a means of enforcing, against the work's
# users, your or third parties' legal rights to forbid circumvention of
# technological measures.
# 
#   4. Conveying Verbatim Copies.
# 
#   You may convey verbatim copies of the Program's source code as you
# receive it, in any medium, provided that you conspicuously and
# appropriately publish on each copy an appropriate copyright notice;
# keep intact all notices stating that this License and any
# non-permissive terms added in accord with section 7 apply to the code;
# keep intact all notices of the absence of any warranty; and give all
# recipients a copy of this License along with the Program.
# 
#   You may charge any price or no price for each copy that you convey,
# and you may offer support or warranty protection for a fee.
# 
#   5. Conveying Modified Source Versions.
# 
#   You may convey a work based on the Program, or the modifications to
# produce it from the Program, in the form of source code under the
# terms of section 4, provided that you also meet all of these conditions:
# 
#     a) The work must carry prominent notices stating that you modified
#     it, and giving a relevant date.
# 
#     b) The work must carry prominent notices stating that it is
#     released under this License and any conditions added under section
#     7.  This requirement modifies the requirement in section 4 to
#     "keep intact all notices".
# 
#     c) You must license the entire work, as a whole, under this
#     License to anyone who comes into possession of a copy.  This
#     License will therefore apply, along with any applicable section 7
#     additional terms, to the whole of the work, and all its parts,
#     regardless of how they are packaged.  This License gives no
#     permission to license the work in any other way, but it does not
#     invalidate such permission if you have separately received it.
# 
#     d) If the work has interactive user interfaces, each must display
#     Appropriate Legal Notices; however, if the Program has interactive
#     interfaces that do not display Appropriate Legal Notices, your
#     work need not make them do so.
# 
#   A compilation of a covered work with other separate and independent
# works, which are not by their nature extensions of the covered work,
# and which are not combined with it such as to form a larger program,
# in or on a volume of a storage or distribution medium, is called an
# "aggregate" if the compilation and its resulting copyright are not
# used to limit the access or legal rights of the compilation's users
# beyond what the individual works permit.  Inclusion of a covered work
# in an aggregate does not cause this License to apply to the other
# parts of the aggregate.
# 
#   6. Conveying Non-Source Forms.
# 
#   You may convey a covered work in object code form under the terms
# of sections 4 and 5, provided that you also convey the
# machine-readable Corresponding Source under the terms of this License,
# in one of these ways:
# 
#     a) Convey the object code in, or embodied in, a physical product
#     (including a physical distribution medium), accompanied by the
#     Corresponding Source fixed on a durable physical medium
#     customarily used for software interchange.
# 
#     b) Convey the object code in, or embodied in, a physical product
#     (including a physical distribution medium), accompanied by a
#     written offer, valid for at least three years and valid for as
#     long as you offer spare parts or customer support for that product
#     model, to give anyone who possesses the object code either (1) a
#     copy of the Corresponding Source for all the software in the
#     product that is covered by this License, on a durable physical
#     medium customarily used for software interchange, for a price no
#     more than your reasonable cost of physically performing this
#     conveying of source, or (2) access to copy the
#     Corresponding Source from a network server at no charge.
# 
#     c) Convey individual copies of the object code with a copy of the
#     written offer to provide the Corresponding Source.  This
#     alternative is allowed only occasionally and noncommercially, and
#     only if you received the object code with such an offer, in accord
#     with subsection 6b.
# 
#     d) Convey the object code by offering access from a designated
#     place (gratis or for a charge), and offer equivalent access to the
#     Corresponding Source in the same way through the same place at no
#     further charge.  You need not require recipients to copy the
#     Corresponding Source along with the object code.  If the place to
#     copy the object code is a network server, the Corresponding Source
#     may be on a different server (operated by you or a third party)
#     that supports equivalent copying facilities, provided you maintain
#     clear directions next to the object code saying where to find the
#     Corresponding Source.  Regardless of what server hosts the
#     Corresponding Source, you remain obligated to ensure that it is
#     available for as long as needed to satisfy these requirements.
# 
#     e) Convey the object code using peer-to-peer transmission, provided
#     you inform other peers where the object code and Corresponding
#     Source of the work are being offered to the general public at no
#     charge under subsection 6d.
# 
#   A separable portion of the object code, whose source code is excluded
# from the Corresponding Source as a System Library, need not be
# included in conveying the object code work.
# 
#   A "User Product" is either (1) a "consumer product", which means any
# tangible personal property which is normally used for personal, family,
# or household purposes, or (2) anything designed or sold for incorporation
# into a dwelling.  In determining whether a product is a consumer product,
# doubtful cases shall be resolved in favor of coverage.  For a particular
# product received by a particular user, "normally used" refers to a
# typical or common use of that class of product, regardless of the status
# of the particular user or of the way in which the particular user
# actually uses, or expects or is expected to use, the product.  A product
# is a consumer product regardless of whether the product has substantial
# commercial, industrial or non-consumer uses, unless such uses represent
# the only significant mode of use of the product.
# 
#   "Installation Information" for a User Product means any methods,
# procedures, authorization keys, or other information required to install
# and execute modified versions of a covered work in that User Product from
# a modified version of its Corresponding Source.  The information must
# suffice to ensure that the continued functioning of the modified object
# code is in no case prevented or interfered with solely because
# modification has been made.
# 
#   If you convey an object code work under this section in, or with, or
# specifically for use in, a User Product, and the conveying occurs as
# part of a transaction in which the right of possession and use of the
# User Product is transferred to the recipient in perpetuity or for a
# fixed term (regardless of how the transaction is characterized), the
# Corresponding Source conveyed under this section must be accompanied
# by the Installation Information.  But this requirement does not apply
# if neither you nor any third party retains the ability to install
# modified object code on the User Product (for example, the work has
# been installed in ROM).
# 
#   The requirement to provide Installation Information does not include a
# requirement to continue to provide support service, warranty, or updates
# for a work that has been modified or installed by the recipient, or for
# the User Product in which it has been modified or installed.  Access to a
# network may be denied when the modification itself materially and
# adversely affects the operation of the network or violates the rules and
# protocols for communication across the network.
# 
#   Corresponding Source conveyed, and Installation Information provided,
# in accord with this section must be in a format that is publicly
# documented (and with an implementation available to the public in
# source code form), and must require no special password or key for
# unpacking, reading or copying.
# 
#   7. Additional Terms.
# 
#   "Additional permissions" are terms that supplement the terms of this
# License by making exceptions from one or more of its conditions.
# Additional permissions that are applicable to the entire Program shall
# be treated as though they were included in this License, to the extent
# that they are valid under applicable law.  If additional permissions
# apply only to part of the Program, that part may be used separately
# under those permissions, but the entire Program remains governed by
# this License without regard to the additional permissions.
# 
#   When you convey a copy of a covered work, you may at your option
# remove any additional permissions from that copy, or from any part of
# it.  (Additional permissions may be written to require their own
# removal in certain cases when you modify the work.)  You may place
# additional permissions on material, added by you to a covered work,
# for which you have or can give appropriate copyright permission.
# 
#   Notwithstanding any other provision of this License, for material you
# add to a covered work, you may (if authorized by the copyright holders of
# that material) supplement the terms of this License with terms:
# 
#     a) Disclaiming warranty or limiting liability differently from the
#     terms of sections 15 and 16 of this License; or
# 
#     b) Requiring preservation of specified reasonable legal notices or
#     author attributions in that material or in the Appropriate Legal
#     Notices displayed by works containing it; or
# 
#     c) Prohibiting misrepresentation of the origin of that material, or
#     requiring that modified versions of such material be marked in
#     reasonable ways as different from the original version; or
# 
#     d) Limiting the use for publicity purposes of names of licensors or
#     authors of the material; or
# 
#     e) Declining to grant rights under trademark law for use of some
#     trade names, trademarks, or service marks; or
# 
#     f) Requiring indemnification of licensors and authors of that
#     material by anyone who conveys the material (or modified versions of
#     it) with contractual assumptions of liability to the recipient, for
#     any liability that these contractual assumptions directly impose on
#     those licensors and authors.
# 
#   All other non-permissive additional terms are considered "further
# restrictions" within the meaning of section 10.  If the Program as you
# received it, or any part of it, contains a notice stating that it is
# governed by this License along with a term that is a further
# restriction, you may remove that term.  If a license document contains
# a further restriction but permits relicensing or conveying under this
# License, you may add to a covered work material governed by the terms
# of that license document, provided that the further restriction does
# not survive such relicensing or conveying.
# 
#   If you add terms to a covered work in accord with this section, you
# must place, in the relevant source files, a statement of the
# additional terms that apply to those files, or a notice indicating
# where to find the applicable terms.
# 
#   Additional terms, permissive or non-permissive, may be stated in the
# form of a separately written license, or stated as exceptions;
# the above requirements apply either way.
# 
#   8. Termination.
# 
#   You may not propagate or modify a covered work except as expressly
# provided under this License.  Any attempt otherwise to propagate or
# modify it is void, and will automatically terminate your rights under
# this License (including any patent licenses granted under the third
# paragraph of section 11).
# 
#   However, if you cease all violation of this License, then your
# license from a particular copyright holder is reinstated (a)
# provisionally, unless and until the copyright holder explicitly and
# finally terminates your license, and (b) permanently, if the copyright
# holder fails to notify you of the violation by some reasonable means
# prior to 60 days after the cessation.
# 
#   Moreover, your license from a particular copyright holder is
# reinstated permanently if the copyright holder notifies you of the
# violation by some reasonable means, this is the first time you have
# received notice of violation of this License (for any work) from that
# copyright holder, and you cure the violation prior to 30 days after
# your receipt of the notice.
# 
#   Termination of your rights under this section does not terminate the
# licenses of parties who have received copies or rights from you under
# this License.  If your rights have been terminated and not permanently
# reinstated, you do not qualify to receive new licenses for the same
# material under section 10.
# 
#   9. Acceptance Not Required for Having Copies.
# 
#   You are not required to accept this License in order to receive or
# run a copy of the Program.  Ancillary propagation of a covered work
# occurring solely as a consequence of using peer-to-peer transmission
# to receive a copy likewise does not require acceptance.  However,
# nothing other than this License grants you permission to propagate or
# modify any covered work.  These actions infringe copyright if you do
# not accept this License.  Therefore, by modifying or propagating a
# covered work, you indicate your acceptance of this License to do so.
# 
#   10. Automatic Licensing of Downstream Recipients.
# 
#   Each time you convey a covered work, the recipient automatically
# receives a license from the original licensors, to run, modify and
# propagate that work, subject to this License.  You are not responsible
# for enforcing compliance by third parties with this License.
# 
#   An "entity transaction" is a transaction transferring control of an
# organization, or substantially all assets of one, or subdividing an
# organization, or merging organizations.  If propagation of a covered
# work results from an entity transaction, each party to that
# transaction who receives a copy of the work also receives whatever
# licenses to the work the party's predecessor in interest had or could
# give under the previous paragraph, plus a right to possession of the
# Corresponding Source of the work from the predecessor in interest, if
# the predecessor has it or can get it with reasonable efforts.
# 
#   You may not impose any further restrictions on the exercise of the
# rights granted or affirmed under this License.  For example, you may
# not impose a license fee, royalty, or other charge for exercise of
# rights granted under this License, and you may not initiate litigation
# (including a cross-claim or counterclaim in a lawsuit) alleging that
# any patent claim is infringed by making, using, selling, offering for
# sale, or importing the Program or any portion of it.
# 
#   11. Patents.
# 
#   A "contributor" is a copyright holder who authorizes use under this
# License of the Program or a work on which the Program is based.  The
# work thus licensed is called the contributor's "contributor version".
# 
#   A contributor's "essential patent claims" are all patent claims
# owned or controlled by the contributor, whether already acquired or
# hereafter acquired, that would be infringed by some manner, permitted
# by this License, of making, using, or selling its contributor version,
# but do not include claims that would be infringed only as a
# consequence of further modification of the contributor version.  For
# purposes of this definition, "control" includes the right to grant
# patent sublicenses in a manner consistent with the requirements of
# this License.
# 
#   Each contributor grants you a non-exclusive, worldwide, royalty-free
# patent license under the contributor's essential patent claims, to
# make, use, sell, offer for sale, import and otherwise run, modify and
# propagate the contents of its contributor version.
# 
#   In the following three paragraphs, a "patent license" is any express
# agreement or commitment, however denominated, not to enforce a patent
# (such as an express permission to practice a patent or covenant not to
# sue for patent infringement).  To "grant" such a patent license to a
# party means to make such an agreement or commitment not to enforce a
# patent against the party.
# 
#   If you convey a covered work, knowingly relying on a patent license,
# and the Corresponding Source of the work is not available for anyone
# to copy, free of charge and under the terms of this License, through a
# publicly available network server or other readily accessible means,
# then you must either (1) cause the Corresponding Source to be so
# available, or (2) arrange to deprive yourself of the benefit of the
# patent license for this particular work, or (3) arrange, in a manner
# consistent with the requirements of this License, to extend the patent
# license to downstream recipients.  "Knowingly relying" means you have
# actual knowledge that, but for the patent license, your conveying the
# covered work in a country, or your recipient's use of the covered work
# in a country, would infringe one or more identifiable patents in that
# country that you have reason to believe are valid.
# 
#   If, pursuant to or in connection with a single transaction or
# arrangement, you convey, or propagate by procuring conveyance of, a
# covered work, and grant a patent license to some of the parties
# receiving the covered work authorizing them to use, propagate, modify
# or convey a specific copy of the covered work, then the patent license
# you grant is automatically extended to all recipients of the covered
# work and works based on it.
# 
#   A patent license is "discriminatory" if it does not include within
# the scope of its coverage, prohibits the exercise of, or is
# conditioned on the non-exercise of one or more of the rights that are
# specifically granted under this License.  You may not convey a covered
# work if you are a party to an arrangement with a third party that is
# in the business of distributing software, under which you make payment
# to the third party based on the extent of your activity of conveying
# the work, and under which the third party grants, to any of the
# parties who would receive the covered work from you, a discriminatory
# patent license (a) in connection with copies of the covered work
# conveyed by you (or copies made from those copies), or (b) primarily
# for and in connection with specific products or compilations that
# contain the covered work, unless you entered into that arrangement,
# or that patent license was granted, prior to 28 March 2007.
# 
#   Nothing in this License shall be construed as excluding or limiting
# any implied license or other defenses to infringement that may
# otherwise be available to you under applicable patent law.
# 
#   12. No Surrender of Others' Freedom.
# 
#   If conditions are imposed on you (whether by court order, agreement or
# otherwise) that contradict the conditions of this License, they do not
# excuse you from the conditions of this License.  If you cannot convey a
# covered work so as to satisfy simultaneously your obligations under this
# License and any other pertinent obligations, then as a consequence you may
# not convey it at all.  For example, if you agree to terms that obligate you
# to collect a royalty for further conveying from those to whom you convey
# the Program, the only way you could satisfy both those terms and this
# License would be to refrain entirely from conveying the Program.
# 
#   13. Use with the GNU Affero General Public License.
# 
#   Notwithstanding any other provision of this License, you have
# permission to link or combine any covered work with a work licensed
# under version 3 of the GNU Affero General Public License into a single
# combined work, and to convey the resulting work.  The terms of this
# License will continue to apply to the part which is the covered work,
# but the special requirements of the GNU Affero General Public License,
# section 13, concerning interaction through a network will apply to the
# combination as such.
# 
#   14. Revised Versions of this License.
# 
#   The Free Software Foundation may publish revised and/or new versions of
# the GNU General Public License from time to time.  Such new versions will
# be similar in spirit to the present version, but may differ in detail to
# address new problems or concerns.
# 
#   Each version is given a distinguishing version number.  If the
# Program specifies that a certain numbered version of the GNU General
# Public License "or any later version" applies to it, you have the
# option of following the terms and conditions either of that numbered
# version or of any later version published by the Free Software
# Foundation.  If the Program does not specify a version number of the
# GNU General Public License, you may choose any version ever published
# by the Free Software Foundation.
# 
#   If the Program specifies that a proxy can decide which future
# versions of the GNU General Public License can be used, that proxy's
# public statement of acceptance of a version permanently authorizes you
# to choose that version for the Program.
# 
#   Later license versions may give you additional or different
# permissions.  However, no additional obligations are imposed on any
# author or copyright holder as a result of your choosing to follow a
# later version.
# 
#   15. Disclaimer of Warranty.
# 
#   THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
# APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT
# HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY
# OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM
# IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF
# ALL NECESSARY SERVICING, REPAIR OR CORRECTION.
# 
#   16. Limitation of Liability.
# 
#   IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
# WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR CONVEYS
# THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY
# GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE
# USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF
# DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD
# PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS),
# EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGES.
# 
#   17. Interpretation of Sections 15 and 16.
# 
#   If the disclaimer of warranty and limitation of liability provided
# above cannot be given local legal effect according to their terms,
# reviewing courts shall apply local law that most closely approximates
# an absolute waiver of all civil liability in connection with the
# Program, unless a warranty or assumption of liability accompanies a
# copy of the Program in return for a fee.
# 
#                      END OF TERMS AND CONDITIONS
# 
#             How to Apply These Terms to Your New Programs
# 
#   If you develop a new program, and you want it to be of the greatest
# possible use to the public, the best way to achieve this is to make it
# free software which everyone can redistribute and change under these terms.
# 
#   To do so, attach the following notices to the program.  It is safest
# to attach them to the start of each source file to most effectively
# state the exclusion of warranty; and each file should have at least
# the "copyright" line and a pointer to where the full notice is found.
# 
#     <one line to give the program's name and a brief idea of what it does.>
#     Copyright (C) <year>  <name of author>
# 
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.
# 
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
# 
#     You should have received a copy of the GNU General Public License
#     along with this program.  If not, see <https://www.gnu.org/licenses/>.
# 
# Also add information on how to contact you by electronic and paper mail.
# 
#   If the program does terminal interaction, make it output a short
# notice like this when it starts in an interactive mode:
# 
#     <program>  Copyright (C) <year>  <name of author>
#     This program comes with ABSOLUTELY NO WARRANTY; for details type `show w'.
#     This is free software, and you are welcome to redistribute it
#     under certain conditions; type `show c' for details.
# 
# The hypothetical commands `show w' and `show c' should show the appropriate
# parts of the General Public License.  Of course, your program's commands
# might be different; for a GUI interface, you would use an "about box".
# 
#   You should also get your employer (if you work as a programmer) or school,
# if any, to sign a "copyright disclaimer" for the program, if necessary.
# For more information on this, and how to apply and follow the GNU GPL, see
# <https://www.gnu.org/licenses/>.
# 
#   The GNU General Public License does not permit incorporating your program
# into proprietary programs.  If your program is a subroutine library, you
# may consider it more useful to permit linking proprietary applications with
# the library.  If this is what you want to do, use the GNU Lesser General
# Public License instead of this License.  But first, please read
# <https://www.gnu.org/licenses/why-not-lgpl.html>.
