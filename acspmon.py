#!/usr/bin/env python
#
# Aerohive AP ACSP monitor, show ACSP process graphically in real-time
# Note:
#   (1) Need to run the tool as root user(e.g. sudo ...)
#   (2) All APs to be monitored should be connected to the same subnet
#   (3) By default, all APs should use the same username('admin') and password('aerohive')
#   (4) Assume the IP address of an AP doens't change, this is normally true if using DHCP
#   (5) Automatical AP's location calculation is based on ideal FSPL algorithm
# Free space path loss(FSPL) algorithm:
#   FSPL = 32.44 + 20log10(F) + 20log10(d), where 'F' is 2.4 or 5(GHz) and 'd' is meters
# Get more help on the design/implementation/usage of the tool, refer to:
#   https://wiki.aerohive.com/wiki/display/~jtao/AP+ACSP+monitor
#


import os, sys, optparse, signal, time, threading, re
import paramiko, tkMessageBox, tkSimpleDialog, functools
from signal import signal, SIGINT
from socket import inet_aton
from scapy.all import sr, IP, TCP
from random import randint
from math import *
from Tkinter import *
from datetime import datetime



# Tunable constants
DEBUG_ENABLE = False
SSH_LOST_TIMEOUT = 3            # max timeout, SSH lost(e.g. node rebooted, power off)
SSH_NODE_PROBE_TIMEOUT = 3
NEW_NODE_DETECT_INTERVAL = 3
SSH_CMD_DELAY_DEFAULT = 0.5
SSH_CMD_DELAY_EXTRA = 0.0
SSH_CMD_BUF_LEN = 98304         # 96KB, since 'show acsp _nbr' could be > 75KB

HIVEAP_USERNAME = 'admin'
HIVEAP_PASSWORD = 'aerohive'
IFNAME_WIFI0 = 'wifi0'
IFNAME_WIFI1 = 'wifi1'

# All nodes found in the subnet, could be AP or non-AP
NODES = {}                      # indexed by IP
NODES_LOCK = threading.Lock()   # lock to protect the global node list

# All detected APs in the subnet, could be active or inactive(e.g. powered off)
APS = {}                        # indexed by IP
APS_LOCK = threading.Lock()     # lock to protect the global AP list

APS_COORD_METHOD = 'auto'       # AP coordinates calculation method, could be auto/manual/random
APS_COORD_NBRSCORE_ORDER = False    # Calculate APs coordinates in the order of nbr their scores

# the Tk canvas in which radio circles are drawn
CANVAS = None
CANVAS_WIDTH = 800
CANVAS_HEIGHT = 600
CANVAS_COLOR = 'white'
CANVAS_COLOR_TRANSP = False     # fill oval color(not transparent)? 
CANVAS_METER_PER_DOT = 0.1        # how many meters are represented by one dot-size on canvas
CANVAS_FREEZE = False           # Freeze GUI updating

# average noise floor detected by all APs
RF_AVR_NFLOOR = -90
RF_AVR_NFLOOR_MARGIN = 50       # safe margin to nfloor
RF_ABSORB_FACT = 10             # average RF signal absorb factor
RF_SMOOTH_WINDOW = 3            # RF signal smooth window(average of the num of samples is used) 

ACSP_RUN_TIMESTAMP = False      # show the timestamp that radio ACSP becomes RUN
RADIO_DISPLAYED = 'a'           # which radio of an AP should be displayed(0: wifi0, 1: wifi1, a: all)

# File path to save user input CLIs
USER_CLIS_FILE_PATH = './.cli'



# Utility functions
def cprint(color, fmt, *args):
    CCODES = {'red':'\033[22;31m', 'yellow':'\033[01;33m', 'cyan':'\033[22;36m', 'gray':'\033[01;30m'}
    CSTART = CEND = '\033[0m'
    if color in CCODES:
        CSTART = CCODES[color]
    print ('\n' + CSTART + fmt + CEND) % args

def LOG(level, fmt, *args):
    LEVELS = {'DEBUG':'gray', 'INFO':None, 'WARN':'yellow', 'ERROR':'red', 'ALERT':'cyan'}
    if level not in LEVELS:
        level = 'INFO'
    if level == 'DEBUG' and not DEBUG_ENABLE:
        return
    cprint(LEVELS[level], '['+level+']: '+fmt, *args)

# fill un-needed white spaces to make string splitting correct
def fillwhite(text, start, end, c='-'):
    '''
        replace any white spaces between the 'start' substr and 'end' substr,
        in text string 'text' to char 'c', e.g. between substr '(' and ')'.
        if 'c' is not given, '-' is used to fill by default.
        NOTE: nested 'start/end' substrs are not supported!
    '''
    newt = ''
    a = 0
    s = text.find(start)
    e = text.find(end)

    while e > s >= 0:
        newt += text[a:s]
        newt += (text[s:e+1].replace(' ', c).replace('\t', c))
        a = e+1
        s = text.find(start, e+1, len(text))
        e = text.find(end, e+1, len(text))
    
    if s < 0 or e <= s:
        newt += text[a:len(text)]

    return newt



class SSHLostException(Exception):
    pass

# Abstraction of SSH operation to a node
class SSHNode(object):
    def __init__(self, ip='0.0.0.0'):
        self.ssh_lock = threading.Lock() # lock to protect SSH transaction
        try:
            inet_aton(ip)       # validation
            self.ip = ip
        except Exception:
            raise
        self.ssh = None         # paramiko.SSHClient handle
        self.shell = None       # send()/recv() shell, get by invoke_shell()
        self.active = False     # online or offline

    def __str__(self):
        return "SSH to %s, %s" % (self.ip, 'open' if self.shell else 'closed')
        
    def __repr__(self):
        return self.__str__()

    def ssh_open(self):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.ssh_lock.acquire() 
            self.ssh.connect(self.ip, username=HIVEAP_USERNAME, password=HIVEAP_PASSWORD,
                    timeout=SSH_LOST_TIMEOUT)
            self.shell = self.ssh.invoke_shell()
            self.shell.settimeout(SSH_LOST_TIMEOUT)
            time.sleep(SSH_CMD_DELAY_DEFAULT + SSH_CMD_DELAY_EXTRA)
            self.shell.recv(SSH_CMD_BUF_LEN)    # read out welcome info
            self.active = True
            self.ssh_lock.release() 
            LOG('INFO', "Node %s connected through SSH", self.ip)
            return True
        except Exception:
            self.shell = None
            self.active = False
            self.ssh_lock.release() 
            LOG('WARN', "Node %s CANNOT SSH to", self.ip)
            return False

    def ssh_cmd(self, cmd, delay=SSH_CMD_DELAY_DEFAULT):
        if self.shell:
            try:
                self.ssh_lock.acquire() 
                # ready out whatever garbage that left last time
                self.shell.settimeout(0)
                try:
                    self.shell.recv(SSH_CMD_BUF_LEN)
                except Exception:
                    pass
                self.shell.settimeout(SSH_LOST_TIMEOUT)
                self.shell.send(cmd)
                if delay > 0:
                    time.sleep(delay + SSH_CMD_DELAY_EXTRA)
                out = self.shell.recv(SSH_CMD_BUF_LEN)
                self.ssh_lock.release() 
                self.active = True
                LOG('DEBUG', '%s >>>>>>>>>>>>>>>>>>>', self.ip)
                LOG('DEBUG', '%s', out)
                LOG('DEBUG', '%s <<<<<<<<<<<<<<<<<<<', self.ip)
                return out
            except Exception:
                self.active = False
                self.shell = None
                self.ssh.close()
                self.ssh_lock.release() 
                LOG('ALERT', 'Node %s SSH timeout at cmd "%s"', self.ip, cmd)
                raise SSHLostException('Node '+self.ip+' SSH timeout at cmd "'+cmd+'"')
        else:
            # connection lost, try to open SSH, ignore return code
            LOG('ALERT', '%s: try to open SSH', self)
            if self.ssh_open():
                node.ssh_cmd("console timeout 0\n")
                node.ssh_cmd("console page 0\n")
            return None;

    def ssh_cmd_lines(self, cmd, delay=SSH_CMD_DELAY_DEFAULT):
        out = self.ssh_cmd(cmd, delay)
        if out:
            # out always contains the original cmd in the first line, and the
            # node's shell prompt in the last line, remove these 2 lines, and
            # return a list of pure output lines
            out = out.split("\n")[1:-1]
        return out

    def ssh_close(self):
        if self.ssh:
            self.ssh_lock.acquire() 
            self.ssh.close()
            self.ssh_lock.release() 
            LOG('INFO', "Node %s SSH closed", self.ip)


# GUI coordinates
class GUICircle(object):
    global CANVAS, CANVAS_FREEZE
    UP, DOWN = [0, 1]               # circle up side or down side

    def __init__(self):
        self.oval_id = None         # Tk canvas circle oval item id
        self.c_id = None            # center point oval id
        self.c = [0, 0]             # circle center coordinates
        self.r = 0                  # circle radius length 
        self.xy0 = [0, 0]           # border rectangle top-left point coordinates
        self.xy1 = [0, 0]           # border rectangle bottom-right point coordinates
        self.color = 'black'        # fill color, black by default
        self.stipple = None         # fill color stipple bitmap
        self.outline = ''           # outline color, none by default
        self.dash = None            # outline dash pattern
        self.width = 0
        self.text_id = None         # optional text item id
        self.text = None            # text to display
        self.text_xy = [0, 0]       # text block center point coordinates
        self.text_color = 'black'   # default text color
        self.cname_id = None        # optional name item id
        self.cname = None           # name to display, displayed at the center point

    def __str__(self):
        return 'GUICircle(%s)-%d-%s' % (self.c, self.r, self.color)

    def __repr__(self):
        return self.__str__()

    # text_side = UP or DOWN, specify where to put the text(which side of the circle)
    # active: True - actively draw/update the circle; 
    #         False - still display the circle but make it unfill and dashed and inactive(not updated)
    def draw(self, c, r, color='black', stipple=None, text=None, text_loc=None, 
            text_color='black', cname=None, active=True):
        LOG('DEBUG', 'center %s, radius %d, color %s', c, r, color)
        self.c = c
        self.r = r
        self.xy0[0], self.xy0[1] = c[0] - r, c[1] - r
        self.xy1[0], self.xy1[1] = c[0] + r, c[1] + r
        self.color = color
        self.stipple = stipple
        self.outline = ''
        self.width = 0
        if CANVAS_COLOR_TRANSP or not active:
            self.color = ''
            self.outline = 'black'
            self.width = 1
            if not active:
                self.dash = (5, 5)
                self.text_color = self.outline
        self.text = text
        if text_loc == self.UP:
            self.text_xy = [self.xy0[0]+r, self.xy0[1]]
        elif text_loc == self.DOWN:
            self.text_xy = [self.xy1[0]-r, self.xy1[1]]
        self.text_color = text_color
        self.cname = cname if cname else self.cname

        if CANVAS_FREEZE:
            return

        if not self.oval_id:
            self.oval_id = CANVAS.create_oval(self.xy0[0], self.xy0[1], self.xy1[0], self.xy1[1], 
                    width=self.width, fill=self.color, stipple=self.stipple)
        else:
            CANVAS.coords(self.oval_id, self.xy0[0], self.xy0[1], self.xy1[0], self.xy1[1])
            CANVAS.itemconfig(self.oval_id, width=self.width, fill=self.color, 
                    stipple=self.stipple, dash=self.dash)

        if self.oval_id:
            '''
            if not self.c_id:
                self.c_id = CANVAS.create_oval(self.c[0]-1, self.c[1]-1, self.c[0]+1, self.c[1]+1, 
                        width=1, fill=self.color)
            else:
                CANVAS.coords(self.c_id, self.c[0]-1, self.c[1]-1, self.c[0]+1, self.c[1]+1)
                CANVAS.itemconfig(self.c_id, width=1, fill=self.color)
            '''

            if self.text and not self.text_id:
                self.text_id = CANVAS.create_text(self.text_xy, text=self.text, font=('arial', 7), 
                        fill=self.text_color)
            if self.text_id:
                CANVAS.coords(self.text_id, self.text_xy[0], self.text_xy[1])
                CANVAS.itemconfig(self.text_id, text=self.text, font=('arial', 7))

            if self.cname and not self.cname_id:
                self.cname_id = CANVAS.create_text(self.c, text=self.cname, font=('arial', 7))
            if self.cname_id:
                CANVAS.coords(self.cname_id, self.c[0], self.c[1])
                CANVAS.itemconfig(self.cname_id, text=self.cname, font=('arial', 7))

    # make the circle disappear
    def erase(self):
        if self.oval_id:
            CANVAS.delete(self.oval_id)
            self.oval_id = None
        if self.c_id:
            CANVAS.delete(self.c_id)
            self.c_id = None
        if self.text_id:
            CANVAS.delete(self.text_id)
            self.text_id = None
        if self.cname_id:
            CANVAS.delete(self.cname_id)
            self.cname_id = None


# Pack all ACSP neighbor info
class ACSPNbr(object):
    def __init__(self, radio=None):
        # the Radio instance _reference_, easy to get mode, phymode, the belonging AP, etc.
        self.radio = radio          

        # the following are all numbers
        self.rssi = None            # the nbr's RSSI received by this radio
        self.rssi_window = []       # the nbr's RSSI smooth window 
        self.max_txpwr = None       # max. tx power limit
        self.mgmt_tpbo = None       # tx power backoff for mgmt frames
        self.data_tpbo = None       # tx power backoff for data frames
        self.tot_cu = None          # total cu
        #self.tx_cu = None
        #self.rx_cu = None
        self.crc_err = None         # error rate
        self.sta_cnt = None         # total number of connected stations
        #self.nbr_cnt = None

    def __str__(self):
        return "nbr %s-%s-%s-%s: rssi=%s/stacnt=%s/crc=%s/txpwr=%s/mbo=%s/dbo=%s" % \
            (self.radio.ap.name, self.radio.name, self.radio.mac, self.radio.ap.ip, self.rssi, \
            self.sta_cnt, self.crc_err, self.max_txpwr, self.mgmt_tpbo, self.data_tpbo)

    def __repr__(self):
        return self.__str__()


PTN_ACSP = {
    'disabled_reason': re.compile(r'(\(.+?\))'),
    'nbr_rssi': re.compile(r'[ \t]+(-[0-9]+)[ \t]+'), 
    'nbrtabd_fmt1': re.compile(r'([ \t]+:[ \t]+)'), 
    'nbrtabd_fmt2': re.compile(r'([ \t]+:[0-9]+[ \t]+)'), 
}

# Pack all ACSP related info
class ACSP(object):
    global APS, APS_LOCK

    CHNL_STATE_DISABLE = 'Disable'
    CHNL_STATE_INIT = 'Init'
    CHNL_STATE_SCAN = 'Scanning'
    CHNL_STATE_REQ = 'Channel_Req'
    CHNL_STATE_LISTEN_DFS = 'DFS_CAC'
    CHNL_STATE_LISTEN = 'Listening'
    CHNL_STATE_RUN = 'Enable'
    CHNL_STATE_SCHED_WAIT = 'Sched_Waiting'

    def __init__(self):
        self.acsp_supported = False
        self.chnl_state = None 
        self.chnl_disabled_reason = None
        self.chnl_run_ts = None     # the timestamp when ACSP becomes RUN
        self.chnl = None        # number
        self.width = None       # number
        self.pwr_state = None
        self.pwr_disabled_reason = None
        self.txpwr = None       # number, real tx power(dBm), = max_txpwr - data_tpbo

        self.nbrs = {}          # all received nbr info, key:radio mac, value:ACSPNbr instance
        self.nbrs_bydist = []   # all nbrs, ordered by distance(from near to far from this radio)
        self.nbrs_radios = []   # all nbrs' corresponding radios, same order as nbrs_bydist

    def __str__(self):
        return "ACSP chnl(%s/%s/%s)-pwr(%s/%s)" % \
            (self.chnl_state, self.chnl, self.width, self.pwr_state, self.txpwr)

    def __repr__(self):
        return self.__str__()

    # scan all detected AP radio neighbors, update their ACSP info heard by current AP
    def update_acsp_nbrs(self, ssh):
        def sort_nbr_bydist(n):
            if not n.radio.txpwr:
                n.radio.txpwr = 20
            return n.radio.txpwr - n.rssi

        nbrtab = ssh.ssh_cmd_lines('show acsp neighbor\n', delay=2)
        '''
        nbrtabd = ssh.ssh_cmd_lines('show acsp _nbr\n', delay=2)
        '''

        self.nbrs = {}
        APS_LOCK.acquire()
        for ip, ap in APS.items():
            if ap is self.ap:
                continue

            for name, radio in ap.radios.items():
                nbr = ACSPNbr(radio)
                vapsd = None    # for easy comment the vapsd block

                vaps = [vap for vap in nbrtab if radio.mac[:-1] in vap]
                LOG('DEBUG', '%s: vaps of acsp nbr %s:\n%s', self.ap, radio, vaps)
                if vaps:
                    tot_rssi = tot_sta = tot_crc = tot_cu = 0
                    for vap in vaps:
                        vap_cols = vap.split()
                        try:
                            tot_rssi += int(PTN_ACSP['nbr_rssi'].search(vap).group(1))
                            tot_sta += int(vap_cols[-2])
                            tot_crc += int(vap_cols[-3][-1])
                            cu = vap_cols[-3][:3] if len(vap_cols[-3]) > 3 else vap_cols[-4]
                            tot_cu += int(cu)
                        except Exception:
                            LOG('ALERT', '[%s]Failed to parse rssi/sta/crc/cu, from line:\n%s', ssh.ip, vap)
                            raise
                    nbr.rssi_window.append(tot_rssi / len(vaps))
                    if len(nbr.rssi_window) > RF_SMOOTH_WINDOW:
                        nbr.rssi_window.pop(0)
                    nbr.rssi = sum(nbr.rssi_window) / len(nbr.rssi_window)
                    nbr.sta_cnt = tot_sta
                    nbr.crc_err = tot_crc / len(vaps)

                '''
                vapsd = [vap for vap in nbrtabd if radio.mac[:-1] in vap]
                LOG('DEBUG', 'vapsd: %s', vapsd)
                if vapsd:
                    # latest products have different output format 
                    if PTN_ACSP['nbrtabd_fmt1'].search(vapsd[0]):
                        pwr_base = 12
                    elif PTN_ACSP['nbrtabd_fmt2'].search(vapsd[0]):
                        pwr_base = 11
                    else:
                        pwr_base = 10
                    vap_cols = vapsd[0].split()  # power attributes are radio-specific
                    try:
                        nbr.max_txpwr = int(vap_cols[pwr_base])
                        nbr.mgmt_tpbo = int(vap_cols[pwr_base+1])
                        nbr.data_tpbo = int(vap_cols[pwr_base+2])
                    except Exception:
                        LOG('ALERT', '[%s]Failed to parse max_txpwr/tpbo, from line:\n%s', ssh.ip, vapsd[0])
                        raise

                    if nbr.max_txpwr > 20 or nbr.max_txpwr == 0:
                        LOG('ALERT', '[%s]wrong max_txpwr %d, from line:\n%s', ssh.ip, nbr.max_txpwr, vapsd[0])
                '''
                    
                if vaps or vapsd:
                    self.nbrs[nbr.radio.mac] = nbr
        
        if self.nbrs:
            #self.nbrs_bydist = sorted(self.nbrs.values(), key=lambda n: n.rssi, reverse=True)
            self.nbrs_bydist = sorted(self.nbrs.values(), key=sort_nbr_bydist)
            self.nbrs_radios = [n.radio for n in self.nbrs_bydist]

        APS_LOCK.release()
        LOG('DEBUG', 'nbrs:\n%s', self.nbrs)
        LOG('DEBUG', 'nbrs_bydist:\n%s', self.nbrs_bydist)
        LOG('DEBUG', 'nbrs_radios:\n%s', self.nbrs_radios)

    def update_acsp_stats(self, ssh):
        # some mode radio doesn't support ACSP
        if self.mode == 'access' or self.mode == 'backhaul' or self.mode == 'dual':
            self.acsp_supported = True
            out = ssh.ssh_cmd_lines('show acsp\n')
            line = 3 if self.name == IFNAME_WIFI0 else 4

            out[line] = fillwhite(out[line], '(', ')')
            out[line] = fillwhite(out[line], 'Channel', 'Req')
            out[line] = fillwhite(out[line], 'DFS', 'CAC')
            out[line] = fillwhite(out[line], 'Sched', 'Waiting')
            acsp_infos = out[line].split()
            LOG('DEBUG', '%s', acsp_infos)

            match = PTN_ACSP['disabled_reason'].search(acsp_infos[1])
            if match:
                self.chnl_disabled_reason = match.group(1)
                acsp_infos[1] = PTN_ACSP['disabled_reason'].sub('', acsp_infos[1])
            else:
                self.chnl_disabled_reason = None
            if self.chnl_state != ACSP.CHNL_STATE_RUN and acsp_infos[1] == ACSP.CHNL_STATE_RUN:
                self.chnl_run_ts = datetime.now().strftime("%m-%d_%H:%M:%S")
            self.chnl_state = acsp_infos[1]
            self.chnl = int(acsp_infos[2])
            if not self.chnl_state:
                LOG('ALERT', '[%s]Failed to parse chnl_state/chnl, from output:\n%s', ssh.ip, out[line])

            if 'width' in out[1]:
                self.width = int(acsp_infos[3])
                pwr_idx = 4
            else:
                pwr_idx = 3
            match = PTN_ACSP['disabled_reason'].search(acsp_infos[pwr_idx])
            if match:
                self.chnl_disabled_reason = match.group(1)
                acsp_infos[pwr_idx] = PTN_ACSP['disabled_reason'].sub('', acsp_infos[pwr_idx])
            else:
                self.pwr_disabled_reason = None
            self.pwr_state = acsp_infos[pwr_idx]
            self.txpwr = int(acsp_infos[pwr_idx+1])
            if not self.pwr_state:
                LOG('ALERT', '[%s]Failed to parse pwr_state/txpwr, from output:\n%s', ssh.ip, out[line])

            LOG('DEBUG', '%s: ACSP state %s, chnl %s, width %s, pwr_state %s, txpwr %s', 
                self.name, self.chnl_state, self.chnl, self.width, self.pwr_state, self.txpwr)

            self.update_acsp_nbrs(ssh)
        else:
            LOG('WARN', 'ACSP not supported on radio %s with mode %s', self, self.mode)
            self.acsp_supported = False


PTN_RADIO = {
    'mode':     re.compile(r'Mode=(.+?);'), 
    'phymode':  re.compile(r'Phymode=(.+?);'), 
    'nfloor':   re.compile(r'Noise floor=(.+?)dBm;'),
}

# Pack all Radio related info
class Radio(ACSP, GUICircle):
    BAND_2 = 2      # 2.4GHz band
    BAND_5 = 5      # 5GHz  band
    STATE_DOWN = 'D'
    STATE_UP = 'U'

    def __init__(self, name, mac, state, ap):
        ACSP.__init__(self)
        GUICircle.__init__(self)

        self.name = name
        self.mac = mac
        self.state = state      # link state: up/down
        self.mode = None 
        self.phymode = None     # 2.4GHz: 11b/g, 11ng; 5GHz: 11a, 11na, 11ac
        self.band = None        #2 for 2.4GHz band, or 5 for 5GHz band
        self.nfloor = None      # noise floor detected by this radio
        self.nfloor_window = [] # noise floor detected by this radio
        self.nbr_score = None   # neighbor score, radio with higher score calculates coords first

        self.ap = ap            # the belonging AP

    def __str__(self):
        return "%s-%s-%s-%s" % (self.name, self.mac, self.mode, self.phymode)

    def __repr__(self):
        return self.__str__()

    @staticmethod
    def ieee2ghz(chnl):
        if chnl == 0:
            chnl = 200  # special number for undetermined channel
        if chnl == 14:
            mhz = 2484
        elif chnl < 14:
            mhz = 2407 + chnl*5
        elif chnl < 27:
            mhz = 2512 + (chnl-15)*20
        else:
            mhz = 5000 + chnl*5
        return mhz / 1000.0

    @staticmethod
    def chnl2color(chnl):
        # 2.4G band use red, 5G band use blue, smaller chnl -> light color
        colorfmt = '#{0:02x}{1:02x}{2:02x}'
        if chnl < 15:
            n = int(512 - (511.0/14) * chnl)
            if n < 128:
                r, g, b = 128 + n, 0, 0
            elif n < 384:
                r, g, b = 255, n - 127, 0
            else:
                r, g, b = 255, 255, n - 382
        else:
            if chnl == 36:
                chnl += 1
            n = int(512 - (511.0/(165-36)) * (chnl-36))
            if n < 128:
                b, g, r = 128 + n, 0, 0
            elif n < 384:
                b, g, r = 255, n - 127, 0
            else:
                b, g, r = 255, 255, n - 382
        LOG('DEBUG', 'color %d, %d, %d, %d, %s', n, r, g, b, colorfmt.format(r, g, b))
        return colorfmt.format(r, g, b)

    def show(self, c=[0, 0], apname=None):
        if RADIO_DISPLAYED != 'a' and RADIO_DISPLAYED != self.name[-1]:
            return

        if self.mode == 'access' or self.mode == 'backhaul' or self.mode == 'dual':
            # According to FSPL, the coverage radius of the radio:
            #   d = 10 ^ ((txpwr - nfloor - 32.44 - 20log10(F))/20) 
            ghz = Radio.ieee2ghz(self.chnl)
            nfloor = RF_AVR_NFLOOR + RF_AVR_NFLOOR_MARGIN
            r = int(pow(10, (self.txpwr - 32.44 - 20*log10(ghz) - nfloor) / 20) / CANVAS_METER_PER_DOT)
            color = Radio.chnl2color(self.chnl)
            stipple = None
            if self.chnl_state == ACSP.CHNL_STATE_DISABLE:
                if self.chnl_disabled_reason == '(Link-down)':
                    color = 'gray'
            elif self.chnl_state != ACSP.CHNL_STATE_RUN:
                color = 'gray'
                stipple = 'gray25'
            text = '%s/%s/%s\n%s/%s/%s/%s' % (self.name, self.mode, self.phymode, \
                    self.chnl_state, self.chnl, self.pwr_state, self.txpwr)
            if ACSP_RUN_TIMESTAMP and self.chnl_state == ACSP.CHNL_STATE_RUN:
                text += ('\n(' + self.chnl_run_ts + ')')
            text_loc = GUICircle.UP if self.name == IFNAME_WIFI0 else GUICircle.DOWN
            text_color = 'black' 
            if self.chnl_state == ACSP.CHNL_STATE_DISABLE:
                text_color = 'magenta'
            elif self.chnl_state != ACSP.CHNL_STATE_RUN:
                text_color = 'green'

            self.draw(c, r, color, stipple, text=text, text_loc=text_loc, text_color=text_color, 
                        cname=apname, active=self.ap.active)

    def calc_nbr_score(self):
        # this radio's nbr score is higher when it has more nbrs, with higher rssi,
        # and more matured in ACSP state machine(in later states)
        if self.nbrs:
            score = 0
            for nbr in self.nbrs.values():
                s = nbr.radio.chnl_state
                snr = nbr.rssi - RF_AVR_NFLOOR      # should be positive
                if s == ACSP.CHNL_STATE_DISABLE or s == ACSP.CHNL_STATE_RUN:
                    score += snr / 2
                elif s == ACSP.CHNL_STATE_SCAN or s == ACSP.CHNL_STATE_LISTEN:
                    score += snr / 4
                elif s == ACSP.CHNL_STATE_INIT or s == ACSP.CHNL_STATE_SCHED_WAIT:
                    score += snr / 6
                else:
                    score += snr / 8
        else:
            score = -sys.maxint - 1     # the minimum integer
        return score

    def update_radio_stats(self, ssh):
        out = ssh.ssh_cmd('show interface '+self.name+'\n')
        try:
            self.mode = PTN_RADIO['mode'].search(out).group(1)
            self.phymode= PTN_RADIO['phymode'].search(out).group(1)
            self.band = Radio.BAND_5 if 'a' in self.phymode else Radio.BAND_2
            self.nfloor_window.append(int(PTN_RADIO['nfloor'].search(out).group(1)))
            if len(self.nfloor_window) > RF_SMOOTH_WINDOW:
                self.nfloor_window.pop(0)
            self.nfloor = sum(self.nfloor_window) / len(self.nfloor_window)
        except Exception:
            LOG('ALERT', "[%s]Failed to parse mode/phymode/band/nfloor, from output:\n%s", ssh.ip, out)
            raise
        LOG('DEBUG', '%s: mac %s, mode %s, phymode %s', self.name, self.mac, self.mode, self.phymode)

        self.update_acsp_stats(ssh)

        self.nbr_score = self.calc_nbr_score()
        LOG('DEBUG', '%s, nbr_score %d', self, self.nbr_score)

        c = self.c  # initial value
        apname = self.ap.name + '/' + self.ap.mac
        if len(self.ap.radios) >= 2:
            if self.name != IFNAME_WIFI0:
                c = self.ap.radios[IFNAME_WIFI0].c      # two radios have the same center

            if not CANVAS_FREEZE:
                self.ap.radios[IFNAME_WIFI0].erase()
                self.ap.radios[IFNAME_WIFI1].erase()

            # the radio with larger coverage radius draw first, thus it won't cover the other one
            if self.ap.radios[IFNAME_WIFI0].r > self.ap.radios[IFNAME_WIFI1].r:
                self.ap.radios[IFNAME_WIFI0].show(c)
                self.ap.radios[IFNAME_WIFI1].show(c, apname=apname)
            else:
                self.ap.radios[IFNAME_WIFI1].show(c)
                self.ap.radios[IFNAME_WIFI0].show(c, apname=apname)
        else:
            self.show(c, apname=apname)


# AP class, mainly for abstraction of ACSP
class AP(SSHNode):
    def __init__(self, ip):
        SSHNode.__init__(self, ip)

        self.lock = threading.Lock()        # lock to sync between info update and info get

        self.name = None
        self.mac = None         # invalid mac
        self.hive = None

        self.radios = {}        # Should be type Radio. key: name, value: Radio instance

    def __str__(self):
        return "%s-%s-%s" % (self.name, self.mac, self.ip)

    def __repr__(self):
        return self.__str__()

    def setup_radio(self, name, mac, state, ap):
        self.radios[name] = Radio(name, mac, state, ap)


    # Update AP info(e.g. Radio, GUI displaying, etc)
    def update_ap_stats(self):
        for r in self.radios.values():
            try:
                self.lock.acquire()
                r.update_radio_stats(self)
                self.lock.release()
            except SSHLostException:
                for r in self.radios.values():
                    r.draw(r.c, r.r, active=False)
                self.lock.release()
                LOG('ALERT', 'AP %s offline', self)
            except Exception as e:
                self.lock.release()
                LOG('ERROR', 'parsing error: %s', e)


# Check whether an active node is AP or not
def detect_ap(node):
    global NODES, NODES_LOCK, APS, APS_LOCK

    if not node.ssh_open():
        # node cannot be connected, give it another chance next time
        NODES_LOCK.acquire()
        del NODES[node.ip]
        NODES_LOCK.release()
    else:
        out = node.ssh_cmd_lines("show interface | in " + IFNAME_WIFI0 + "\n")
        if not out or len(out) == 0 or 'Wifi0' not in ''.join(out):
            NODES_LOCK.acquire()
            del NODES[node.ip]
            NODES_LOCK.release()
        else:
            LOG('INFO', "Node %s added to node list", node)

            node.ssh_cmd("console timeout 0\n")
            node.ssh_cmd("console page 0\n")
            try:
                tmp = node.ssh_cmd_lines("show interface | in mgt0\n")
                node.mac = tmp[0].split()[1]
                node.hive = tmp[0].split()[7]
                tmp = node.ssh_cmd_lines("show version | in Platform\n", delay=1)
                node.name = tmp[0].split()[1]
            except Exception:
                LOG('ALERT', '[%s]Failed to parse mode mac/hive/name, from output:\n%s', node.ip, tmp)
                NODES_LOCK.acquire()
                del NODES[node.ip]
                NODES_LOCK.release()

            if node.name[:2] == 'SR':
                LOG('ALERT', 'Treat SR switch as AP by mistake, out:\n%s', out)

            APS_LOCK.acquire()
            if node.ip in APS:
                if node.active:
                    LOG('WARN', 'Try to add duplicated AP %s, ignore', node)
                    APS_LOCK.release()
                    return
                else:
                    node.active = True
                    LOG('INFO', 'AP %s back online', node)
            else:
                APS[node.ip] = node
                LOG('INFO', '%s added to AP monitor list', node)
            APS_LOCK.release()

            node.setup_radio(IFNAME_WIFI0, out[0].split()[1], out[0].split()[3], node)
            out = node.ssh_cmd_lines("show interface | in " + IFNAME_WIFI1 + "\n")
            if out and len(out) > 0:
                node.setup_radio(IFNAME_WIFI1, out[0].split()[1], out[0].split()[3], node)

            while True:
                node.update_ap_stats()
                time.sleep(0.5)


# Detect new APs in a subnet, and open a SSH shell channel to them respectively
def detect_new_aps(subnet):
    global NODES, NODES_LOCK

    while True:
        # 'ping' port 22 of all nodes in the subnet, to check if they have SSH service
        ans,unans = sr(IP(dst=subnet)/TCP(dport=22), timeout=SSH_NODE_PROBE_TIMEOUT)
        if len(ans) > 0:
            for (s, r) in ans:     # a list of all alive IP strings
                ip = r[IP].src

                # Ignore exisitng node, rely on node's IP not changing
                NODES_LOCK.acquire()
                if ip in NODES:
                    NODES_LOCK.release()
                    continue

                node = AP(ip)
                NODES[node.ip] = node
                NODES_LOCK.release()

                # AP connection and verification is timing consuming, and might make us
                # miss the ACSP starting procedure if there are many APs in the subnet.
                # So we start a thread for each node to do the work concurrently
                t = threading.Thread(target=detect_ap, args=(node,), name="apDetectThread_"+str(node.ip))
                t.setDaemon(True)
                t.start()
        time.sleep(NEW_NODE_DETECT_INTERVAL)


# Calculate the distance between point p1(x1, y1) and p2(x2, y2), a and b are tuples
def distance(p1, p2):
    x1, y1 = p1
    x2, y2 = p2
    return sqrt((x1 - x2)**2 + (y1 - y2)**2)

# Calculate 2 given circles' cross point. 
# Circle 1's center coordinates is c1(a 2-element tuple of form (x1, y1)), radius is r1;
# Circle 2's center coordinates is c2(a 2-element tuple of form (x2, y2)), radius is r2;
# Depending on the relative location and size of the two circles, there could be several results:
#   1) no cross point: d == 0 && r1 != r2; or d != 0 && d > r1 + r2; or d <= |r1 - r2|
#   2) 1 cross point: d != 0 && d = r1 + r2
#   3) 2 cross points: d != 0 && d < r1 + r2
#   4) infinite cross points: d == 0 && r1 == r2
# Suppose the distance between the 2 circles' centers is d, if 'compensate=True', then:
#   * if d < |r1 - r2|, |r1 - r2| - d is added to the min. of r1 and r2 to compute again
# Return of cases(2-element tuple, the 1st is return code, the 2nd is value):
#   1) & 4), or d < |r1 - r2| but not compensated: (-1, None)
#   2) d < |r1 - r2| & compensated: (0, [(x, y)])
#   3): (1, [(x, y)])
#   4): (2, [(x1, y1), (x2, y2)])
# The caller should check the return code of this function's return value to tell which case
#
def circles_cpoints(c1, r1, c2, r2, compensate=False):
    points = (-1, None); x1, y1 = c1; x2, y2 = c2
    has_compensated = False

    d = distance(c1, c2)
    if d != 0:
        if d < abs(r1 - r2) and compensate:
            if r1 < r2:
                r1 += (r2 - r1 - d)
            else:
                r2 += (r1 - r2 - d)
            has_compensated = True

        if d >= abs(r1 - r2) and d <= r1 + r2:
            try:
                p1 = (((y1 - y2)*(-x1**2*y1 - x1**2*y2 + 2*x1*x2*y1 + 2*x1*x2*y2 - x2**2*y1 - x2**2*y2 - y1**3 + y1**2*y2 + y1*y2**2 + y1*r1**2 - y1*r2**2 - y2**3 - y2*r1**2 + y2*r2**2 + sqrt((x1 - x2)**2*(-x1**2 + 2*x1*x2 - x2**2 - y1**2 + 2*y1*y2 - y2**2 + r1**2 + 2*r1*r2 + r2**2)*(x1**2 - 2*x1*x2 + x2**2 + y1**2 - 2*y1*y2 + y2**2 - r1**2 + 2*r1*r2 - r2**2))) + (x1**2 - x2**2 + y1**2 - y2**2 - r1**2 + r2**2)*(x1**2 - 2*x1*x2 + x2**2 + y1**2 - 2*y1*y2 + y2**2))/(2*(x1 - x2)*(x1**2 - 2*x1*x2 + x2**2 + y1**2 - 2*y1*y2 + y2**2)), (sqrt((x1 - x2)**2*(-x1**2 + 2*x1*x2 - x2**2 - y1**2 + 2*y1*y2 - y2**2 + r1**2 + 2*r1*r2 + r2**2)*(x1**2 - 2*x1*x2 + x2**2 + y1**2 - 2*y1*y2 + y2**2 - r1**2 + 2*r1*r2 - r2**2))*(-x1**2 + 2*x1*x2 - x2**2 - y1**2 + 2*y1*y2 - y2**2) + (x1**2 - 2*x1*x2 + x2**2 + y1**2 - 2*y1*y2 + y2**2)*(x1**2*y1 + x1**2*y2 - 2*x1*x2*y1 - 2*x1*x2*y2 + x2**2*y1 + x2**2*y2 + y1**3 - y1**2*y2 - y1*y2**2 - y1*r1**2 + y1*r2**2 + y2**3 + y2*r1**2 - y2*r2**2))/(2*(x1**2 - 2*x1*x2 + x2**2 + y1**2 - 2*y1*y2 + y2**2)**2)) 
                p2 = (-((y1 - y2)*(x1**2*y1 + x1**2*y2 - 2*x1*x2*y1 - 2*x1*x2*y2 + x2**2*y1 + x2**2*y2 + y1**3 - y1**2*y2 - y1*y2**2 - y1*r1**2 + y1*r2**2 + y2**3 + y2*r1**2 - y2*r2**2 + sqrt((x1 - x2)**2*(-x1**2 + 2*x1*x2 - x2**2 - y1**2 + 2*y1*y2 - y2**2 + r1**2 + 2*r1*r2 + r2**2)*(x1**2 - 2*x1*x2 + x2**2 + y1**2 - 2*y1*y2 + y2**2 - r1**2 + 2*r1*r2 - r2**2))) - (x1**2 - x2**2 + y1**2 - y2**2 - r1**2 + r2**2)*(x1**2 - 2*x1*x2 + x2**2 + y1**2 - 2*y1*y2 + y2**2))/(2*(x1 - x2)*(x1**2 - 2*x1*x2 + x2**2 + y1**2 - 2*y1*y2 + y2**2)), (x1**2*y1 + x1**2*y2 - 2*x1*x2*y1 - 2*x1*x2*y2 + x2**2*y1 + x2**2*y2 + y1**3 - y1**2*y2 - y1*y2**2 - y1*r1**2 + y1*r2**2 + y2**3 + y2*r1**2 - y2*r2**2 + sqrt((x1 - x2)**2*(-x1**2 + 2*x1*x2 - x2**2 - y1**2 + 2*y1*y2 - y2**2 + r1**2 + 2*r1*r2 + r2**2)*(x1**2 - 2*x1*x2 + x2**2 + y1**2 - 2*y1*y2 + y2**2 - r1**2 + 2*r1*r2 - r2**2)))/(2*(x1**2 - 2*x1*x2 + x2**2 + y1**2 - 2*y1*y2 + y2**2)))
            except Exception:
                LOG('ERROR', 'Failed to compute cpoints of (%s, %s) + (%s, %s) + comp %s', \
                        c1, r1, c2, r2, compensate)
                raise

            if d == r1 + r2 or d == abs(r1 - r2):
                points = (0 if has_compensated else 1, [p1])
            else:
                points = (2, [p1, p2])

    return points


# Get a reference nbr radio, and calculate its path loss to this radio. 
# If ref1_rd or ref2_rd is given, the returned reference radio should not be on 
# the same AP as ref1_rd and ref2_rd.
# Input:
#   rd: this radio, to calculate coordinates
#   ref_nbrs0: a list of wifi0 nbr radios that heard by this radio, and done coord calc
#   rref_nbrs0: a list of wifi0 nbr radios that can hear this radio, and done coord calc
#   ref_nbrs1: a list of wifi1 nbr radios that heard by this radio, and done coord calc
#   rref_nbrs1: a list of wifi1 nbr radios that can hear this radio, and done coord calc
#   ref1_rd: the first reference radio, which already done coord calc
#   ref2_rd: the second reference radio, which already done coord calc
#   has_cross: if the found ref radio needs to have cross point with ref1_rd/ref2_rd
# Output: tuple (ref_rd, fspl, ghz)
#   ref_rd: the reference radio if found
#   fspl: the free space path loss(dB) between the reference radio and this radio
#   ghz: channel frequency(in GHz) of the reference radio
def get_ref_nbr(ref_nbrs0, rref_nbrs0, ref_nbrs1, rref_nbrs1,
                rd, ref1_rd=None, ref2_rd=None, need_cross=False):
    ref_rd = fspl = ghz = None
    ref1_ap = ref1_rd.ap if ref1_rd else None
    ref2_ap = ref2_rd.ap if ref2_rd else None
    ref1_cross = ref2_cross = False

    ref_nbrs = ref_nbrs0 + rref_nbrs0 + ref_nbrs1 + rref_nbrs1
    rlen0, rrlen0, rlen1, rrlen1 = map(len, [ref_nbrs0, rref_nbrs0, ref_nbrs1, rref_nbrs1])
    ref_nbrs = ref_nbrs0 + rref_nbrs0 + ref_nbrs1 + rref_nbrs1

    for i in range(len(ref_nbrs)):
        ref_rd = ref_nbrs[i]
        if ref_rd.ap != ref1_ap and ref_rd.ap != ref2_ap:
            if need_cross:
                if ref1_rd:
                    d = distance(ref_rd.c, ref1_rd.c)
                    ref1_cross = (d != 0 and d <= (ref_rd.r + ref1_rd.r))
                if ref2_rd:
                    d = distance(ref_rd.c, ref2_rd.c)
                    ref2_cross = (d != 0 and d <= (ref_rd.r + ref2_rd.r))
                if (ref1_rd == None or ref1_cross) and (ref2_rd == None or ref2_cross):
                    break
            else:
                break

    if i < rlen0:
        ref_nbrs0.pop(i)
        fspl = ref_rd.txpwr - rd.nbrs[ref_rd.mac].rssi
        ghz = Radio.ieee2ghz(ref_rd.chnl)
        LOG('DEBUG', 'ref_nbr0 %s txpwr %s chnl %s(%s): heard by %s rssi %s fspl %s', 
            ref_rd, ref_rd.txpwr, ref_rd.chnl, ghz, rd, rd.nbrs[ref_rd.mac].rssi, fspl)
    elif i < rlen0 + rrlen0:
        rref_nbrs0.pop(i - rlen0)
        fspl = rd.txpwr - ref_rd.nbrs[rd.mac].rssi
        ghz = Radio.ieee2ghz(rd.chnl)
        LOG('DEBUG', '%s txpwr %s chnl %s(%s): heard by rref_nbr0 %s rssi %s fspl %s', 
            rd, rd.txpwr, rd.chnl, ghz, ref_rd, ref_rd.nbrs[rd.mac].rssi, fspl)
    elif i < rlen0 + rrlen0 + rlen1:
        ref_nbrs1.pop(i - rlen0 - rrlen0)
        fspl = ref_rd.txpwr - rd.nbrs[ref_rd.mac].rssi
        ghz = Radio.ieee2ghz(ref_rd.chnl)
        LOG('DEBUG', 'ref_nbr1 %s txpwr %s chnl %s(%s): heard by %s rssi %s fspl %s', 
            ref_rd, ref_rd.txpwr, ref_rd.chnl, ghz, rd, rd.nbrs[ref_rd.mac].rssi, fspl)
    elif i < rlen0 + rrlen0 + rlen1 + rrlen1:
        rref_nbrs1.pop(i - rlen0 - rrlen0 - rlen1)
        fspl = rd.txpwr - ref_rd.nbrs[rd.mac].rssi
        ghz = Radio.ieee2ghz(rd.chnl)
        LOG('DEBUG', '%s txpwr %s chnl %s(%s): heard by rref_nbr1 %s rssi %s fspl %s', 
            rd, rd.txpwr, rd.chnl, ghz, ref_rd, ref_rd.nbrs[rd.mac].rssi, fspl)
    else:
        LOG('ERROR', 'Cannot found reference nbr')

    return (ref_rd, fspl, ghz)


# Calculate each AP's GUI coordinate related to others
def calc_ap_coord():
    global APS, APS_LOCK, RF_AVR_NFLOOR

    while True:
        # Calculate average noise floor from all APs
        tot_nfloor = tot_radios = 0
        APS_LOCK.acquire()
        if APS:
            for ip, ap in APS.items():
                for name, radio in ap.radios.items():
                    if radio.nfloor:
                        tot_nfloor += radio.nfloor 
                        tot_radios += 1
            if tot_radios > 0:
                RF_AVR_NFLOOR = tot_nfloor / tot_radios
        APS_LOCK.release()

        # "3-point locating' method:
        # An AP could be located by other 3 APs. Normally, 2 of the 3 APs have 2
        # cross points, if consider the radio coverage as circle with center c
        # and radius r. The other one in the 3 APs finally choose the appropriate
        # cross point based on RF signal loss estimation
        #
        # To calculate each AP's coordinates as accurate as possible, need to use
        # the following rules: (1). the center of the AP cluster(high nbr score) 
        # must be calculate first, and other APs are gruadually calculated in the
        # 'from-center-to-outside' direction. (2). to calculate an AP, the other 3
        # APs used to locate it must be as close as possible to this AP, so that
        # FSPL algorithm is more reliable(longer distance transmittion is supposed
        # to less accurate since there are more obstacles which absorbes the RF).
        # (3). in case there are so many APs in the cluster and some AP's ACSP nbr
        # table is full, the best 3-AP used to locate it might not be availabe,
        # this AP could be bypassed temporarily, and be calculated later when other
        # APs complete calculation, which are in that AP's nbr table
        #
        # For APs with 2 radios, wifi0 has higher priority to be used for calculation
        #
        # Note that the 3rd AP could select either cross point of the 2 points
        # calculated by the first 2 APs. After all APs done, the whole canvus
        # could be rotate/mirror to match the real layout
        #
        # TODO: rssi/nfloor sometimes has jitters, so need to smooth them in a 
        # time window(e.g. average of the last 5 times)
        
        APS_LOCK.acquire()
        # get a list of APs with wifi0 nbr score in ascending order
        aps_nscore = [a for a in APS.values() if a.radios and a.radios[IFNAME_WIFI0].nbr_score]
        if APS_COORD_NBRSCORE_ORDER:
            aps_nscore = sorted(aps_nscore, key=lambda a: a.radios[IFNAME_WIFI0].nbr_score, reverse=True)
        LOG('DEBUG', 'aps_nscore: %s',  aps_nscore)
        LOG('DEBUG', 'nbr scores: %s', [a.radios[IFNAME_WIFI0].nbr_score for a in aps_nscore])
        # now each AP in aps_nscore have at least wifi0 with valid acsp nbrs

        aps, aps_delayed = [], []
        for ap in aps_nscore:
            LOG('DEBUG', 'aps: %s\nap: %s', aps, ap)

            if ap in aps:   # coord already calculated
                continue

            rd0, rd1 = ap.radios[IFNAME_WIFI0], None
            if len(ap.radios) > 1: 
                rd1 = ap.radios[IFNAME_WIFI1]

            LOG('DEBUG', '%s %s', rd0, rd0.nbrs_bydist)
            LOG('DEBUG', '%s %s', rd1, rd1.nbrs_bydist)

            if APS_COORD_METHOD == 'random':
                # randomly assign the AP's coordinates, for test
                rd0.c = (randint(50, CANVAS_WIDTH-50), randint(50, CANVAS_HEIGHT-50))
                if rd1:
                    rd1.c = rd0.c
                continue
            elif APS_COORD_METHOD == 'manual':
                # user decides manually assign the AP's coordinates
                continue

            required_ref_nbrs = len(aps) if len(aps) < 3 else 3

            # get all wifi0 nbrs that already calc done, near in distance first
            ref_nbrs0 = [r for r in rd0.nbrs_radios if r.ap in aps and r.name==IFNAME_WIFI0]
            LOG('DEBUG', 'wifi0 ref_nbrs: %s', ref_nbrs0)
            # try wifi1
            ref_nbrs1 = [r for r in rd0.nbrs_radios if r.ap in aps and r.name==IFNAME_WIFI1]
            LOG('DEBUG', 'wifi1 ref_nbrs: %s', ref_nbrs1)
            # try the reversed nbr-relationship direction
            rref_nbrs0 = [a.radios[IFNAME_WIFI0] for a in aps if rd0 in a.radios[IFNAME_WIFI0].nbrs_radios]
            LOG('DEBUG', 'wifi0 rref_nbrs: %s', rref_nbrs0)
            # try wifi1 of the reversed nbr-relationship direction
            rref_nbrs1 = [a.radios[IFNAME_WIFI1] for a in aps if rd0 in a.radios[IFNAME_WIFI1].nbrs_radios]
            LOG('DEBUG', 'wifi1 rref_nbrs: %s', rref_nbrs1)

            # count the total number of unique APs
            uaps = set() 
            for r in ref_nbrs0 + ref_nbrs1 + rref_nbrs0 + rref_nbrs1:
                uaps.add(r.ap)
            LOG('DEBUG', 'unique nbr APs: %s', uaps)

            if len(uaps) < required_ref_nbrs:
                if ap not in aps_delayed:
                    aps_delayed.append(ap)
                    aps_nscore.append(ap)
                    LOG('WARN', 'Delay %s coord calc due to %s ref nbrs not available', 
                        ap, required_ref_nbrs)
                continue

            # the 1st AP is always put to the center of the canvas
            if required_ref_nbrs == 0:
                rd0.c = [CANVAS_WIDTH/2, CANVAS_HEIGHT/2]
                if rd1:
                    rd1.c = rd0.c
                LOG('DEBUG', 'the 1st AP %s fixed to %s', ap, rd0.c)
                aps.append(ap)
                continue

            # the 2nd AP is always put to straight right of the 1st AP
            if required_ref_nbrs >= 1:
                try:
                    ref1_rd, fspl, ghz = get_ref_nbr(ref_nbrs0, rref_nbrs0, ref_nbrs1, rref_nbrs1, rd0)
                except Exception as e:
                    LOG('ERROR', 'ref1_rd computing error: %s', e)
                    continue

                d1 = int(pow(10, (fspl - 32.44 - 20*log10(ghz)) / 20) / CANVAS_METER_PER_DOT)
                LOG('DEBUG', 'd1: distance from ref1 %s(%s-%s) to me %s: %s', 
                    ref1_rd, ref1_rd.c, ref1_rd.r, rd0, d1)

                if required_ref_nbrs == 1:
                    rd0.c = [ref1_rd.c[0]+d1, ref1_rd.c[1]]
                    if rd1:
                        rd1.c = rd0.c
                    LOG('DEBUG', 'the 2nd AP %s fixed to right of the 1st AP by distance %d', ap, d1)
                    aps.append(ap)
                    continue

            # the 3rd AP is always put to the above cross point of the first 2 APs
            if required_ref_nbrs >= 2:
                try:
                    ref2_rd, fspl, ghz = get_ref_nbr(ref_nbrs0, rref_nbrs0, ref_nbrs1, rref_nbrs1, 
                                                    rd0, ref1_rd)
                except Exception as e:
                    LOG('ERROR', 'ref2_rd computing error: %s', e)
                    continue

                d2 = int(pow(10, (fspl - 32.44 - 20*log10(ghz)) / 20) / CANVAS_METER_PER_DOT)
                LOG('DEBUG', 'd2: distance from ref2 %s(%s-%s) to me %s: %s', 
                    ref2_rd, ref2_rd.c, ref2_rd.r, rd0, d2)

                if required_ref_nbrs == 2:
                    points = circles_cpoints(ref1_rd.c, d1, ref2_rd.c, d2, compensate=False)
                    if points[0] < 0:
                        if ap not in aps_delayed:
                            aps_delayed.append(ap)
                            aps_nscore.append(ap)
                            LOG('WARN', 'Delay %s coord calc since no cross point between (%s:%s)-(%s:%s)', 
                                ap, ref1_rd.c, d1, ref2_rd.c, d2)
                    else:
                        rd0.c = points[1][0]
                        if rd1:
                            rd1.c = rd0.c
                        LOG('DEBUG', 'the 3rd AP %s put to the cpoint %s of the first 2 APs', ap, rd0.c)
                        aps.append(ap)
                    continue
                
            # other APs are calc according to the '3-point locating' method
            if required_ref_nbrs >= 3:
                try:
                    ref3_rd, fspl, ghz = get_ref_nbr(ref_nbrs0, rref_nbrs0, ref_nbrs1, rref_nbrs1, 
                                                    rd0, ref1_rd, ref2_rd)
                except Exception as e:
                    LOG('ERROR', 'ref3_rd computing error: %s', e)
                    continue

                d3 = int(pow(10, (fspl - 32.44 - 20*log10(ghz)) / 20) / CANVAS_METER_PER_DOT)
                LOG('DEBUG', 'd3: distance from ref3 %s(%s-%s) to me %s: %s', 
                    ref3_rd, ref3_rd.c, ref3_rd.r, rd0, d3)

                points = circles_cpoints(ref1_rd.c, d1, ref2_rd.c, d2, compensate=False)
                if points[0] < 0:
                    if ap not in aps_delayed:
                        aps_delayed.append(ap)
                        aps_nscore.append(ap)
                        LOG('WARN', 'Delay %s coord calc since no cross point between (%s:%s)-(%s:%s)', 
                            ap, ref1_rd.c, d1, ref2_rd.c, d2)
                elif points[0] <= 1:
                    rd0.c = points[1][0]
                    if rd1:
                        rd1.c = rd0.c
                    LOG('DEBUG', 'AP %s put to %s', ap, rd0.c)
                    aps.append(ap)
                else:
                    # the 3rd ref AP determines the best cross point of first 2 ref APs
                    n1 = distance(ref1_rd.c, ref3_rd.c)
                    n2 = distance(ref2_rd.c, ref3_rd.c)
                    if abs(d3 - n1) < abs(d3 - n2):
                        rd0.c = points[1][0]
                    else:
                        rd0.c = points[1][1]
                    if rd1:
                        rd1.c = rd0.c
                    LOG('DEBUG', 'AP %s put to %s', ap, rd0.c)
                    aps.append(ap)

        APS_LOCK.release()
        time.sleep(NEW_NODE_DETECT_INTERVAL)

def update_gui():
    global APS, APS_LOCK

    def sort_ap_coverage(ap):
        if len(ap.radios) == 1:
            return ap.radios[IFNAME_WIFI0].r
        else:
            if ap.radios[IFNAME_WIFI0].r > ap.radios[IFNAME_WIFI1].r:
                return ap.radios[IFNAME_WIFI0].r
            else:
                return ap.radios[IFNAME_WIFI1].r

    if not APS or CANVAS_FREEZE:
        return

    # display all APs, larger radio coverage first so that it won't cover other
    # smaller coverage APs
    APS_LOCK.acquire()
    aps = sorted(APS.values(), key=sort_ap_coverage, reverse=True)

    for ap in aps:
        apname = ap.name + '/' + ap.mac
        if len(ap.radios) == 1:
            ap.radios[IFNAME_WIFI0].show(apname=apname)
        else:
            # two radios have the same center
            ap.radios[IFNAME_WIFI1].c = ap.radios[IFNAME_WIFI0].c

            ap.radios[IFNAME_WIFI0].erase()
            ap.radios[IFNAME_WIFI1].erase()

            # the radio with larger coverage radius draw first, thus it won't cover the other one
            if ap.radios[IFNAME_WIFI0].r > ap.radios[IFNAME_WIFI1].r:
                ap.radios[IFNAME_WIFI0].show()
                ap.radios[IFNAME_WIFI1].show(apname=apname)
            else:
                ap.radios[IFNAME_WIFI1].show()
                ap.radios[IFNAME_WIFI0].show(apname=apname)
    APS_LOCK.release()


def quit_safe(code):
    APS_LOCK.acquire()
    if APS:
        for ap in APS.values():
            ap.ssh_close()
    APS_LOCK.release()
    exit(code)

def quit_callback(signum, stack):
    quit_safe(254)

# find the AP under given location (x, y)
def find_ap_at_xy(x, y):
    ap_found = None

    APS_LOCK.acquire()
    if APS:
        for ap in APS.values():
            if len(ap.radios) == 0:
                continue
            elif len(ap.radios) == 1:
                rd = ap.radios[IFNAME_WIFI0]
            else:
                # the smaller radio is sensitive to mouse
                if ap.radios[IFNAME_WIFI0].r > ap.radios[IFNAME_WIFI1].r and ap.radios[IFNAME_WIFI1].r:
                    rd = ap.radios[IFNAME_WIFI1]
                else:
                    rd = ap.radios[IFNAME_WIFI0]

            if sqrt((x - rd.c[0])**2 + (y - rd.c[1])**2) < rd.r:
                # randomly select one AP if there are multiple under the mouse
                ap_found = ap
                break
    APS_LOCK.release()

    return ap_found

class CLIDialog(tkSimpleDialog.Dialog):
    def body(self, master):
        Label(master, text="CLI:").grid(row=0)
        self.e1 = Entry(master, width=42)
        self.e1.grid(row=0, column=1)
        Label(master, text="Delay between APs:").grid(row=1)
        self.e2 = Entry(master, width=32)
        self.e2.grid(row=1, column=1)
        return self.e1  # initial focus

    def apply(self):
        self.result = (str(self.e1.get()), str(self.e2.get()))
        return self.result

PRESSED_AP = None
MENU = None
USER_CLIS = [
        'interface eth0 shutdown', 
        'interface wifi0 radio channel auto', 
        'interface wifi1 radio channel auto', 
        'interface wifi0 radio power auto', 
        'interface wifi1 radio power auto', 
        'no interface eth0 shutdown', 
        'no interface wifi0 mode', 
        'no interface wifi1 mode', 
        'no interface wifi0 radio profile', 
        'no interface wifi1 radio profile', 
        'reboot no-prompt', 
    ]
USER_CLIS_FILE = None
TARGET_APS = []
def mouse_menu_callback(event):
    global PRESSED_AP, MENU, USER_CLIS, TARGET_APS

    # multiple CLI could be specified in 'clis' string, separated by ';'
    def cli_cmd(clis, ap_delay=0):
        clis = clis.split(';')

        if PRESSED_AP:  # menu of the AP
            try:
                for cli in clis:
                    PRESSED_AP.ssh_cmd(cli+'\n')
                    LOG('INFO', 'CLI "%s" issued to %s', cli, PRESSED_AP)
            except Exception:
                LOG('ERROR', 'CLI "%s" failed to issue to %s', clis, PRESSED_AP)
        else:   # menu of all APs
            if TARGET_APS:
                aps = TARGET_APS
            else:
                aps = APS.values()
            APS_LOCK.acquire()
            if aps:
                for ap in aps:
                    try:
                        for cli in clis:
                            ap.ssh_cmd(cli+'\n')
                            LOG('INFO', 'CLI "%s" issued to %s', cli, ap)
                    except Exception:
                        LOG('ERROR', 'CLI "%s" failed to issue to %s', clis, ap)
                    time.sleep(ap_delay)
            APS_LOCK.release()

    def menu_add_cli(menu, cli, callback):
        menu.add_command(label='CLI: '+cli, command=functools.partial(callback, cli))

    def send_cli():
        global USER_CLIS, TARGET_APS

        result = CLIDialog(MENU).result
        if not result or not result[0]:
            return
        if result[1]:
            ap_delay = float(result[1])
        else:
            ap_delay = 0

        cli = result[0].strip()
        cli_cmd(cli, ap_delay=ap_delay)
        if cli not in USER_CLIS:
            if True:
                USER_CLIS.append(cli)
                USER_CLIS.sort()
            else:
                USER_CLIS.insert(0, cli)    # put latest CLI first
            # save CLI history to file
            USER_CLIS_FILE = open(USER_CLIS_FILE_PATH, 'w+')
            USER_CLIS_FILE.write('\n'.join(USER_CLIS))
            USER_CLIS_FILE.close()
            # insert user inputed CLI as menu item
            index = 4 + USER_CLIS.index(cli)
            MENU.insert_command(index, label='CLI: '+cli, command=functools.partial(cli_cmd, cli))

    PRESSED_AP = find_ap_at_xy(event.x, event.y)

    if not MENU:
        MENU = Menu(tearoff=0)
        MENU.add_command(label=PRESSED_AP or "All APs", state=DISABLED)
        MENU.add_separator()
        MENU.add_command(label="Send CLI...", command=send_cli)
        MENU.add_separator()
        if os.access(USER_CLIS_FILE_PATH, os.R_OK|os.W_OK):
            USER_CLIS_FILE = open(USER_CLIS_FILE_PATH, 'r')
            USER_CLIS = USER_CLIS_FILE.readlines()
            USER_CLIS_FILE.close()
            USER_CLIS = map(lambda cli: cli.strip(), USER_CLIS)
        for cli in USER_CLIS:
            menu_add_cli(MENU, cli, cli_cmd)
        MENU.add_separator()
        MENU.add_command(label="Quit ACSPmon", command=functools.partial(quit_safe, 253))

    MENU.delete(0)
    if PRESSED_AP:
        target = PRESSED_AP
    elif TARGET_APS:
        target = 'All selected APs'
    else:
        target = 'All APs'
    MENU.insert_command(0, label=target, state=DISABLED)
    MENU.post(event.x_root,event.y_root)

SELECTED_AP = None
def mouse_selection_callback(event):
    global SELECTED_AP, MENU, TARGET_APS_SELECTION, TARGET_APS

    if MENU:
        MENU.unpost()

    ap = find_ap_at_xy(event.x, event.y)
    if ap:
        if TARGET_APS_SELECTION and ap not in TARGET_APS:
            TARGET_APS.append(ap)
        else:
            SELECTED_AP = ap
        LOG('INFO', '%s selected', ap)


def mouse_move_callback(event):
    global SELECTED_AP

    if SELECTED_AP and not CANVAS_FREEZE:
        SELECTED_AP.radios[IFNAME_WIFI0].show(c=(event.x, event.y))
        SELECTED_AP.radios[IFNAME_WIFI1].show(c=(event.x, event.y))

def mouse_release_callback(event):
    global SELECTED_AP

    if SELECTED_AP and not CANVAS_FREEZE:
        SELECTED_AP.radios[IFNAME_WIFI0].show(c=(event.x, event.y))
        SELECTED_AP.radios[IFNAME_WIFI1].show(c=(event.x, event.y))
        LOG('INFO', '%s put to %s', SELECTED_AP, SELECTED_AP.radios[IFNAME_WIFI0].c)
        SELECTED_AP = None

def win_resize_callback(event):
    global CANVAS, CANVAS_WIDTH, CANVAS_HEIGHT

    CANVAS_WIDTH = event.width
    CANVAS_HEIGHT = event.height
    CANVAS.configure(width=CANVAS_WIDTH, height=CANVAS_HEIGHT)

SHORTCUT_KEYS_HELP = '''
a     -- Toggle which radio of an AP is shown on the GUI: wifi0, wifi1, all\n
c X   -- Set AP coordinates calculation method to X, X could be 'a'(auto), 'm'(manual), or 'r'(random)(default: auto)\n
d     -- Toggle to disable/enable debugging output(default: Disabled)\n
e NUM -- Set SSH command extra delay(s) to NUM(default: 0)\n
f     -- Toggle to freeze/unfreeze GUI updating(default: unfreezed)\n
h     -- Toggle to show/hide this help\n
m NUM -- Set noise floor margin(dBm) to NUM(default: 50)\n
p NUM -- Set 'number of meters per dot'(m) to NUM(default: 0.1)\n
r     -- Toggle to show/hide the timestamp that when a radio's ACSP becomes RUN\n
t     -- Toggle to fill/unfill radio circle color(default: fill)\n
s     -- Toggle to calculate AP coords in the order of occurrence or nbr score(default: occurrence)\n
t     -- Toggle to fill/unfill radio circle color(default: fill)\n
w NUM -- Set RF signal sample smoothing window to NUM(default: 3)\n
x     -- Toggle to select/unselect APs which are used as the CLIs target in the 'right-click' menu\n
\n
Note: For any shortcut key with value NUM, it must be closed by 'Enter' key, +/- key could be used instead of NUM\n
'''
class HelpDialog(tkSimpleDialog.Dialog):
    def body(self, master):
        Label(master, text=SHORTCUT_KEYS_HELP, justify=LEFT).grid(row=0)
        return None

RADIO_DISPLAYED_LIST = ['a', '0', '1']
radio_displayed = 0
shortcut_key = ''
shortcut_num = ''
TARGET_APS_SELECTION = False
def key_press_callback(event):
    global APS_COORD_METHOD, DEBUG_ENABLE, CANVAS_FREEZE, CANVAS_COLOR_TRANSP, \
        SSH_CMD_DELAY_EXTRA, RF_AVR_NFLOOR_MARGIN, CANVAS_METER_PER_DOT, RF_SMOOTH_WINDOW, \
        ACSP_RUN_TIMESTAMP, RADIO_DISPLAYED, TARGET_APS_SELECTION, TARGET_APS, \
        coords_methods, coords_methods_turn, shortcut_key, shortcut_num, radio_displayed

    if event.keysym == 'a':
        radio_displayed = (radio_displayed + 1) % len(RADIO_DISPLAYED_LIST)
        RADIO_DISPLAYED = RADIO_DISPLAYED_LIST[radio_displayed]
        LOG('INFO', 'RADIO_DISPLAYED: %s', RADIO_DISPLAYED)
    if event.keysym == 'd':
        DEBUG_ENABLE = bool(True - DEBUG_ENABLE)
        LOG('INFO', 'DEBUG_ENABLE: %s', DEBUG_ENABLE)
    elif event.keysym == 'f':
        CANVAS_FREEZE = bool(True - CANVAS_FREEZE)
        LOG('INFO', 'CANVAS_FREEZE: %s', CANVAS_FREEZE)
    elif event.keysym == 'h':
        #tkMessageBox.showinfo('Shortcut key help', SHORTCUT_KEYS_HELP)
        dia = HelpDialog(CANVAS, title='Shortcut key help')
    elif event.keysym == 't':
        CANVAS_COLOR_TRANSP = bool(True - CANVAS_COLOR_TRANSP)
        LOG('INFO', 'CANVAS_COLOR_TRANSP: %s', CANVAS_COLOR_TRANSP)
    elif event.keysym in 'cempw':
        if not shortcut_key:
            shortcut_key = event.keysym
            LOG('INFO', 'Continue to input value for shortcut key "%s" ...', event.keysym)
        else:
            if shortcut_key == 'c' and event.keysym == 'm':
                APS_COORD_METHOD = 'manual'
                LOG('INFO', 'APS_COORD_METHOD: %s', APS_COORD_METHOD)
                shortcut_key = ''
    elif event.keysym == 'a':
        if shortcut_key == 'c': 
            APS_COORD_METHOD = 'auto'
            LOG('INFO', 'APS_COORD_METHOD: %s', APS_COORD_METHOD)
    elif event.keysym == 'r':
        if shortcut_key == 'c': 
            APS_COORD_METHOD = 'random'
            LOG('INFO', 'APS_COORD_METHOD: %s', APS_COORD_METHOD)
        else:
            ACSP_RUN_TIMESTAMP = bool(True - ACSP_RUN_TIMESTAMP)
            LOG('INFO', 'ACSP_RUN_TIMESTAMP: %s', ACSP_RUN_TIMESTAMP)
    elif event.keysym == 's':
        APS_COORD_NBRSCORE_ORDER = bool(True - APS_COORD_NBRSCORE_ORDER)
        LOG('INFO', 'APS_COORD_NBRSCORE_ORDER: %s', APS_COORD_NBRSCORE_ORDER)
    elif event.keysym == 'x':
        TARGET_APS_SELECTION = bool(True - TARGET_APS_SELECTION)
        LOG('INFO', 'TARGET_APS_SELECTION: %s', TARGET_APS_SELECTION)
        TARGET_APS = []
    elif event.keysym == 'Return':
        if shortcut_key and shortcut_key != 'c' and shortcut_num:
            value = float(shortcut_num)
            if shortcut_key == 'e':
                SSH_CMD_DELAY_EXTRA = value 
                LOG('INFO', 'SSH_CMD_DELAY_EXTRA: %s', SSH_CMD_DELAY_EXTRA)
            elif shortcut_key == 'm':
                RF_AVR_NFLOOR_MARGIN = value
                LOG('INFO', 'RF_AVR_NFLOOR_MARGIN: %s', RF_AVR_NFLOOR_MARGIN)
            elif shortcut_key == 'p':
                CANVAS_METER_PER_DOT = value
                LOG('INFO', 'CANVAS_METER_PER_DOT: %s', CANVAS_METER_PER_DOT)
            elif shortcut_key == 'w':
                RF_SMOOTH_WINDOW = value
                LOG('INFO', 'RF_SMOOTH_WINDOW: %s', RF_SMOOTH_WINDOW)
    elif event.keysym == 'minus' or 'equal':
            if shortcut_key == 'e':
                SSH_CMD_DELAY_EXTRA += (-0.2 if event.keysym == 'minus' else 0.2) 
                LOG('INFO', 'SSH_CMD_DELAY_EXTRA: %s', SSH_CMD_DELAY_EXTRA)
            elif shortcut_key == 'm':
                RF_AVR_NFLOOR_MARGIN += (-1 if event.keysym == 'minus' else 1)
                LOG('INFO', 'RF_AVR_NFLOOR_MARGIN: %s', RF_AVR_NFLOOR_MARGIN)
            elif shortcut_key == 'p':
                CANVAS_METER_PER_DOT += (-0.01 if event.keysym == 'minus' else 0.01)
                LOG('INFO', 'CANVAS_METER_PER_DOT: %s', CANVAS_METER_PER_DOT)
            elif shortcut_key == 'w':
                RF_SMOOTH_WINDOW += (-1 if event.keysym == 'minus' else 1)
                LOG('INFO', 'RF_SMOOTH_WINDOW: %s', RF_SMOOTH_WINDOW)
    elif event.keysym.isdigit():
        shortcut_num += event.keysym
    elif event.keysym == 'period':
        shortcut_num += '.'
    else:
        LOG('WARN', 'Unsupported shortcut key: %s', event.keysym)

    if not (event.keysym in 'cempw' or event.keysym in ['minus', 'equal']) \
        and not (event.keysym.isdigit() or event.keysym == 'period'):
        shortcut_key = shortcut_num = ''


# Main entry
if __name__ == '__main__':
    # Handle commmand line parameters
    p = optparse.OptionParser(description='Aerohive AP ACSP monitor, type "h" in GUI for shortcut keys help')
    p.add_option('-a', '--radio_displayed', action='store', type='choice', dest='radio_displayed', 
        choices=['0', '1', 'a'],
        help='Set which radio of an AP is shown on the GUI, "0": wifi0, "1": wifi1, "a": all')
    p.add_option('-c', '--coord_method', action='store', type='choice', dest='coord_method', 
        choices=['auto', 'manual', 'random'],
        help='Set the method by which APs relative location coordinates are calculated, ' + 
             'supported methods are "auto", "random", and "manual"')
    p.add_option('-d', '--debug', action='store_true', dest='debug', default=False, 
        help='Enable verbose debug log')
    p.add_option('-e', '--ext_delay', action='store', type='float', dest='ext_delay', default=None, 
        help='Set the extra SSH command transaction delay time')
    p.add_option('-f', '--freeze_gui', action='store_true', dest='freeze_gui', default=False, 
        help='Freeze GUI updating')
    p.add_option('-m', '--nfloor_margin', action='store', type='int', dest='nfloor_margin', default=None, 
        help='Set the safe margin to noise floor, within which signal is considered unusable')
    p.add_option('-n', '--subnet', action='store', type='string', dest='subnet', default=None, 
        help='Set the subnet(x.y.z.n/mask, or x.y.z.0 for 24 mask bits, or x.y.z.n:m for m ' + 
             'consequential ips starting from n) in which APs are monitored')
    p.add_option('-p', '--meters_per_dot', action='store', type='int', dest='meters_per_dot', default=None, 
        help='Set how many radio RF coverage meters(radius) per dot when drawn on canvas')
    p.add_option('-r', '--acsp_run_ts', action='store_true', dest='acsp_run_ts', default=False, 
        help='Show the timestamp that radio ACSP state becomes RUN')
    p.add_option('-s', '--coord_nbrscore_order', action='store_true', dest='nbrscore_order', default=False, 
        help='Calculate APs location coordinates in the order of their nbr scores(from large to small), by default, occurrence order is used')
    p.add_option('-t', '--color-transparent', action='store_true', dest='color_trans', default=False, 
        help='Don not fill radio circle color, make it transparent')
    p.add_option('-u', '--userpass', action='store_true', dest='userpass', default=None, 
        help='Set username and password(separated by ":") for all APs to be monitored')
    p.add_option('-w', '--smooth_window', action='store', type='int', dest='smooth_window', default=None, 
        help='Set the RF signal smooth window size(num of samples which average is done on)')
    opts, args = p.parse_args()

    if not opts.subnet:
        LOG('ERROR', "Subnet must be provided, see usage.")
        p.print_help()
        p.exit(255)

    if opts.userpass:
        HIVEAP_USERNAME = opts.userpass.split(':')[0]
        HIVEAP_PASSWORD = opts.userpass.split(':')[1]

    if opts.radio_displayed:
        RADIO_DISPLAYED = opts.radio_displayed

    subnet = opts.subnet
    if ':' in subnet:
        ipstr = subnet.split(':')[0]
        start_ip = int(ipstr.split('.')[3])
        num_ip = int(subnet.split(':')[1])
        subnet_prefix = ipstr[:ipstr.rfind('.')] + '.'
        subnet = [subnet_prefix + str(ip) for ip in range(start_ip, start_ip+num_ip)]
    else:
        if subnet.split('.')[3] == '0':
            subnet += '/24'

    DEBUG_ENABLE = opts.debug
    CANVAS_COLOR_TRANSP = opts.color_trans
    CANVAS_FREEZE = opts.freeze_gui
    APS_COORD_METHOD = opts.coord_method
    APS_COORD_NBRSCORE_ORDER = opts.nbrscore_order

    if opts.ext_delay:
        SSH_CMD_DELAY_EXTRA = opts.ext_delay
    if opts.meters_per_dot:
        CANVAS_METER_PER_DOT = opts.meters_per_dot
    if opts.nfloor_margin:
        RF_AVR_NFLOOR_MARGIN = opts.nfloor_margin
    if opts.smooth_window:
        RF_SMOOTH_WINDOW = opts.smooth_window

    
    # Quit when user press 'Ctrl+C'
    signal(SIGINT, quit_callback)

    # Keep detecting new APs when they're online
    t1 = threading.Thread(target=detect_new_aps, args=(subnet,), name="apsDetectThread")
    t1.setDaemon(True)  # This is needed to allow the main thread response to any interrupt
    t1.start()

    # Calculate each AP's location coordinate related to others
    t2 = threading.Thread(target=calc_ap_coord, args=(), name="apCoordCalThread")
    t2.setDaemon(True)
    t2.start()

    # Start GUI
    root = Tk()
    root.title('ACSPmon GUI')
    CANVAS = Canvas(root, width=CANVAS_WIDTH, height=CANVAS_HEIGHT, bg=CANVAS_COLOR)
    CANVAS.pack(expand=YES, fill=BOTH)
    CANVAS.bind('<Button-1>', mouse_selection_callback)
    CANVAS.bind('<Button-3>', mouse_menu_callback)
    CANVAS.bind('<Motion>', mouse_move_callback)
    CANVAS.bind('<ButtonRelease-1>', mouse_release_callback)
    root.bind('<Configure>', win_resize_callback)
    root.bind('<KeyPress>', key_press_callback)

    # GUI event handler
    root.mainloop()

    # The program doesn't quit by itself, press 'Ctrl+C'(possibly several times) to kill it
    while True:
        time.sleep(5)
        print APS


