#!/usr/bin/env python2
import struct
import time
import requests
import numpy as np
import sys
import argparse
import json
import os
from Crypto.Cipher import AES
from bluepy.btle import Peripheral, DefaultDelegate, ADDR_TYPE_RANDOM


def getWifiName():

    ssid = os.popen("iwconfig wlp1s0 \
                    | grep 'ESSID' \
                    | awk '{print $4}' \
                    | awk -F\\\" '{print $2}'").read()

    return ssid

''' TODO
Key should be generated and stored during init
'''

UUID_SVC_MIBAND2 = "0000fee100001000800000805f9b34fb"
UUID_CHAR_AUTH = "00000009-0000-3512-2118-0009af100700"
UUID_SVC_ALERT = "0000180200001000800000805f9b34fb"
UUID_CHAR_ALERT = "00002a0600001000800000805f9b34fb"
UUID_SVC_HEART_RATE = "0000180d00001000800000805f9b34fb"
UUID_CHAR_HRM_MEASURE = "00002a3700001000800000805f9b34fb"
UUID_CHAR_HRM_CONTROL = "00002a3900001000800000805f9b34fb"

HRM_COMMAND = 0x15
HRM_MODE_SLEEP      = 0x00
HRM_MODE_CONTINUOUS = 0x01
HRM_MODE_ONE_SHOT   = 0x02

CCCD_UUID = 0x2902

class MiBand2(Peripheral):
    _KEY = b'\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x40\x41\x42\x43\x44\x45'
    _send_key_cmd = struct.pack('<18s', b'\x01\x08' + _KEY)
    _send_rnd_cmd = struct.pack('<2s', b'\x02\x08')
    _send_enc_key = struct.pack('<2s', b'\x03\x08')

    def __init__(self, addr):
        Peripheral.__init__(self, addr,
         addrType=ADDR_TYPE_RANDOM)
        print("Connected")

        svc = self.getServiceByUUID(UUID_SVC_MIBAND2)
        self.char_auth = svc.getCharacteristics(UUID_CHAR_AUTH)[0]
        self.cccd_auth = self.char_auth.getDescriptors(forUUID=CCCD_UUID)[0]

        svc = self.getServiceByUUID(UUID_SVC_ALERT)
        self.char_alert = svc.getCharacteristics(UUID_CHAR_ALERT)[0]

        svc = self.getServiceByUUID(UUID_SVC_HEART_RATE)
        self.char_hrm_ctrl = svc.getCharacteristics(UUID_CHAR_HRM_CONTROL)[0]
        self.char_hrm = svc.getCharacteristics(UUID_CHAR_HRM_MEASURE)[0]
        self.cccd_hrm = self.char_hrm.getDescriptors(forUUID=CCCD_UUID)[0]

        self.timeout = 5.0
        self.state = None
        # Enable auth service notifications on startup
        self.auth_notif(True)
        self.waitForNotifications(0.1) # Let Mi Band to settle

    def init_after_auth(self):
        self.cccd_hrm.write(b"\x01\x00", True)

    def encrypt(self, message):
        aes = AES.new(self._KEY, AES.MODE_ECB)
        return aes.encrypt(message)

    def auth_notif(self, status):
        if status:
            print("Enabling Auth Service notifications status...")
            self.cccd_auth.write(b"\x01\x00", True)
        elif not status:
            print("Disabling Auth Service notifications status...")
            self.cccd_auth.write(b"\x00\x00", True)
        else:
            print("Something went wrong while changing the Auth Service notifications status...")

    def send_key(self):
        print("Sending Key...")
        self.char_auth.write(self._send_key_cmd)
        self.waitForNotifications(self.timeout)

    def req_rdn(self):
        print("Requesting random number...")
        self.char_auth.write(self._send_rnd_cmd)
        self.waitForNotifications(self.timeout)

    def send_enc_rdn(self, data):
        print("Sending encrypted random number")
        cmd = self._send_enc_key + self.encrypt(data)
        send_cmd = struct.pack('<18s', cmd)
        self.char_auth.write(send_cmd)
        self.waitForNotifications(self.timeout)

    def initialize(self):
        self.setDelegate(AuthenticationDelegate(self))
        self.send_key()

        while True:
            self.waitForNotifications(0.1)
            if self.state == "AUTHENTICATED":
                return True
            elif self.state:
                return False

    def authenticate(self):
        self.setDelegate(AuthenticationDelegate(self))
        self.req_rdn()

        while True:
            self.waitForNotifications(0.1)
            if self.state == "AUTHENTICATED":
                return True
            elif self.state:
                return False

    def hrmStartContinuous(self):
        self.char_hrm_ctrl.write(b'\x15\x01\x01', True)

    def hrmStopContinuous(self):
        self.char_hrm_ctrl.write(b'\x15\x01\x00', True)


class AuthenticationDelegate(DefaultDelegate):

    heart_beat = ''

    """This Class inherits DefaultDelegate to handle the authentication process."""
    def __init__(self, device):
        DefaultDelegate.__init__(self)
        self.device = device

    def setHeartBeat(val):
        AuthenticationDelegate.heart_beat = val

    def handleNotification(self, hnd, data):
        # Debug purposes
        #print("HANDLE: " + str(hex(hnd)))
        #print("DATA: " + str(data.encode("hex")))
        if hnd == self.device.char_auth.getHandle():
            if data[:3] == b'\x10\x01\x01':
                self.device.req_rdn()
            elif data[:3] == b'\x10\x01\x04':
                self.device.state = "ERROR: Key Sending failed"
            elif data[:3] == b'\x10\x02\x01':
                random_nr = data[3:]
                self.device.send_enc_rdn(random_nr)
            elif data[:3] == b'\x10\x02\x04':
                self.device.state = "ERROR: Something wrong when requesting the random number..."
            elif data[:3] == b'\x10\x03\x01':
                print("Authenticated!")
                self.device.state = "AUTHENTICATED"
            elif data[:3] == b'\x10\x03\x04':
                print("Encryption Key Auth Fail, sending new key...")
                self.device.send_key()
            else:
                self.device.state = "ERROR: Auth failed"
            #print("Auth Response: " + str(data.encode("hex")))
        elif hnd == self.device.char_hrm.getHandle():
            rate = struct.unpack('bb', data)[1]
            #print(rate)
            #print(str(rate))
            AuthenticationDelegate.setHeartBeat(str(rate))
            # AAAA = str(rate)

            #print(array_rate)
           # print("Heart Rate: " + str(rate))
        else:
            print("Unhandled Response " + hex(hnd) + ": " + str(data.encode("hex")))

def analizeDataTrigger(mac):
	headers = {'Content-Type': 'text/html; charset=utf-8'}

	params = {'UserId' : mac}

	response = requests.get('http://api.mgsu41.tk/physical/api/PhysicalDataApi/analysisUserPhysicalData', headers=headers, params=params)


def setOnWork(mac):

    headers = {
        'Content-Type': 'text/html; charset=utf-8',
    }

    wifiName = getWifiName()

    params = {'Wifi' : wifiName[0:len(wifiName)-1],

		'UserId' : mac
}

    response = requests.get('http://api.mgsu41.tk/physical/api/PhysicalDataApi/isOnWork', headers=headers, params=params)

    return response.json()

#http://api.mgsu41.tk/physical/api/PhysicalDataApi/isOnWork?Wifi=GOSHA


def curlSendData(hr, mac):

    headers = {
        'Content-Type': 'text/html; charset=utf-8',
    }

    params = dataGenerate(hr, mac)

    response = requests.get('http://api.mgsu41.tk/physical/api/PhysicalDataApi/setUserPhysicalData', headers=headers, params=params)


def init(band):
    if band.initialize():
        print("Init ok")
        return True
    else:
        band.disconnect()
        return False

def dataGenerate(hr, mac):
    temperature = np.random.uniform(36.3, 36.8)
    temperature = round(temperature, 1)

    upper_pressure = np.random.randint(120, 140)

    low_pressure = np.random.randint(105, 118)

    a = (('HeartRate', str(hr)),
           ('UserId',str(mac)),
           ('Temp', str(temperature)),
           ('PressureHigh', str(upper_pressure)),
           ('PressureLow', str(low_pressure)))

    print(a)
    return a

# http://api.mgsu41.tk/physical/api/PhysicalDataApi/setUserPhysicalData?UserId=123&HeartRate=123&Temp=36.6&PressureHigh=130&PressureLow=70

def main(host):
    """ main func """

    print('Connecting to ' + host)
    band = MiBand2(host)
    band.setSecurityLevel(level="medium")

    init(band)


    band.authenticate()#херня для входа в систему
    band.init_after_auth()

    return band
        #print(AuthenticationDelegate.heart_beat)

    # if arg.notify: #отпправка уведомления
    #     print("Sending message notification...")
    #     band.char_alert.write(b'\x01')
    #     time.sleep(arg.t)
    #     print("Sending phone notification...")
    #     band.char_alert.write(b'\x02')
    #     time.sleep(arg.t)
    #     print("Turning off notifications...")
    #     band.char_alert.write(b'\x00')
    #
    # if arg.heart: #отпправка данных ЭКГ
    #     print("Cont. HRM start")
    #     band.hrmStopContinuous()
    #     band.hrmStartContinuous()
    #
    #     band.waitForNotifications(1.0)

    # print("Disconnecting...")
    # band.disconnect()
    # del band

# {#  TODO сделать  фунц #
if __name__ == "__main__":


	dataSendCounter = 0
	mac = 'CC:D8:71:05:DA:65'

	band = main(mac)

	setOnWork(mac)



	while True:
		if ((dataSendCounter % 2 == 0) & (dataSendCounter >= 2)):
			analizeDataTrigger(mac)
		dataSendCounter += 1
		band.hrmStopContinuous()
		band.hrmStartContinuous()
	
		for i in range(30):
			if(band.waitForNotifications(1.0)):
				curlSendData(AuthenticationDelegate.heart_beat, mac)
			else:
				continue
