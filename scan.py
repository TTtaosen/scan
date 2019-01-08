# python3
# -*- coding: utf-8 -*-
#--------------------#

import string
from random import *
import time
import socket
import re
import os
import requests
from colored import fg, bg
import multiprocessing as mp
import nmap 
import sys
import asyncio

#---------------------#
red = (fg(1))
white = (fg(15))
green = (fg(40))
end = '\033[0m'
yellow = '\33[93m'
cdcolor = (fg(63))
#---------------------#

#----------------------------------------#
menupscan = """
                  .-~~~~~~~~~-._       _.-~~~~~~~~~-.
              __.'              ~.   .~              `.__
            .'//                  \./                  \\`.
          .'//                     |                     \\`.
        .'// .-~"""""""~~~~-._     |     _,-~~~~"""""""~-. \\`.
      .'//.-"                 `-.  |  .-'                 "-.\\`.
    .'/H______.============-..   \ | /   ..-============.______\C`.
  .'______________________________\|/______________________________`.
                         easy scan    v 0.1
  """


Banner= """
                           _ooOoo_
                          o8888888o
                          88" . "88
                          (| -_- |)
                           O\ = /O
                       ____/`---'\____
                     .   ' \\| |// `.
                      / \\||| : |||// \\
                    / _||||| -:- |||||- \\
                      | | \\\ - /// | |
                    | \_| ''\---/'' | |
                     \ .-\__ `-` ___/-. /
                  ___`. .' /--.--\ `. . __
               ."" '< `.___\_<|>_/___.' >'"".
              | | : `- \`.;`\ _ /`;.`/ - ` : | |
                \ \ `-. \_ __\ /__ _/ .-` / /
        ======`-.____`-.___\_____/___.-`____.-'======
                           `H---C'
        .............................................
"""
#------------------------------------------#

def ipScan():
    os.system("cls")
    print(Banner)
    ip = input("Enter ip:")

    np = nmap.PortScanner()
    tmp = np.scan(ip,arguments='-sP')
    for host in np.all_hosts():
        print('Host:%s %s State: %s\n' % (host, np[host].hostname(),np[host].state()))

def pScan():
    os.system("cls")
    print(Banner)
    ip = input("Enter ip:")
    protrange = input("Enter protrange:")
    if protrange == "":
        protrange ='0-1024'
        
    np = nmap.PortScanner()
    tmp = np.scan(ip, protrange,arguments='-sT')
    
    for host in np.all_hosts():
        print('----------------------------------------------------')
        print('Host:%s (%s)'%(host, np[host].hostname()))
        print('State: %s' % np[host].state())
        for proto in np[host].all_protocols():
            print("--------")
            print('Protocol:%s'%proto)

            lport = np[host][proto].keys()
            for port in lport:
                print ('port : %s\tstate : %s  server: %s' % (port, np[host][proto][port]['state'],np[host][proto][port]['name']))

def osScan():
    os.system("cls")
    print(Banner)
    ip = input("Enter ip:")
    np = nmap.PortScanner()
    tmp = np.scan(ip, arguments='-sS -O')
    osInfor = np[ip].get('osmatch')
    result = []
    index = []
    for i in range(len(osInfor)):
        result.append(osInfor[i].get('name'))
        index.append(osInfor[i].get('accuracy'))
    res = index.index(max(index))
    print("OS: %s "% result[res])

def vulScan():
    os.system("cls")
    print(Banner)
    ip = input("Enter ip:")
    port = input("Enter port:")
    np = nmap.PortScanner()
    np.scan(ip,port,arguments='-sV --script nmap-vulners')
    for proto in np[ip].all_protocols():
        print("--------")
        print('Protocol:%s'%proto)
        lport = np[ip][proto].keys()
        for port in lport:
            try:    
                print(port)
                print(np[ip][proto][port]['script']['vulners'])
            except Exception as e:
                print("\tcon't found vulnerability")



def menu():
    inpmnu = str(input("""
    {0}[e]{1} exit
    {2}[b]{3} back to the main menu
    scan>""".format(red,end,yellow,end)
    ))
    if(inpmnu == 'b'):
        os.system("cls")
        scanner()
    elif(inpmnu == 'e'):
        quit()
    else:
        pass

def scanner():
    os.system("cls")
    print(menupscan)
    inpmnu = str(input("""
    {0}[1]{1} ip scan
    {0}[2]{1} port scan
    {0}[3]{1} os detection
    {0}[4]{1} vulnerability scanner
    {2}[e]{3} exit
    scan>""".format(yellow, end, red, end)
    ))
    def ifelif():
        if inpmnu == '1':
            ipScan()
            menu()
        if inpmnu == "2":
            pScan()
            menu()
        elif inpmnu == '3':
            osScan()
            menu()
        elif inpmnu == '4':
            vulScan()
            menu()
        elif inpmnu == 'e':
            quit()
        else:
            os.system("cls")
            scanner()
    ifelif()
            
            

if __name__ == "__main__":
    scanner()
