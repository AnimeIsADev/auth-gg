import os
import time
try:
    import requests
    import subprocess
    import tkinter
    from tkinter import messagebox
    import sys
    import hashlib
except Exception as e:
    print(f'Error -> {e}')
    time.sleep(2)
    os._exit(0)

root = tkinter.Tk()
root.withdraw()
hwid = str(subprocess.check_output('wmic csproduct get uuid')).split('\\r\\n')[1].strip('\\r').strip()
BUF_SIZE = 65536
md5 = hashlib.md5()
clear = lambda: os.system('cls')
try:
    with open(sys.argv[0], 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
except:
    messagebox.showerror('Auth.GG | Licensing System', 'Hash Calculating Failed')
    os._exit(0)
filehash = md5.hexdigest()

login_status = 0
register_status = 0
apikey = "UPDATE_ME" 
secret = "UPDATE_ME"
aid = "UPDATE_ME"
version = "1.0"
random = "your random code here"

def main():
    clear()
    os.system("title Auth Menu")
    print("[1] Login")
    print("[2] Register")
    print("[3] Redeem (extend subscription)")
    print("[4] Keybase | Login | Register | All-In-One")
    option = input("\n[?] ")
    if option == "1":
        login()
    elif option == "2":
        register()
    elif option == "3":
        redeem()
    elif option == "4":
        aio()
    else:
        print("\n[!] Invalid Option")
        time.sleep(2)
        os._exit(0)


def integrity_check():
    global login_status, register_status
    headers = {"User-Agent": "AuthGG"}
    data = {
        "type": "start",
        "random": random,
        "secret": secret,
        'aid': aid,
        'apikey': apikey
    }
    try:
        with requests.Session() as sess:
            sess.trust_env = False
            request_1 = sess.post("https://api.auth.gg/version2/api.php", verify=False,data=data, headers=headers)
            response_1 = request_1.json()
            flag1 = (response_1 == request_1.json())
            if flag1:
                if response_1["status"] == 'Failed':
                    messagebox.showerror("Auth.GG Licensing System", "This application is disabled!")
                    os._exit(0)
                if response_1['status'] == "Disabled":
                    messagebox.showerror("Auth.GG | Licensing System", "This application is disabled!")
                    os._exit(0)
                if response_1['developermode'] == 'Disabled':
                    if response_1['version'] != version:
                        messagebox.showinfo("Auth.GG | Licensing System", "Update [{}] is available!".format(response_1['version']))
                        os.system('start {}'.format(response_1['downloadlink']))
                        os._exit(0)
                    if response_1['hash'] != filehash:
                        messagebox.showerror("Auth.GG | Licensing System", "Hashes do not match, file tampering possible!")
                        os._exit(0)
                    if response_1['login'] != "Enabled":
                        login_status = 1
                    if response_1['register'] != "Enabled":
                        register_status = 1
                else:
                    messagebox.showinfo('Auth.GG | Licensing System', 'Developer mode is enabled, bypassing security checks!')
            else:
                os._exit(0)
    except:
            messagebox.showerror("Auth.GG Licensing System", "Something went wrong!")
            os._exit(0)     
def login():
    if login_status == 0:
        os.system('cls')
        os.system("title Login Menu")
        username = input("[?] Enter Username: ")
        password = input("[?] Enter Password: ")
        data = {
            "type": "login",
            "aid": aid,
            "random": random,
            'apikey': apikey,
            "secret": secret,
            "username": username,
            "password": password,
            "hwid": hwid
        }
        headers = {"User-Agent": "AuthGG"}
        try:
            with requests.Session() as sess:
                sess.trust_env = False
                request_2 = sess.post('https://api.auth.gg/version2/api.php',  verify=False,headers=headers, data=data)
                response_2 = request_2.text
                flag2 = (response_2 == request_2.text)
                if flag2:
                    if "success" in response_2:
                        print("\n[!] Welcome back, {}!".format(username))
                        time.sleep(2)
                        pass
                    else:
                        if "invalid_details" in response_2:
                            print("\n[!] Please check your credentials!")
                        elif "invalid_hwid" in response_2:
                            print("\n[!] Invalid HWID, please do not attempt to share accounts!")
                        elif "hwid_updated" in response_2:
                            print("\n[!] Your HWID has been updated, relogin!")
                        elif "time_expired" in response_2:
                            print("\n[!] Your subscription has expired!")
                        elif "net_error" in response_2:
                            print("\n[!] Something went wrong!")
                        else:
                            print("\n[!] Something went wrong!")
                        time.sleep(2)
                        os._exit(0)
                else:
                    os._exit(0)

        except:
            messagebox.showerror("Auth.GG Licensing System", "Something went wrong!")
            os._exit(0) 
    else:
        messagebox.showerror("Auth.GG Licensing System", "Login is not available at this time!")
        os._exit(0)  
def register():
    os.system('cls')
    os.system("title Register Menu")
    if register_status == 0:
        token = input("[?] Please enter token: ")
        email = input("[?] Please enter email: ")
        username = input("[?] Please enter username: ")
        password = input("[?] Please enter password: ")
        headers = {"User-Agent": "AuthGG"}
        data = {
            "type": "register",
            "aid": aid,
            "random": random,
            'apikey': apikey,
            "secret": secret,
            "username": username,
            "password": password,
            "email": email,
            "token": token,
            "hwid": hwid
        }
        try:
            with requests.Session() as sess:
                sess.trust_env = False
                request_3 = sess.post('https://api.auth.gg/version2/api.php',  verify=False,data=data, headers=headers)
                response_3 = request_3.text
                flag3 = (response_3 == request_3.text)
                if flag3:
                    if "success" in response_3:
                        print("\n[!] {}, you have successfully registered!".format(username))
                        time.sleep(2)
                        os._exit(0)
                    else:
                        if "invalid_token" in response_3:
                            print("\n[!] Token invalid or already used")
                        elif "invalid_username" in response_3:
                            print("\n[!] Username already taken, please choose another one")
                        elif "email_used" in response_3:
                            print('\n[!] Email is invalid or in use!')
                        else:
                            print("\n[!] Something went wrong!")
                        time.sleep(2)
                        os._exit(0)
                else:
                    os._exit(0)
        except:
            messagebox.showerror("Auth.GG Licensing System", "Something went wrong!")
            os._exit(0)      
    else:
        messagebox.showerror("Auth.GG Licensing System", "Register is not available at this time!")
        os._exit(0)  
def redeem():
    os.system('cls')
    os.system("title Redeem Menu") 
    username = input("[?] Enter Username: ")
    password = input("[?] Enter Password: ")
    token = input("[?] Please enter token: ")
    headers = {"User-Agent": "AuthGG"}
    data = {
            "type": "redeem",
            "aid": aid,
            "random": random,
            'apikey': apikey,
            "secret": secret,
            "username": username,
            "password": password,
            "token": token,
    }
    try:
        with requests.Session() as sess:
            sess.trust_env = False
            request_4 = sess.post("https://api.auth.gg/version2/api.php", verify=False, data=data, headers=headers)
            response_4 = request_4.text
            flag4 = (response_4 == request_4.text)
            if flag4:
                if "success" in response_4:
                    print("\n[!] Successfully redeemed license & extended subscription!")
                elif "invalid_token" in response_4:
                    print('\n[!] Invalid Credentials!')
                elif "net_error" in response_4:
                    print('\n[!] Something went wrong!')
                time.sleep(2)
                os._exit(0)
            else:
                os._exit(0)
    except:
        messagebox.showerror("Auth.GG Licensing System", "Something went wrong!")
        os._exit(0)
        

def aio():
    os.system('cls')
    os.system('title Keybase Menu')
    key_input = input("[?] Enter Key: ")
    def key_login(key):
        if login_status == 0:
            data = {
                "type": "login",
                "aid": aid,
                "random": random,
                'apikey': apikey,
                "secret": secret,
                "username": key,
                "password": key,
                "hwid": hwid
            }
            headers = {"User-Agent": "AuthGG"}
            try:
                with requests.Session() as sess:
                    sess.trust_env = False
                    request_5 = sess.post('https://api.auth.gg/version2/api.php', verify=False, headers=headers, data=data)
                    if "success" in request_5.text:
                        return True
                    else:
                        return False
            except:
                messagebox.showerror("Auth.GG Licensing System", "Something went wrong!")
                os._exit(0)
        else:
            messagebox.showerror("Auth.GG Licensing System", "Login is not available at this time!")
            os._exit(0)
    def key_register(key):
        if login_status == 0:
            data = {
                "type": "register",
                "aid": aid,
                "random": random,
                "secret": secret,
                "username": key,
                "password": key,
                "email": key,
                "token": key,
                "hwid": hwid
            }
            headers = {"User-Agent": "AuthGG"}
            try:
                with requests.Session() as sess:
                    sess.trust_env = False
                    request_6 = sess.post('https://api.auth.gg/version2/api.php',  verify=False,headers=headers, data=data)
                    if "success" in request_6.text:
                        return True
                    else:
                        return False
            except:
                messagebox.showerror("Auth.GG Licensing System", "Something went wrong!")
                os._exit(0)
        else:
            messagebox.showerror("Auth.GG Licensing System", "Register is not available at this time!")
            os._exit(0)  
    if key_login(key_input):
        print('\n[!] Auth Granted')
        time.sleep(2)
    else:
        if key_register(key_input):
            print('\n[!] You have successfully registered! ')
            time.sleep(2)
            os._exit(0)
        else:
            print("[!] Key is invalid!")
            time.sleep(2)
            os._exit(0)
            
                
if integrity_check():
    pass
else:
    main()
    
