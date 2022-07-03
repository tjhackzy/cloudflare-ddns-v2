
#!/usr/bin/env python


__version__ = "1.0.1"

import json
import os
import signal
import sys
import threading
import time
import requests

CONFIG_PATH = os.environ.get('CONFIG_PATH', os.getcwd() + "/")

class GracefulExit:
  def __init__(self):
    self.kill_now = threading.Event()
    signal.signal(signal.SIGINT, self.exit_gracefully)
    signal.signal(signal.SIGTERM, self.exit_gracefully)

  def exit_gracefully(self, signum, frame):
    print("Stopping main thread...")
    self.kill_now.set()

def deleteEntries(type):
    # Helper function for deleting A or AAAA records
    # in the case of no IPv4 or IPv6 connection, yet
    # existing A or AAAA records are found.
    for option in config["cloudflare"]:
        print("Getting Zone information from CloudFlare API")
        answer = cf_api(
            "zones/" + option['zone_id'] + "/dns_records?per_page=100&type=" + type,
            "GET", option)
    if answer is None or answer["result"] is None:
        print("Error from getting Zone....pausing for 1 min")
        time.sleep(3)
        return
    for record in answer["result"]:
        identifier = str(record["id"])
        cf_api(
            "zones/" + option['zone_id'] + "/dns_records/" + identifier, 
            "DELETE", option)
        print("Deleted stale record " + identifier)

def getIPs():
    a = None
    aaaa = None
    global ipv4_enabled
    global ipv6_enabled
    global purgeUnknownRecords
    if ipv4_enabled:
        try:
            a = requests.get("https://1.1.1.1/cdn-cgi/trace").text.split("\n")
            a.pop()
            a = dict(s.split("=") for s in a)["ip"]
            print("Getting IPv4 - " + a)
        except Exception:
            global shown_ipv4_warning
            if not shown_ipv4_warning:
                shown_ipv4_warning = True
                print("IPv4 not detected")
            if purgeUnknownRecords:
                deleteEntries("A")
    if ipv6_enabled:
        try:
            aaaa = requests.get("https://[2606:4700:4700::1111]/cdn-cgi/trace").text.split("\n")
            aaaa.pop()
            aaaa = dict(s.split("=") for s in aaaa)["ip"]
        except Exception:
            global shown_ipv6_warning
            if not shown_ipv6_warning:
                shown_ipv6_warning = True
                print("IPv6 not detected")
            if purgeUnknownRecords:
                deleteEntries("AAAA")
    ips = {}
    if(a is not None):
        ips["ipv4"] = {
            "type": "A",
            "ip": a
        }
    if(aaaa is not None):
        ips["ipv6"] = {
            "type": "AAAA",
            "ip": aaaa
        }
    return ips

def commitRecord(ip):
    notification = False
    try:
        gotify_url = config["Gotify_BaseURL"]
        gotify_app_token = config["Gotify_AppToken"]
        gotify_notification_subject = config["Gotify_Notification_Title"]
        notification = True
        print("Gotify Settings found! URL:" + gotify_url + ", app-token:" + gotify_app_token)
    except:
        notification = False
        print("No Gotify Settings found!")
    for option in config["cloudflare"]:
        subdomains = option["subdomains"]
        response = cf_api("zones/" + option['zone_id'], "GET", option)
        if response is None or response["result"]["name"] is None:
            time.sleep(1)
            return
        base_domain_name = response["result"]["name"]
        ttl = 60 # default Cloudflare TTL
        for subdomain in subdomains:
            subdomain = subdomain.lower().strip()
            record = {
                "type": ip["type"],
                "name": subdomain.replace("#","@"),
                "content": ip["ip"],
                "proxied": option["proxied"],
                "ttl": option["ttls"]
            }
            dns_records = cf_api(
                "zones/" + option['zone_id'] + "/dns_records?per_page=100&type=" + ip["type"], 
                "GET", option)
            fqdn = base_domain_name
            if subdomain:
                fqdn = subdomain + "." + base_domain_name
            identifier = None
            modified = False
            duplicate_ids = []
            if dns_records is not None:
                for r in dns_records["result"]:
                    if (r["name"] == fqdn.replace("#.","")):
                        if identifier:
                            if r["content"] == ip["ip"]:
                                duplicate_ids.append(identifier)
                                identifier = r["id"]
                            else:
                                duplicate_ids.append(r["id"])
                        else:
                            identifier = r["id"]
                            if r['content'] != record['content'] or r['proxied'] != record['proxied'] or r['ttl'] != record["ttl"]:
                                modified = True
            if identifier:
                if modified:
                    print("Updating record " + str(record))
                    response = cf_api(
                        "zones/" + option['zone_id'] + "/dns_records/" + identifier,
                        "PUT", option, {}, record)
                    if notification:
                        send_push(gotify_notification_subject,"Record Updated! -" + str(record), gotify_url, gotify_app_token)
                else:
                    print("No need to update IP. IP is OK! (record-> " + str(record) + ")")
            else:
                print("Adding new record " + str(record))
                response = cf_api(
                    "zones/" + option['zone_id'] + "/dns_records", "POST", option, {}, record)
                if notification:
                    send_push(gotify_notification_subject,"Record Added! -" + str(record), gotify_url, gotify_app_token)
            if purgeUnknownRecords:
                for identifier in duplicate_ids:
                    identifier = str(identifier)
                    print("Deleting stale record " + identifier)
                    response = cf_api(
                        "zones/" + option['zone_id'] + "/dns_records/" + identifier,
                        "DELETE", option)
                    if notification:
                        send_push(gotify_notification_subject,"Record Deleted! -" + str(identifier), gotify_url, gotify_app_token)
    return True

def cf_api(endpoint, method, config, headers={}, data=False):
    api_token = config['authentication']['api_token']
    if api_token != '' and api_token != 'api_token_here':
        headers = {
            "Authorization": "Bearer " + api_token,
            **headers
        }
    else:
        headers = {
            "X-Auth-Email": config['authentication']['api_key']['account_email'],
            "X-Auth-Key": config['authentication']['api_key']['api_key'],
        }

    if(data == False):
        response = requests.request(
            method, "https://api.cloudflare.com/client/v4/" + endpoint, headers=headers)
    else:
        response = requests.request(
            method, "https://api.cloudflare.com/client/v4/" + endpoint,
            headers=headers, json=data)

    if response.ok:
        return response.json()
    else:
        print("Error sending '" + method + "' request to '" + response.url + "':")
        print(response.text)
        return None

def updateIPs(ips):
    for ip in ips.values():
        commitRecord(ip)

def send_push(title_msg, message_msg, url, apptoken):
    URL_PUSH = url + "/message?token="+ apptoken
    Param_Push = { 'title':title_msg, 'message':message_msg, 'priority':9 }
    r = requests.post(URL_PUSH, params=Param_Push)
    print("Gotify notification sent!")

if __name__ == '__main__':
    shown_ipv4_warning = False
    shown_ipv6_warning = False
    ipv4_enabled = True
    ipv6_enabled = True
    purgeUnknownRecords = False
    repeat_interval = 1

    if sys.version_info < (3, 5):
        raise Exception("This script requires Python 3.5+")

    config = None
    try:
        with open(CONFIG_PATH + "config.json") as config_file:
            config = json.loads(config_file.read())
    except:
        print("Error reading config.json")
        time.sleep(30) # wait 60 seconds to prevent excessive logging on docker auto restart

    if config is not None:
        try:
            ipv4_enabled = config["a"]
            ipv6_enabled = config["aaaa"]
            repeat_interval = config["interval"]
        except:
            ipv4_enabled = True
            ipv6_enabled = True
            print("Individually disable IPv4 or IPv6 with new config.json options.")
        try:
            purgeUnknownRecords = config["purgeUnknownRecords"]
        except:
            purgeUnknownRecords = False
            print("No config detected for 'purgeUnknownRecords' - defaulting to False")
        if(len(sys.argv) > 1):
            if(sys.argv[1] == "--repeat"):
                delay = repeat_interval*60
                print("Repeat Interval Set to : " + str(delay) + " (seconds)")
                if ipv4_enabled and ipv6_enabled:
                    print("Updating IPv4 (A) & IPv6 (AAAA) records every "+ str(repeat_interval) + " minutes")
                elif ipv4_enabled and not ipv6_enabled:
                    print("Updating IPv4 (A) records every "+ str(repeat_interval) + " minutes")
                elif ipv6_enabled and not ipv4_enabled:
                    print("Updating IPv6 (AAAA) records every "+ str(repeat_interval) + " minutes")
                next_time = time.time()
                killer = GracefulExit()
                prev_ips = None
                while True:
                    updateIPs(getIPs())
                    print("Waiting for Next time interval to trigger the update....")
                    if killer.kill_now.wait(delay):
                        break
            else:
                print("Unrecognized parameter '" + sys.argv[1] + "'. Stopping now.")
        else:
            updateIPs(getIPs())
