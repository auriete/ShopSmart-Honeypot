# this is gonna be what statically detects and flags stuff inside the logs
import ast
import pandas as pd
import libinjection
import os
import dotenv

BF_WINDOW = os.getenv("BRUTE_FORCE_MAX_WINDOW")
BF_MAX_ATT = os.getenv("BRUTE_FORCE_MAX_ATTEMPTS")

def getdata(logname):
    with open(f"logs/{logname}") as l:
        return l.read().splitlines()


data = getdata("2026_11_04_015626.log")


def timestamp_correlate(data):
    
    timestamp_list = []
    ip_list = []

    for log in data:
        result = ast.literal_eval(log) # convert to dict
        timestamp_list.append(result["req"]["timestamp"])
        ip_list.append(result["req"]["remote_addr"])

    info = {
            'timestamps': timestamp_list,
            'ip_addrs': ip_list
        }

    return info # create a dict with the timestamps and addresses


def bf():
    times = timestamp_correlate(data)
    df = pd.DataFrame(times) #create a dataframe with the data, which is like a table in SQL kinda
    df['timestamps'] = pd.to_datetime(df['timestamps']) #convert every timestamp into an actual datetime object instead of just a string
    df = df.sort_values(by='timestamps').reset_index(drop=True) #sort the values by the timestamps so its cleaner, and reset the index so its still ordered nicely
    df = df.set_index('timestamps') #set the timestamps to be the index

    df['fast_attempts'] = (
        df.groupby('ip_addrs')['ip_addrs']  #group by ip addresses
          .rolling(window = BF_WINDOW) #in windows of 10 seconds (note: add rules file that determines the window, threshold size, etc later)
          .count() #count the occurences
          .reset_index(level=0, drop=True)
    )

    alerts = df[df['fast_attempts'] >= BF_MAX_ATT] #make a new dataframe with alerts, alerting when there are more than (threshold) requests in the window time
    alerts = alerts.reset_index()

    offending_addr = alerts['ip_addrs'].iloc[0] #iloc just gets the index, meaningthat this gets the first ip address
    num_attempts = alerts['fast_attempts'].iloc[-1]
    atk_start = alerts['timestamps'].iloc[0]
    atk_end = alerts['timestamps'].iloc[-1]

    print(f"Brute force detected: {num_attempts} requests from {atk_start} to {atk_end} by: {offending_addr}")


def sqli_detect():
    for log in data:
        result = ast.literal_eval(log)
        payload = result['req']['data'].partition("=")[2] #split the data so that its just the user input inside here
        result = libinjection.is_sql_injection(payload)
        if result["is_sqli"] == True:
            print(f"SQLi detected in event ID {result["event_id"]} at {result["timestamp"]}: {payload}")
            return True
        return False

def xss_detect():
    for log in data:
        result = ast.literal_eval(log)
        payload = result['req']['data'].partition("=")[2]
        result = libinjection.is_xss(payload)
        if result["is_xss"] == True:
             print(f"XSS detected in event ID {result["event_id"]} at {result["timestamp"]}: {payload}")
             return True
        return False

def main():
    sqli_detect()
    xss_detect()


if __name__ == '__main__':
    main()
