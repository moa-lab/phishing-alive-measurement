# other_domain_extractor.py

import csv
import os, sys
import json
import re
import time
from glob import glob
from datetime import datetime, timezone, timedelta
import sqlite3
from urllib.parse import urlparse
from pytz import timezone as tz

root_dir_path = "./phishing/phishing-feeds-collection/"
data_collect_path = "./phishing/phishing-html-collection/"


def print_error(e):
    from datetime import datetime
    now = datetime.now()
    current_time = now.strftime("%Y-%m-%d %H:%M:%S")
    print("---------------------")
    print("Current Time =", current_time)
    print(e)
    # send_to_telegram(str(e))

# malware filter
def malware_filter_domain(directory): # Checked
    
    file_list = glob(os.path.join(directory, '**', '*.txt'), recursive=True)
    if file_list:
        latest_file = max(file_list, key=os.path.getmtime)
    else:
        return []
    
    with open(latest_file, 'r') as f:
        data = f.read().splitlines()
        
    pattern = r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$'
    filtered_domain = [s.replace('||', '') for s in data[6:] if not re.match(pattern, s.replace('||', ''))]
    
    return filtered_domain

def phishstats_domain(directory): # Checked
    current_time = datetime.now(timezone.utc)
    one_hour_ago = current_time - timedelta(hours = 1)
    file_list = glob(os.path.join(directory, '**', '*.txt'), recursive=True)
    filtered_files = [file for file in file_list if datetime.fromtimestamp(os.path.getmtime(file), tz=timezone.utc) > one_hour_ago]

    if filtered_files:
        latest_file = min(filtered_files, key=os.path.getmtime)
    else:
        print("Phishstats: No files found within the last hour.")
        return []

    filtered_domain = []
    with open(latest_file, 'r') as f:
        data = f.readlines()
    for row in data:
        if len(row.strip()) >= 3 and row.strip().startswith('"') and row.strip().endswith('"'):
            try:
                timestamp_str = row.strip().split(",")[0].strip('"')
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                if timestamp > current_time - timedelta(hours=1):
                    url = row.strip().split(",")[2].strip('"')
                    filtered_domain.append(url)
            except (ValueError, IndexError) as e:
                print("Error parsing row:", e)
                continue
    return filtered_domain

def phishtank_domain(directory):  # Checked
    current_time = datetime.now(timezone.utc)
    one_hour_ago = current_time - timedelta(hours=1)

    file_list = glob(os.path.join(directory, '**', '*.json'), recursive=True)
    filtered_files = [file for file in file_list if datetime.fromtimestamp(os.path.getmtime(file), tz=timezone.utc) > one_hour_ago]

    if filtered_files:
        latest_file = max(filtered_files, key=os.path.getmtime)
    else:
        print("Phishtank: No files found within the last hour.")
        return []

    filtered_domain = []
    try:
        with open(latest_file, 'r') as f:
            data = json.load(f)
            for item in data:
                verification_time = datetime.strptime(item['verification_time'], "%Y-%m-%dT%H:%M:%S+00:00").replace(tzinfo=timezone.utc)
                if verification_time > one_hour_ago:
                    url = item['url']
                    filtered_domain.append(url)
    except json.JSONDecodeError as e:
        print(f"Error parsing Phishtank JSON file: {latest_file}")
        print(f"JSONDecodeError: {str(e)}")

    return filtered_domain

# openphish
def openphish_domain(directory): # Checked
    file_list = glob(os.path.join(directory, '**', '*.txt'), recursive=True)
    if file_list:
        latest_file = max(file_list, key=os.path.getmtime)
    else:
        return []
    
    with open(latest_file, 'r') as f:
        data =f.read().splitlines()
        
    return data

# phishing_database
def phishing_database_domain(directory): #checked
    file_list = glob(os.path.join(directory, '**', '*.txt'), recursive=True)
    if file_list:
        latest_file = max(file_list, key=os.path.getmtime)
    else:
        return []
    
    with open(latest_file, 'r') as f:
        data =f.read().splitlines()
    return data

# phishunt
def phishunt_domain(directory):

    file_list = glob(os.path.join(directory, '**', '*.txt'), recursive=True)
    if file_list:
        latest_file = max(file_list, key=os.path.getmtime)
    else:
        return []
    
    with open(latest_file, 'r') as f:
        data =f.read().splitlines()
        
    return data

def url_extract(link):
    return urlparse(link).netloc

def insert_domains(domains, source):
    conn = sqlite3.connect(os.path.join(data_collect_path, 'phishing_domains.db'))
    c = conn.cursor()
    last_id = get_last_id()
    for domain in domains:
        try:
            last_id += 1
            c.execute("INSERT INTO domains (id, url, source) VALUES (?, ?, ?)", (last_id, url_extract(domain), source))
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()
    return last_id

def get_last_id():
    conn = sqlite3.connect(os.path.join(data_collect_path, 'phishing_domains.db'))
    c = conn.cursor()
    c.execute("SELECT MAX(id) FROM domains")
    last_id = c.fetchone()[0]
    conn.close()
    return last_id if last_id else 0

def create_database():
    conn = sqlite3.connect(os.path.join(data_collect_path, 'phishing_domains.db'))
    c = conn.cursor()
    c.execute(
                """CREATE TABLE IF NOT EXISTS dns_records_to_check (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                dns_server TEXT,
                source TEXT,
                trials INTEGER,
                updated_timestamp TEXT,
                first_failure_timestamp TEXT,
                second_failure_timestamp TEXT,
                third_failure_timestamp TEXT,
                UNIQUE(url, dns_server)
            )"""
    )
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS error_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT,
        dns_server TEXT,
        source TEXT,
        error_message TEXT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    conn.commit()
    conn.close()

def get_existing_domains(source):
    conn = sqlite3.connect(os.path.join(data_collect_path, 'phishing_domains.db'))
    c = conn.cursor()
    c.execute("SELECT url FROM domains WHERE source = ?", (source,))
    existing_domains = [row[0] for row in c.fetchall()]
    conn.close()
    return existing_domains

def get_processed_urls(source):
    conn = sqlite3.connect(os.path.join(data_collect_path, 'phishing_domains.db'))
    c = conn.cursor()
    c.execute("SELECT url FROM domains WHERE source = ?", (source,))
    processed_urls = [row[0] for row in c.fetchall()]
    conn.close()
    return processed_urls

def main():
    create_database()
    directory = {
        "malware_filter": root_dir_path + "malware-filter",
        "phishstats": root_dir_path + "phishstats",
        "phishtank": root_dir_path + "phishtank",
        "apwg": root_dir_path + "apwg",
        "openphish": root_dir_path + "openphish",
        "phishing_database": root_dir_path + "phishing_database",
        "phishunt": root_dir_path + "phishunt"
    }
    
    sources = [
        ("malware_filter", malware_filter_domain),
        ("phishstats", phishstats_domain),
        ("phishtank", phishtank_domain),
        ("openphish", openphish_domain),
        ("phishing_database", phishing_database_domain),
        ("phishunt", phishunt_domain)
    ]

    for source, domain_func in sources:
        # last_id = get_source_last_id(source)
        domains = domain_func(directory[source])
        last_id = insert_domains(domains, source)
        print(f"{source}: Last ID: {last_id}, Num of domains: {len(domains)}")

if __name__ == "__main__":
    main()