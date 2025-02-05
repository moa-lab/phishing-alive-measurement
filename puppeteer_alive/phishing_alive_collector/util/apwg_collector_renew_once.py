import requests
import json
import os
import time
import sqlite3
import glob

root_save_path = os.getenv("ROOT_SAVE_PATH", "./tmp/apwg")

def send_to_telegram(msg):
    msg = "[APWG Feed Collector] " + msg
    telegram_api_key = os.getenv("TELEGRAM_API_KEY")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    telegram_url = f"https://api.telegram.org/bot{telegram_api_key}/sendMessage?chat_id={chat_id}&text={msg}"
    requests.get(telegram_url)

def print_error(e):
    from datetime import datetime
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    print("---------------------")
    print("Current Time =", current_time)
    print(e)
    send_to_telegram(str(e))

def get_apwg_last_id(cursor):
    try:
        cursor.execute("SELECT apwg_id FROM apwg_last_id")
        result = cursor.fetchone()
        if result:
            return result
        else:
            # If the table is empty, insert an initial value of 0
            cursor.execute("INSERT INTO apwg_last_id (apwg_id) VALUES (?)", (0,))
            return 0
    except Exception as e:
        print_error(e)

def update_apwg_last_id(new_last_id, cursor, conn):
    try:
        cursor.execute("SELECT COUNT(*) FROM apwg_last_id")
        count = cursor.fetchone()[0]
        if count == 0:
            cursor.execute("INSERT INTO apwg_last_id (apwg_id) VALUES (?)", (new_last_id,))
        else:
            cursor.execute("UPDATE apwg_last_id SET apwg_id = ?", (new_last_id,))
        conn.commit()
    except Exception as e:
        print_error(e)

def get_phishings(last_id, retries=3):
    for attempt in range(retries):
        try:
            save_j_data = {"data": []}
            json_files = sorted(
                glob.glob(os.path.join(root_save_path, "phishing_data/**/*.json"), recursive=True), 
                reverse=True
            )
            for feed in json_files:                
                with open(feed, "r") as f:
                    j_data = json.load(f)
                for item in j_data["data"]:
                    if last_id is not None and int(last_id[0]) < item["id"]:
                        save_j_data["data"].append(item)
                    else:
                        break
                # print(save_j_data)

            return save_j_data
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            print_error(f"Attempt {attempt + 1} failed: {str(e)}")
            if attempt < retries - 1:
                time.sleep(5)  # Add a delay before retrying
            else:
                raise
    return {"data": []}

def update_url_trials(apwg_id, trials, cursor, conn):
    try:
        cursor.execute("UPDATE apwg_urls_to_check SET trials = ? WHERE apwg_id = ?", (trials, apwg_id))
        conn.commit()
    except Exception as e:
        print_error(e)
        
def save_json_file(data, file_path):
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)

def main():
    conn = sqlite3.connect(os.path.join(root_save_path, "phishing-alive.db"))
    cursor = conn.cursor()

    # Create tables if they don't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS apwg_last_id (
            apwg_id INTEGER
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS apwg_all_urls (
            apwg_id INTEGER PRIMARY KEY,
            url TEXT,
            brand TEXT,
            confidence INTEGER,
            status TEXT,
            discoveredAt INTEGER,
            createdAt INTEGER,
            updatedAt INTEGER,
            ip TEXT,
            asn TEXT,
            metadata TEXT,
            tld TEXT,
            trials INTEGER,
            updated_timestamp TEXT,
            first_failure_timestamp TEXT,
            second_failure_timestamp TEXT,
            third_failure_timestamp TEXT
        )
    """)    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS apwg_urls_to_check (
            apwg_id INTEGER PRIMARY KEY,
            apwg_url TEXT,
            trials INTEGER,
            first_failure_timestamp TEXT,
            second_failure_timestamp TEXT,
            third_failure_timestamp TEXT,
            added_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()

    save_j_data = {"data": []}
    last_id = get_apwg_last_id(cursor)
    print(f"current last id : {last_id}")
    # next_page_url = api_url
    # while True:
    try:
        tmp_j_data= get_phishings(last_id)
        save_j_data["data"].extend(tmp_j_data["data"])
        # if (len(tmp_j_data["data"]) < item_size) or (next_page_url is None):
        #     break
    except Exception as e:
        print_error(e)
    if len(save_j_data["data"]) == 0:
        send_to_telegram("Nothing to do")
        conn.close()
        return

    new_last_id = save_j_data["data"][0]["id"]
    print(f"new last id : {new_last_id}")
    for item in save_j_data["data"]:
        cursor.execute("""
        INSERT OR REPLACE INTO apwg_all_urls (
            apwg_id, url, brand, confidence, status, discoveredAt, createdAt, updatedAt,
            ip, asn, metadata, tld
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
        item["id"], item["url"], item["brand"], item["confidence"], item["status"],
        item["discoveredAt"], item["createdAt"], item["updatedAt"],
        json.dumps(item["ip"]), json.dumps(item["asn"]), json.dumps(item["metadata"]), item["tld"]
        ))
        
    cursor.execute("""
        INSERT OR IGNORE INTO apwg_urls_to_check (apwg_id, apwg_url, trials)
        SELECT apwg_id, url, 0
        FROM apwg_all_urls
        WHERE apwg_id >= 110240000
    """)
    conn.commit()

    update_apwg_last_id(new_last_id, cursor, conn)
    conn.close()

    send_to_telegram("Done. Num: " + str(len(save_j_data["data"])) + " new last id: " + str(new_last_id))

if __name__ == "__main__":
    main()