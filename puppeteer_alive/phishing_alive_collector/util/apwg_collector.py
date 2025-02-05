import requests
import json
import os
import time
import sqlite3
import glob
from json.decoder import JSONDecodeError

root_save_path = os.getenv("ROOT_SAVE_PATH", "./tmp/apwg")

def handle_json_file(file_path):
    """
    Safely handle JSON file reading with detailed error reporting
    """
    try:
        with open(file_path, "r", encoding='utf-8') as f:
            content = f.read()
            try:
                return json.loads(content)
            except JSONDecodeError as e:
                # Try to get context around the error
                error_context = content[max(0, e.pos-50):min(len(content), e.pos+50)]
                error_message = f"""
                JSON Parse Error in file {file_path}:
                Error: {str(e)}
                Position: {e.pos}
                Line: {e.lineno}, Column: {e.colno}
                Context around error: {error_context}
                """
                print_error(error_message)
                return None
    except Exception as e:
        print_error(f"File reading error for {file_path}: {str(e)}")
        return None

def validate_json_item(item):
    """
    Validate that a JSON item has all required fields
    """
    required_fields = ["id", "url", "brand", "confidence", "status", "discoveredAt", 
                      "createdAt", "updatedAt", "ip", "asn", "metadata", "tld"]
    return all(field in item for field in required_fields)

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
            return result[0]  # Return just the integer value
        else:
            # If the table is empty, insert an initial value of 0
            cursor.execute("INSERT INTO apwg_last_id (apwg_id) VALUES (?)", (0,))
            return 0
    except Exception as e:
        print_error(e)
        return 0

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
                print(f"Processing file: {feed}")  # Debug logging
                j_data = handle_json_file(feed)
                
                if j_data is None:
                    print(f"Skipping corrupted file: {feed}")
                    continue
                    
                if not isinstance(j_data, dict) or "data" not in j_data:
                    print(f"Invalid JSON structure in file: {feed}")
                    continue
                
                try:
                    for item in j_data["data"]:
                        # Validate item structure
                        if not isinstance(item, dict) or "id" not in item:
                            print(f"Invalid item structure in {feed}")
                            continue
                            
                        if last_id is not None and last_id < item["id"]:
                            save_j_data["data"].append(item)
                        else:
                            # We've reached older entries, can break the loop
                            return save_j_data
                except Exception as e:
                    print_error(f"Error processing items in {feed}: {str(e)}")
                    continue

            return save_j_data
            
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            print_error(f"Attempt {attempt + 1} failed: {str(e)}")
            if attempt < retries - 1:
                time.sleep(5)
            else:
                raise
        except Exception as e:
            print_error(f"Unexpected error in get_phishings: {str(e)}")
            if attempt < retries - 1:
                time.sleep(5)
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

    try:
        # Create tables (your existing table creation code)
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
        
        try:
            tmp_j_data = get_phishings(last_id)
            if tmp_j_data and "data" in tmp_j_data:
                save_j_data["data"].extend(tmp_j_data["data"])
            else:
                print("No valid data returned from get_phishings")
        except Exception as e:
            print_error(f"Error getting phishings: {str(e)}")
            conn.close()
            return
            
        if len(save_j_data["data"]) == 0:
            send_to_telegram("Nothing to do")
            conn.close()
            return

        # Validate and process data
        valid_items = []
        for item in save_j_data["data"]:
            if validate_json_item(item):
                valid_items.append(item)
            else:
                print(f"Skipping invalid item: {item.get('id', 'unknown id')}")

        if not valid_items:
            print_error("No valid items found in the data")
            conn.close()
            return

        new_last_id = valid_items[0]["id"]
        print(f"new last id : {new_last_id}")
        
        # Process valid items
        for item in valid_items:
            try:
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
                
                if item["brand"] != "National Police Agency JAPAN":
                    cursor.execute("""
                        INSERT OR REPLACE INTO apwg_urls_to_check (apwg_id, apwg_url, trials)
                        VALUES (?, ?, ?)
                    """, (item["id"], item["url"], 0))
            except sqlite3.Error as e:
                print_error(f"Database error processing item {item['id']}: {str(e)}")
                continue

        conn.commit()
        update_apwg_last_id(new_last_id, cursor, conn)
        send_to_telegram(f"Done. Num: {len(valid_items)} new last id: {new_last_id}")

    except Exception as e:
        print_error(f"Main execution error: {str(e)}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    main()