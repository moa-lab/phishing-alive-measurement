#!/usr/bin/bash

while true
do
    echo "crawl Start"
    start_time=$(date +%s)
    # bun run main.js &
    bun run main_test.js &
    bun_pid=$!
    sleep 1740
    end_time=$(date +%s)
    elapsed_time=$((end_time - start_time))

#    # Check if bun run main.js is still running after 30 minutes
    if ps -p $bun_pid > /dev/null; then
        echo "bun run main.js exceeded 30 minutes, killing..."
        python telegram_kill.py
        kill -9 $bun_pid
    fi

    python telegram.py
    echo "crawl is done"
    kill -9 $(ps -ef | grep chrome | grep -v grep | awk '{print $2}')
    kill -9 $(ps -ef | grep "bun run main_test.js" | grep -v grep | awk '{print $2}')
    echo "waiting...."
done

# cd ./puppeteer_alive/source/bun_js
# ./shutter.sh >> ~/alive_puppet.log 2>&1 &
# find ./puppeteer_alive/collected_data/apwg -type d -empty -delete
# sudo kill -9 `ps -ef | grep chrome | grep -v grep | awk '{print $2}'`

# DELETE FROM apwg_urls_to_check WHERE ROWID NOT IN (SELECT MIN(ROWID) FROM apwg_urls_to_check GROUP BY apwg_id);