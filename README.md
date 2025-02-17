# Phishing Alive Collector

7 Days Later: Analyzing Phishing-Site Lifespan After Detected  
Kiho Lee$`^*`$, Kyungchan Lim$`^*`$, Hyoungshick Kim$`^†`$, Yonghwi Kwon$`^‡`$, and Doowon Kim$`^*`$

University of Tennessee, Knoxville$`^*`$, Sungkyunkwan University$`^†`$, and University of Maryland$`^‡`$

## Abstract

Phishing attacks continue to be a major threat to internet users, causing data breaches, financial losses, and identity theft. This study provides an in-depth analysis of the lifespan and evolution of phishing websites, focusing on their survival strategies and evasion techniques. We analyze 286,237 unique phishing URLs over five months using a custom web crawler based on Puppeteer and Chromium. Our crawler runs on a 30-minute cycle, systematically checking the operational status of phishing websites by collecting their HTTP status codes, screenshots, HTML, and HTTP data. Temporal and survival analyses, along with statistical tests, are used to examine phishing website lifecycles, evolution, and evasion tactics. Our findings show that the average lifespan of phishing websites is 54 hours (2.25 days) with a median of 5.46 hours, indicating rapid takedown of many sites while a subset remains active longer. Interestingly, logistic-themed phishing websites (e.g., USPS) operate within a compressed timeframe (1.76 hours) compared to other brands (e.g., Facebook). We further analyze detection effectiveness using Google Safe Browsing (GSB). We find that GSB detects only 18.4% of phishing websites, taking an average of 4.5 days. Notably, 83.93% of phishing sites are already taken down before GSB detection, meaning GSB requires more prompt detection. Moreover, 16.07% of phishing sites persist beyond this point, surviving for an additional 7.2 days on average, resulting in an average total lifespan of approximately 12 days. We reveal that DNS resolution error is the main cause (67%) of phishing website takedowns. Finally, we uncover that phishing sites with extensive visual changes (more than 100 times) exhibit a median lifespan of 17 days, compared to 1.93 hours for those with minimal modifications. These results highlight the dynamic nature of phishing attacks, the challenges in detection and prevention, and the need for more rapid and comprehensive countermeasures against evolving phishing tactics.


## Project Structure

```
.
├── create_table.sql
└── puppeteer_alive
    ├── README.md
    ├── bun_js
    │   ├── README.md
    │   ├── bun.lockb
    │   ├── create_table.sql
    │   ├── jsconfig.json
    │   ├── main.js
    │   ├── main_test.js
    │   ├── other_feeds.sql
    │   ├── package.json
    │   ├── requirements.txt
    │   ├── shutter.sh
    │   └── test_temp.js
    ├── package.json
    └── phishing_alive_collector
        └── util
            ├── apwg_collector.py
            ├── apwg_collector_renew_once.py
            └── other_domain_extractor.py
```

## Data Structure
```
.
└── alive_puppeteer_data_first_small_batch
	├── 2024-04-17-05:28
	│   ├── status_code.txt
	│   ├── headers.json
	│   ├── domain_url.txt
	│   ├── error.log
	│   ├── page.html
	│   └── screenshot.jpg
    ├── 2024-04-17-07:47
	│   ├── status_code.txt
	│   ├── headers.json
	│   ├── domain_url.txt
	│   ├── error.log
	│   ├── page.html
	│   └── screenshot.jpg
	└── ...
```


## Prerequisites

- Node.js
- Bun.js
- Python 3.x

## Installation

1. **Clone the repository:**

    ```sh
    git clone https://github.com/moa-lab/phishing-alive-measurement.git
    cd phishing-alive-measurement/puppeteer_alive/bun_js
    ```

2. **Install Bun.js:**

    Follow the instructions on the [Bun.js website](https://bun.sh/) to install Bun.

3. **Initialize and install dependencies:**

    ```sh
    cd ./puppeteer_alive/
    bun init
    bun install
    ```

4. **Install Python dependencies:**

    ```sh
    pip install -r requirements.txt
    ```

## Usage

1. **Set the DEBUG environment variable for troubleshooting:**

    ```sh
    export DEBUG='puppeteer:*'
    ```

2. **Run the main script:**

    ```sh
    bun run main.js
    ```

3. **Run the test script:**

    ```sh
    bun run main_test.js
    ```

4. **Single Execution:**

    To execute the script for a single run, use the following commands:

    ```sh
    # install dependencies:
          bun init
          bun install
    # execute: NB to troubleshoot set the DEBUG env variable and set {headless:false,dumpio:true} in main.js.
          export DEBUG='puppeteer:*'
          bun run main.js
    ```

## Configuration

- **Database Path:** Update the `dbPath` variable in `main.js` and `main_test.js` to point to your SQLite database.
- **Root Directory Path:** Update the `rootDirPath` variable in `main.js` and `main_test.js` to point to your data directory.
- **Benign Domains:** Update the `benignDomains` array in `main.js` and `main_test.js` to include domains you want to skip.

## Troubleshooting

- **Headless Mode:** To run the browser in non-headless mode for debugging, set `{headless: false, dumpio: true}` in `main.js` and `main_test.js`.
- **Error Logs:** Detailed error logs are written to the specified output directory. Check these logs for more information on any issues encountered.
