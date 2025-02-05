// install dependencies:
//      bun init
//      bun install
// execute:
// NB to troubleshoot set the DEBUG env variable and set {headless:false,dumpio:true} in main.js.
//      export DEBUG='puppeteer:*'
//      bun run main.js

import {
    program
} from "commander";
import {
    PUPPETEER_REVISIONS
} from "puppeteer-core/internal/revisions.js";
import * as browsers from "@puppeteer/browsers";
import os from "os";
import fs from "fs-extra";
import path from 'path';
import rxjs from "rxjs";
import {
    Database
} from 'bun:sqlite';
import { promises } from 'node:dns';
import doh from 'dohjs';
import { log, time } from "console";

const { exec } = require('child_process');
const puppeteer = require('puppeteer');
const {addExtra} = require('puppeteer-extra');
// const anonymizeUaPlugin = require('puppeteer-extra-plugin-anonymize-ua');
// const DevToolsPlugin = require('puppeteer-extra-plugin-devtools');
// puppeteer.use(stealthPlugin());
// puppeteer.use(anonymizeUaPlugin());
const stealthPlugin = require('puppeteer-extra-plugin-stealth');
const stealth = stealthPlugin();
const pextra = addExtra(puppeteer);

for (const item of [stealth]){
    pextra.use(item);
}

process.env.REBROWSER_PATCHES_RUNTIME_FIX_MODE = "alwaysIsolated"


const {
    lastValueFrom
} = require("rxjs");
const {
    mergeMap,
    toArray,
    timeout
} = require("rxjs/operators");

const rootDirPath = "./puppeteer_alive/collected_data/";
const dbPath = path.join(`${rootDirPath}/phishing-feeds-collection/apwg`, "phishing-alive.db")
const benignDomains = [
    "www.google.com", "google.com", "www.facebook.com", "facebook.com", "irs.gov", "www.irs.gov", "www.usps.com"
];

const ERROR_CATEGORIES = {
    DNS: 'DNSError',
    NETWORK: 'NetworkError',
    SSL: 'SSLError',
    TIMEOUT: 'TimeoutError',
    NAVIGATION: 'NavigationError',
    BROWSER: 'BrowserError',
    PROTOCOL: 'ProtocolError',
    SCREENSHOT: 'ScreenshotError',
    CONTENT: 'ContentError',
    VALIDATION: 'ValidationError',
    UNKNOWN: 'UnknownError'
};

const errorCounts = {
    dns: 0,
    network: 0,
    ssl: 0,
    timeout: 0,
    navigation: 0,
    browser: 0,
    protocol: 0,
    screenshot: 0,
    content: 0,
    validation: 0,
    unknown: 0
};

async function getDnsInfo(domain) {
    const resolver = new promises.Resolver();
    resolver.setServers(['1.1.1.1', '8.8.8.8', '9.9.9.9']);

    const dnsInfo = {
        timestamp: new Date().toISOString(),
        domain: domain,
        a_records: null,
        soa_record: null,
        ns_records: null,
        mx_records: null,
        txt_records: null,
        errors: {}
    };

    try {
        // Get A records with TTL
        dnsInfo.a_records = await resolver.resolve4(domain, { ttl: true });
    } catch (error) {
        dnsInfo.errors.a = error.message;
    }

    try {
        // Get SOA record with TTL
        dnsInfo.soa_record = await resolver.resolveSoa(domain);
    } catch (error) {
        dnsInfo.errors.soa = error.message;
    }

    try {
        // Get NS records
        dnsInfo.ns_records = await resolver.resolveNs(domain);
    } catch (error) {
        dnsInfo.errors.ns = error.message;
    }

    try {
        // Get MX records
        dnsInfo.mx_records = await resolver.resolveMx(domain);
    } catch (error) {
        dnsInfo.errors.mx = error.message;
    }

    try {
        // Get TXT records
        dnsInfo.txt_records = await resolver.resolveTxt(domain);
    } catch (error) {
        dnsInfo.errors.txt = error.message;
    }

    return dnsInfo;
    }

// Additional function for DoH queries as backup
async function getDohInfo(domain) {
    const providers = {
        cloudflare: 'https://cloudflare-dns.com/dns-query',
        google: 'https://dns.google/resolve',
        quad9: 'https://dns.quad9.net:5053/dns-query'
    };

    const results = {};

    for (const [provider, endpoint] of Object.entries(providers)) {
        try {
        const response = await fetch(`${endpoint}?name=${domain}&type=A&ct=application/dns-json`, {
            headers: {
            'Accept': 'application/dns-json'
            }
        });
        results[provider] = await response.json();
        } catch (error) {
        results[provider] = { error: error.message };
        }
    }

    return results;
}

function formatDnsResults(dnsInfo) {
    const mergedResults = {
        timestamp: dnsInfo.timestamp,
        domain: dnsInfo.domain,
        records: {
        a: dnsInfo.a_records ? dnsInfo.a_records.map(record => ({
            type: 'A',
            address: record.address,
            ttl: record.ttl
        })) : [],
        
        soa: dnsInfo.soa_record ? {
            type: 'SOA',
            primary_nameserver: dnsInfo.soa_record.nsname,
            hostmaster: dnsInfo.soa_record.hostmaster,
            serial: dnsInfo.soa_record.serial,
            refresh: dnsInfo.soa_record.refresh,
            retry: dnsInfo.soa_record.retry,
            expire: dnsInfo.soa_record.expire,
            minimum_ttl: dnsInfo.soa_record.minttl
        } : null,
        
        ns: dnsInfo.ns_records ? dnsInfo.ns_records.map(ns => 
            JSON.parse(JSON.stringify({
            type: 'NS',
            nameserver: ns
            }))
        ) : [],
        
        mx: dnsInfo.mx_records ? dnsInfo.mx_records.map(mx => 
            JSON.parse(JSON.stringify({
            type: 'MX',
            priority: mx.priority,
            exchange: mx.exchange
            }))
        ) : [],
        
        txt: dnsInfo.txt_records ? dnsInfo.txt_records.map(txt => 
            JSON.parse(JSON.stringify({
            type: 'TXT',
            value: txt.join(' ')
            }))
        ) : []
        },
        errors: Object.keys(dnsInfo.errors).length > 0 ? dnsInfo.errors : null,
        metadata: {
        total_records: 0,
        has_errors: Object.keys(dnsInfo.errors).length > 0,
        resolution_servers: ['1.1.1.1', '8.8.8.8', '9.9.9.9']
        }
    };
    
    // Calculate total records
    mergedResults.metadata.total_records = 
        mergedResults.records.a.length +
        (mergedResults.records.soa ? 1 : 0) +
        mergedResults.records.ns.length +
        mergedResults.records.mx.length +
        mergedResults.records.txt.length;
    
    // Force full serialization
    return JSON.parse(JSON.stringify(mergedResults));
}

async function trackError(error, category, url, additionalInfo = {}) {
    // Increment category counter
    errorCounts[category.toLowerCase().replace('error', '')] += 1;

    // Log detailed error stats periodically or when requested
    if (Object.values(errorCounts).reduce((a, b) => a + b, 0) % 100 === 0) {
        console.log('\nError Statistics:');
        for (const [category, count] of Object.entries(errorCounts)) {
            if (count > 0) {
                console.log(`${category}: ${count}`);
            }
        }
    }

    // Return enriched error info
    return {
        category,
        timestamp: new Date().toISOString(),
        url,
        error: {
            name: error.name,
            message: error.message,
            stack: error.stack
        },
        ...additionalInfo
    };
}

function categorizeError(error) {
    const msg = error.message.toLowerCase();
    
    // DNS Errors
    if (msg.includes('err_name_not_resolved') || 
        msg.includes('err_dns_fail') ||
        msg.includes('connection refused')) {
        return ERROR_CATEGORIES.DNS;
    }
    
    // Network Errors
    if (msg.includes('err_internet_disconnected') || 
        msg.includes('err_connection_reset') ||
        msg.includes('err_connection_closed') ||
        msg.includes('err_network_changed')) {
        return ERROR_CATEGORIES.NETWORK;
    }
    
    // SSL Errors
    if (msg.includes('err_ssl_protocol_error') || 
        msg.includes('err_cert_') || 
        msg.includes('ssl_error')) {
        return ERROR_CATEGORIES.SSL;
    }
    
    // Timeout Errors
    if (msg.includes('timeout') || 
        msg.includes('err_timed_out') ||
        msg.includes('navigation timeout')) {
        return ERROR_CATEGORIES.TIMEOUT;
    }
    
    // Navigation Errors
    if (msg.includes('err_aborted') || 
        msg.includes('err_failed_load') ||
        msg.includes('navigation failed')) {
        return ERROR_CATEGORIES.NAVIGATION;
    }
    
    // Browser Errors
    if (msg.includes('target closed') || 
        msg.includes('browser disconnected') ||
        msg.includes('browser has disconnected')) {
        return ERROR_CATEGORIES.BROWSER;
    }
    
    // Protocol Errors
    if (msg.includes('protocol error') || 
        msg.includes('protocolTimeout')) {
        return ERROR_CATEGORIES.PROTOCOL;
    }
    
    // Screenshot Errors
    if (msg.includes('screenshot') || 
        msg.includes('capture failed')) {
        return ERROR_CATEGORIES.SCREENSHOT;
    }
    
    // Content Errors
    if (msg.includes('content failed') || 
        msg.includes('err_invalid_response')) {
        return ERROR_CATEGORIES.CONTENT;
    }
    
    return ERROR_CATEGORIES.UNKNOWN;
}


const minimal_args = [
    '--start-maximized',
    '--disable-gpu',
    '--disable-infobars',
    '--disable-browser-side-navigation',
    '--ignore-certificate-errors-skip-list',
    '--disable-accelerated-2d-canvas',
    '--disable-component-extensions-with-background-pages',
    '--disable-features=Translate,TranslateUI,BlinkGenPropertyTrees,IsolateOrigins,site-per-process,AudioServiceOutOfProcess,OptimizationHints,MediaRouter,DialMediaRouteProvider,CalculateNativeWinOcclusion,InterestFeedContentSuggestions,CertificateTransparencyComponentUpdater,AutofillServerCommunication,PrivacySandboxSettings4,AutomationControlled',
    '--enable-features=NetworkService,NetworkServiceInProcess',
    '--autoplay-policy=user-gesture-required',
    '--disable-background-networking',
    '--disable-background-timer-throttling',
    '--disable-backgrounding-occluded-windows',
    '--disable-breakpad',
    '--disable-client-side-phishing-detection',
    '--disable-component-update',
    '--disable-default-apps',
    '--disable-dev-shm-usage',
    '--disable-domain-reliability',
    '--disable-extensions',
    '--disable-gpu-sandbox',
    '--disable-hang-monitor',
    '--disable-ipc-flooding-protection',
    '--disable-notifications',
    '--disable-offer-store-unmasked-wallet-cards',
    '--disable-popup-blocking',
    '--disable-print-preview',
    '--disable-prompt-on-repost',
    '--disable-renderer-backgrounding',
    '--disable-setuid-sandbox',
    '--disable-speech-api',
    '--disable-sync',
    '--disable-web-security',
    '--hide-scrollbars',
    '--ignore-gpu-blacklist',
    '--ignore-certificate-errors',
    '--metrics-recording-only',
    '--mute-audio',
    '--no-default-browser-check',
    '--no-first-run',
    '--no-pings',
    '--no-sandbox',
    '--no-zygote',
    '--password-store=basic',
    '--proxy-server="direct://"',
    '--proxy-bypass-list=*',
    '--use-gl=swiftshader',
    '--use-mock-keychain',
    '--disable-blink-features=AutomationControlled',
    '--webview-disable-safebrowsing-support',
    '--disable-client-side-phishing-detection',
];

async function writeDetailedErrorLog(errorLogPath, url, error, additionalInfo = {}) {
    const errorCategory = categorizeError(error);
    const timestamp = new Date().toISOString();
    
    // Track the error
    const trackedError = await trackError(error, errorCategory, url, additionalInfo);
    
    const errorDetails = {
        ...trackedError,
        errorCategory: errorCategory,
        errorCode: error.code || 'N/A',
        ...additionalInfo
    };

    // Add error context based on category
    const errorContext = {};
    
    switch (errorCategory) {
        case ERROR_CATEGORIES.DNS:
            try {
                const resolver = new Resolver();
                errorContext.dnsDetails = {
                    hostname: new URL(url).hostname,
                    lookupAttempts: await resolver.resolveAny(new URL(url).hostname).catch(() => 'Failed'),
                    previousAttempts: additionalInfo.previousAttempts || 0,
                    timestamp: Date.now()
                };
            } catch (e) {
                errorContext.dnsDetails = { error: 'Failed to get DNS details' };
            }
            break;
            
        case ERROR_CATEGORIES.NETWORK:
            errorContext.networkDetails = {
                lastResponseCode: additionalInfo.lastResponseCode,
                headers: additionalInfo.headers,
                connectionType: additionalInfo.connectionType,
                timestamp: Date.now()
            };
            break;
            
        case ERROR_CATEGORIES.SSL:
            errorContext.sslDetails = {
                protocol: additionalInfo.sslProtocol,
                cipher: additionalInfo.sslCipher,
                certificateError: additionalInfo.certError,
                timestamp: Date.now()
            };
            break;
            
        case ERROR_CATEGORIES.TIMEOUT:
            errorContext.timeoutDetails = {
                duration: additionalInfo.timeoutDuration || 25000,
                type: additionalInfo.timeoutType || 'navigation',
                lastState: additionalInfo.lastKnownState,
                timestamp: Date.now()
            };
            break;
            
        case ERROR_CATEGORIES.BROWSER:
            errorContext.browserDetails = {
                isConnected: additionalInfo.context?.browserState?.isConnected,
                pagesCount: additionalInfo.context?.browserState?.pagesCount,
                timestamp: Date.now()
            };
            break;
    }

    // Combine all error information
    const fullErrorDetails = {
        ...errorDetails,
        context: {
            ...errorDetails.context,
            errorSpecific: errorContext
        }
    };

    // Write detailed error log
    const errorLog = `
=== Error Report ===
Timestamp: ${timestamp}
URL: ${url}
Error Category: ${errorCategory}
Error Type: ${error.name}
Error Message: ${error.message}
Error Code: ${error.code || 'N/A'}

Category-Specific Details:
${JSON.stringify(errorContext, null, 2)}

Stack Trace:
${error.stack}

Additional Context:
${JSON.stringify(additionalInfo.context || {}, null, 2)}

Error Statistics:
${Object.entries(errorCounts)
    .filter(([_, count]) => count > 0)
    .map(([category, count]) => `${category}: ${count}`)
    .join('\n')}
===================
`;

    // Write both human-readable and JSON versions
    await fs.writeFile(errorLogPath, errorLog);
    const jsonLogPath = errorLogPath.replace('.log', '.json');
    await fs.writeFile(jsonLogPath, JSON.stringify(fullErrorDetails, null, 2));

    // Create a category-based symlink for easier analysis
    const categoryDir = path.join(path.dirname(errorLogPath), '..', 'error-categories', errorCategory);
    await fs.mkdirp(categoryDir);
    
    // Also create timestamp-based directory for temporal analysis
    const timeDir = path.join(path.dirname(errorLogPath), '..', 'error-timeline', 
        new Date().toISOString().split('T')[0]);
    await fs.mkdirp(timeDir);
    
    // Create symlinks
    try {
        await fs.symlink(errorLogPath, path.join(categoryDir, path.basename(errorLogPath)));
        await fs.symlink(errorLogPath, path.join(timeDir, path.basename(errorLogPath)));
    } catch (e) {
        // Symlink might already exist, ignore
    }
    
    return errorCategory;
}

async function gettingUrls() {
    const db = new Database(dbPath);
    if (!db.query("PRAGMA table_info(apwg_all_urls)").all().some(column => column.name === "directory")) {
        db.run("ALTER TABLE apwg_all_urls ADD COLUMN directory TEXT");
    }
    const rows = db.query("SELECT * FROM apwg_urls_to_check").all();
    db.close();
    const urls = rows
        .filter(row => row.trials < 3)
        .map(row => ({
            apwg_id: row.apwg_id,
            url: row.apwg_url
        }));
    log(`Number of URLs ${urls.length}`);
    return urls;
}

function chunkArray(array, numChunks) {
    const chunkSize = Math.ceil(array.length / numChunks);
    return Array.from({ length: numChunks }, (_, index) =>
      array.slice(index * chunkSize, (index + 1) * chunkSize)
    );
}

const visitedDomains = new Set();
var cnt_accessed_urls = 0;
var cnt_skiped_urls = 0;
var cnt_err_urls = 0;
var cnt_benign_urls = 0;

async function main(options) {

    const log = (...args) => console.log(new Date().toISOString(), ...args);

    async function shouldSkipUrl(url) {
        for (const domain of benignDomains) {
            if (url.startsWith(`http://${domain}`) || url.startsWith(`https://${domain}`)) {
                return true;
            }
        }
        return false;
    }

    async function removeUrls(inaccessibleIds) {
        const db = new Database(dbPath); // Bun:sqlite
        const dupCheck = new Set(inaccessibleIds);
        const uniqueIds = [...dupCheck];
        for (const id of uniqueIds) {
            log(`Trial Increased ID :: ${id}`);
            try{
            const rows = db.query("SELECT * FROM apwg_urls_to_check WHERE apwg_id = $id");
            const trials = await rows.get({$id : id}).trials + 1;
            
            if (trials != null) {
                const currentTimestamp = new Date().getTime();
                if (trials >= 3) {
                    log(`Trial exceed ID :: ${id}`);
                    db.run(
                        "UPDATE apwg_all_urls SET trials = ?, updated_timestamp = ?, first_failure_timestamp = ?, second_failure_timestamp = ?, third_failure_timestamp = ? WHERE apwg_id = ?",
                        [
                            trials,
                            currentTimestamp,
                            rows.get({$id : id}).first_failure_timestamp,
                            rows.get({$id : id}).second_failure_timestamp,
                            currentTimestamp,
                            id
                        ]
                    );
                    db.run("DELETE FROM apwg_urls_to_check WHERE apwg_id = ?", id);
                } else {
                    let updateStatement = "";
    
                    if (trials === 1) {
                        updateStatement = "UPDATE apwg_urls_to_check SET trials = ?, first_failure_timestamp = ? WHERE apwg_id = ?";
                        db.run(updateStatement, [trials, currentTimestamp, id]);
    
                        db.run(
                            "UPDATE apwg_all_urls SET trials = ?, updated_timestamp = ?, first_failure_timestamp = ?, second_failure_timestamp = ?, third_failure_timestamp = ? WHERE apwg_id = ?",
                            [
                                trials,
                                currentTimestamp,
                                rows.get({$id : id}).first_failure_timestamp,
                                rows.get({$id : id}).second_failure_timestamp,
                                currentTimestamp,
                                id
                            ]
                        );
                    } else if (trials === 2) {
                        updateStatement = "UPDATE apwg_urls_to_check SET trials = ?, second_failure_timestamp = ? WHERE apwg_id = ?";
                        db.run(updateStatement, [trials, currentTimestamp, id]);
    
                        db.run(
                            "UPDATE apwg_all_urls SET trials = ?, updated_timestamp = ?, first_failure_timestamp = ?, second_failure_timestamp = ?, third_failure_timestamp = ? WHERE apwg_id = ?",
                            [
                                trials,
                                currentTimestamp,
                                rows.get({$id : id}).first_failure_timestamp,
                                rows.get({$id : id}).second_failure_timestamp,
                                currentTimestamp,
                                id
                            ]
                        );
                    }
                }
                log(`ID UPDATEED!`);

                }else {
                    log(`No row found for apwg_id: ${id}`);
                }}
            catch (e) {log(`No row found for apwg_id: ${id}`);}
            }
            db.close();
        }

    const browserInstall = async () => {
        let downloaded = false;
        const Version = PUPPETEER_REVISIONS.chrome;
        return await browsers.install({
            browser: "chrome",
            // browser: "firefox",
            buildId: Version,
            cacheDir: `${os.homedir()}/.cache/puppeteer`,
            downloadProgressCallback: (downloadedBytes, totalBytes) => {
                if (!downloaded) {
                    downloaded = true;
                    log(`Downloading the browser /${Version}...`);
                }
            },
        });
    }
    
    

    const browserPromise = browserInstall();

    const withBrowser = async (fn) => {
        const installedBrowser = await browserPromise;
        log(`Launching the browser from ${installedBrowser.executablePath}...`);
        const userDataDir = path.join("./puppeteer_alive/cached_data/", `cached_data_puppet_${Math.random().toString(36).substring(7)}`);

        // const browser = await puppeteer.launch({
        const browser = await pextra.launch({
            headless: true,
            args: minimal_args,
            userDataDir: userDataDir,
            product: installedBrowser.browser,
            executablePath: installedBrowser.executablePath,
            defaultViewport: null,
            protocolTimeout: 30000
        });
        return await fn(browser);
    };

    const pagePool = new Map();

    const withPage = (browser) => async (fn) => {

        let page = pagePool.get(browser);
        if (!page){
            page = await browser.newPage();
            await page.setBypassCSP(true);
            // await page.setDefaultNavigationTimeout(10000); 
            await page.setViewport({
            width: parseInt(options.viewportSize.split('x')[0], 10),
            height: parseInt(options.viewportSize.split('x')[1], 10),
            deviceScaleFactor: 1,
        });
        pagePool.set(browser, page);
        }
        try {
            const result = await fn(page);
            // await page.goto('about:blank');
            return await result;
        } catch (error) {
            await page.close();
            pagePool.delete(page);
            throw error;
        }
    };
    
    const results = await withBrowser(async (browser) => {
        let inaccessibleIds = [];

        const launch$ = rxjs.from(options.urls).pipe(
            mergeMap(async ({ apwg_id, url }) => {
                // Change the variable name to avoid conflict with function name
                const sanitizedUrl = sanitizeUrl(url);
        
                if (!isValidUrl(sanitizedUrl)) {
                    log(`Invalid URL format: ${url}`);
                    const errorContext = {
                        context: {
                            originalUrl: url,
                            sanitizedUrl: sanitizedUrl,
                            errorType: 'URL_VALIDATION_ERROR',
                            timestamp: new Date().toISOString()
                        }
                    };
                    // Create directory for error logging
                    const prefixNum = Math.floor(apwg_id / 10000);
                    const outputDir = path.join(
                        `${rootDirPath}/apwg/`, 
                        String(prefixNum), 
                        `${apwg_id}-invalid_url`,
                        new Date().toISOString().replace(/[:.]/g, '-')
                    );
                    fs.mkdirSync(outputDir, { recursive: true });
                    const errorLogPath = path.join(outputDir, 'error.log');
                    
                    await writeDetailedErrorLog(errorLogPath, url, new Error('Invalid URL format'), errorContext);
                    inaccessibleIds.push(apwg_id);
                    cnt_err_urls += 1;
                    return { result: url };
                }
        
                if (await shouldSkipUrl(sanitizedUrl)) {
                    log(`Skipping BENIGN URL: ${sanitizedUrl}`);
                    inaccessibleIds.push(apwg_id);
                    cnt_benign_urls += 1;
                    log(`ID : ${apwg_id} pushed to be update`);
                    return { result: sanitizedUrl };
                }
        
                let domain;
                try {
                    domain = new URL(sanitizedUrl).origin;
                } catch (error) {
                    log(`Failed to parse URL: ${sanitizedUrl}`);
                    const errorContext = {
                        context: {
                            originalUrl: url,
                            sanitizedUrl: sanitizedUrl,
                            errorType: 'URL_PARSING_ERROR',
                            timestamp: new Date().toISOString()
                        }
                    };
                    const prefixNum = Math.floor(apwg_id / 10000);
                    const outputDir = path.join(
                        `${rootDirPath}/apwg/`, 
                        String(prefixNum), 
                        `${apwg_id}-parse_error`,
                        new Date().toISOString().replace(/[:.]/g, '-')
                    );
                    fs.mkdirSync(outputDir, { recursive: true });
                    const errorLogPath = path.join(outputDir, 'error.log');
                    
                    await writeDetailedErrorLog(errorLogPath, url, error, errorContext);
                    inaccessibleIds.push(apwg_id);
                    cnt_err_urls += 1;
                    return { result: sanitizedUrl };
                }

                const checkingUrl = domain.replace("https://", "").replace("http://", "");
                visitedDomains.add(checkingUrl);
                
                if (inaccessibleIds.length > 0) {
                    await removeUrls(inaccessibleIds);
                    inaccessibleIds.length = 0
                }

                return await withPage(browser)(async (page) => {
                    const timestamp = new Date().toLocaleString("ko-KR", {
                        year: "numeric",
                        month: "2-digit",
                        day: "2-digit",
                        hour: "2-digit",
                        minute: "2-digit",
                        hour12: false,
                    }).replace(/[.,\/\s]/g, "-").replaceAll("--", "-");
                    const prefixNum = Math.floor(apwg_id / 10000);
                        // const cleanedUrl = url.replace(/^https?:\/\//, '').replace(/[^a-zA-Z0-9]/g, '_').substring(0, 50);
                        const cleanedUrl = domain.replace(/^https?:\/\//, '').replace(/[^a-zA-Z0-9]/g, '_');
                        const checkedDirpath = path.join(`${rootDirPath}/apwg/`, String(prefixNum), `${apwg_id}-${cleanedUrl}`);
                        const outputDir = path.join(checkedDirpath, timestamp);
                        const errorLogPath = path.join(outputDir, 'error.log');
                    try {
                        const response = await page.goto(url, {
                            // waitUntil: 'networkidle2', timeout: 15000 // This is rigorous
                            waitUntil: 'domcontentloaded', timeout: 25000
                        });
                        if (!response) {
                            const errorContext = {
                                context: {
                                    attemptTimestamp: new Date().toISOString(),
                                    browserInfo: await browser.version(),
                                    navigationResponse: 'null'
                                }
                            };
                            await writeDetailedErrorLog(errorLogPath, url, new Error('No response received'), errorContext);
                            inaccessibleIds.push(apwg_id);
                            cnt_skiped_urls += 1;
                            log(`Response failed for ${url}. Skipping screenshot and HTML capture.`);
                            return { result: url };
                        }

                        // await page.waitForFunction(() => document.readyState === "complete");
                        //waitForNavigation just timeout. I came up with other solution using the waitForFunction, checking if document is in ready state.

                        fs.mkdirSync(outputDir, {recursive: true});
                        // await Bun.mkdir(outputDir, { recursive: true });

                        const screenshotPath = path.join(outputDir, 'screenshot.jpg');
                        const htmlPath = path.join(outputDir, 'page.html');
                        const headersPath = path.join(outputDir, 'headers.json');
                        const finalUrlPath = path.join(outputDir, 'final_url.txt');
                        const originalUrlPath = path.join(outputDir, 'original_url.txt');
                        const statusCodePath = path.join(outputDir, 'status_code.txt');
                        const httpVersionPath = path.join(outputDir, 'http_version.txt');
                        const getCookiePath = path.join(outputDir, 'cookies.json');
                        const ipAddrPath = path.join(outputDir, 'ip_address.json');

                        const statusCode = await response.status();
                        const headers = await response.headers();
                        const htmlContent = await page.content();
                        await page.screenshot({
                            path: screenshotPath,
                            fullPage: false
                        });
                        const httpVersion = await page.evaluate(() => performance.getEntries()[0].nextHopProtocol);
                        const getCookie = await page.cookies();
                        const finalUrl = await page.url();
                        const title = await page.title();
                        const filteredUrl = new URL(finalUrl).origin.replace(/^https?:\/\//, '');
                        
                        // const ipAddr = await Bun.dns.lookup(filteredUrl, {family: 4, ttl: true});
                        // try{

                        const dnsInfo = await getDnsInfo(filteredUrl);
                        const formattedResults = formatDnsResults(dnsInfo);
                        await fs.writeFile(ipAddrPath, JSON.stringify(formattedResults, null, 2));
                        // const resolver = new Resolver();
                        // await fs.writeFile(ipAddrPath, JSON.stringify(await resolver.resolveAny(filteredUrl, { ttl: true }), null, 2));

                        // } catch (error) {
                        //     const resolver = new doh.DohResolver('https://1.1.1.1/dns-query');
                        //     await resolver.query(filteredUrl, 'A')
                        //     .then((response) => {
                        //     response.answers.forEach(ans => fs.writeFile(ipAddrPath, JSON.stringify(ans, null, 2)));
                        //     })
                        //     .catch((error) => {console.error(error);});
                        // }

                        await fs.writeFile(headersPath, JSON.stringify(headers, null, 2));
                        await fs.writeFile(htmlPath, htmlContent);
                        await fs.writeFile(finalUrlPath, finalUrl);
                        await fs.writeFile(originalUrlPath, url);
                        await fs.writeFile(statusCodePath, String(statusCode));
                        await fs.writeFile(httpVersionPath, String(httpVersion));
                        await fs.writeFile(getCookiePath, JSON.stringify(getCookie, null, 2));
                        // await fs.writeFile(ipAddrPath, JSON.stringify(await resolver.resolve4(filteredUrl, { ttl: true }), null, 2));
                        // await fs.writeFile(ipAddrPath, JSON.stringify(ipAddr, null, 2));

                        if (htmlContent.includes("This domain has expired.")){
                            log(`Skipping Expired URL: ${url}, FinalURL is : ${finalUrl}`);
                            inaccessibleIds.push(apwg_id);
                            cnt_skiped_urls += 1;
                            log(`ID : ${apwg_id} pushed to be update`);
                            await fs.writeFile(errorLogPath, `Error capturing data for ${url}: ${statusCode}, Final_url is Expired: ${finalUrl}`);
                            return {
                                result: url
                            };
                        }

                        if (await shouldSkipUrl(finalUrl)) {
                            log(`Skipping BENIGN URL: ${url}, FinalURL is : ${finalUrl}`);
                            inaccessibleIds.push(apwg_id);
                            cnt_skiped_urls += 1;
                            log(`ID : ${apwg_id} pushed to be update`);
                            await fs.writeFile(errorLogPath, `Error capturing data for ${url}: ${statusCode}, Final_url is benign: ${finalUrl}`);
                            return {
                                result: url
                            };
                        }
                        if (statusCode >= 400 || title.includes("Not Found") || title.includes("404 Not Found") || title.includes("Suspected phishing") || title.includes("Office of Information Technology") || title.includes("Vite + Vue")) {
                            inaccessibleIds.push(apwg_id);
                            log(`ID : ${apwg_id} pushed to be update`);
                            await fs.writeFile(errorLogPath, `Error capturing data for ${url}: ${statusCode}, title: ${title}`);
                        }
                        log(`ID: ${apwg_id}  URL: ${url} is finished`);
                        cnt_accessed_urls += 1;
                        if (inaccessibleIds.length > 0) {
                            await removeUrls(inaccessibleIds);
                            inaccessibleIds.length = 0
                        }
                        return url;
                    } catch (error) {
                        fs.mkdirSync(outputDir, { recursive: true });
                        
                        // Gather additional context
                        let currentUrl = 'Unable to get current URL';
                        try {
                            currentUrl = page.url();
                        } catch (urlError) {
                            // URL access failed, keep default value
                        }
                    
                        let additionalInfo = {
                            context: {
                                attemptTimestamp: new Date().toISOString(),
                                browserInfo: await browser.version(),
                                currentUrl: currentUrl,
                                memory: process.memoryUsage(),
                                visitedDomainsCount: visitedDomains.size,
                                previousAttempts: 0 // You might want to track this from your database
                            }
                        };
                    
                        // Try to gather response information if available
                        try {
                            const response = await page.client().send('Network.getResponseBody');
                            additionalInfo.responseBody = response;
                        } catch (e) {
                            // additionalInfo.responseBodyError = 'Unable to get response body';
                            // ignore
                        }

                        const msg = error.message.toLowerCase();
    
                        if (msg.includes('net::err_name_not_resolved')) {
                            try {
                                additionalInfo.context.dnsInfo = {
                                    domain: new URL(url).hostname,
                                    timestamp: new Date().toISOString()
                                };
                            } catch (urlError) {
                                additionalInfo.context.dnsInfo = {
                                    domain: 'Unable to parse URL',
                                    timestamp: new Date().toISOString()
                                };
                            }
                        } else if (msg.includes('timeout') || msg.includes('navigation timeout')) {
                            try {
                                const readyState = await page.evaluate(() => document.readyState);
                                additionalInfo.context.timeoutInfo = {
                                    timeoutDuration: 25000,
                                    navigationState: readyState,
                                    timestamp: new Date().toISOString()
                                };
                            } catch (evalError) {
                                additionalInfo.context.timeoutInfo = {
                                    timeoutDuration: 25000,
                                    navigationState: 'unknown',
                                    timestamp: new Date().toISOString()
                                };
                            }
                        } else if (msg.includes('target closed') || msg.includes('browser disconnected')) {
                            additionalInfo.context.browserState = {
                                isConnected: browser.isConnected(),
                                pagesCount: (await browser.pages()).length,
                                timestamp: new Date().toISOString()
                            };
                        }

                        // Let writeDetailedErrorLog handle the categorization
                        const errorCategory = await writeDetailedErrorLog(errorLogPath, url, error, additionalInfo);
                        
                        // Update counters and handle cleanup
                        inaccessibleIds.push(apwg_id);
                        cnt_err_urls += 1;
                        
                        if (inaccessibleIds.length > 0) {
                            await removeUrls(inaccessibleIds);
                            inaccessibleIds.length = 0;
                        }
                        
                        return url;
                    }
            }
        )
        }, 16), toArray()
    );
    await lastValueFrom(launch$);
    // return processedUrls;
});
return await results;
}

program
    .option('--screenshot-path <path>', 'screenshot output path', 'screenshot.jpg')
    .option('--viewport-size <size>', 'browser viewport size', '1280x960')
    .option('--debug', 'run the browser in foreground', false)
    .parse(process.argv);

function exetimeout(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function isValidUrl(urlString) {
    try {
        // Check if the URL has a proper protocol
        if (!urlString.startsWith('http://') && !urlString.startsWith('https://')) {
            return false;
        }
        
        // Try parsing the URL
        const url = new URL(urlString);
        
        // Check for minimum valid structure
        return url.protocol && url.host;
    } catch (e) {
        return false;
    }
}

function sanitizeUrl(urlString) {
    urlString = urlString.trim();
    if (urlString.startsWith('//')){
        urlString = 'https:' + urlString;
    } else if (!urlString.includes('://')){
        urlString = 'https://' + urlString;
    }
    return urlString;
}

async function runMain() {
    const numInstances = 16;
    const urlChunks = chunkArray(await gettingUrls(), numInstances);
    try {
        const results = await Promise.allSettled(
            urlChunks.map(async (urlChunk) => {
                try {
                    await main({ ...program.opts(), urls: urlChunk })
                    // exetimeout(30 * 60 * 1000); // 30 minutes in milliseconds
                } catch (error) {
                    console.error(`Error processing URL chunk:`, error);
                }
            })
        );
        console.log('Accessed URLs : ', cnt_accessed_urls);
        console.log('Skipped Duplicate URLs : ', cnt_skiped_urls);
        console.log('Benign URLs (Redirected) : ', cnt_benign_urls);
        console.log('Error occured URLs : ', cnt_err_urls);
        console.log('Main function completed.');
    } catch (error) {
        if (error instanceof Error) {
            console.error('An error occurred:', error);
        } else {
            console.log('Script terminated after 30 minutes.');
        }
    }
    finally {
        process.exit(0);
    }
}

runMain(); 