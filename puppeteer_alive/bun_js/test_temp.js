import puppeteer from 'puppeteer';
// import { Resolver } from 'dns/promises';
import { promises } from 'node:dns';
import { window } from 'rxjs';
import doh from 'dohjs';

const minimal_args = [
  '--disable-gpu',
  '--disable-infobars',
  '--ignore-certificate-errors',
  '--disable-accelerated-2d-canvas',
  '--disable-features=TranslateUI,BlinkGenPropertyTrees,IsolateOrigins,site-per-process',
  '--enable-features=NetworkService,NetworkServiceInProcess',
  '--disable-background-timer-throttling',
  '--disable-backgrounding-occluded-windows',
  '--disable-breakpad',
  '--disable-component-update',
  '--disable-default-apps',
  '--disable-dev-shm-usage',
  '--disable-domain-reliability',
  '--disable-extensions',
  '--disable-gpu-sandbox',
  '--disable-notifications',
  '--disable-popup-blocking',
  '--disable-setuid-sandbox',
  '--disable-web-security',
  '--no-sandbox',
  '--no-zygote',
  '--disable-blink-features=AutomationControlled',
  '--disable-features=IsolateOrigins,site-per-process'
];

async function getdnsgoogle_cloudeflare(url){
  // Google's JSON API
  // Doc: https://developers.google.com/speed/public-dns/docs/doh/json
  // Endpoint: https://dns.google/resolve?
  // Cloudflare's JSON API
  // Doc: https://developers.cloudflare.com/1.1.1.1/dns-over-https/json-format/
  // Endpoint https://cloudflare-dns.com/dns-query?
  var google_dns_response = await fetch('https://dns.google/resolve?name=' + url);
  var google_dns_json = await google_dns_response.json();
  var cloudflare_dns_response = await fetch('https://cloudflare-dns.com/dns-query?name=' + url);
  var cloudflare_dns_json = await cloudflare_dns_response.json();
  if (google_dns_json !== null) {
    return google_dns_json;
  } else {
    return cloudflare_dns_json;
  }
}

async function setupPage(page) {
  // Add initial evasions
  await page.evaluateOnNewDocument(() => {
    window.chrome = {
      runtime: {},
      loadTimes: function() {},
      csi: function() {},
      app: {}
    };
  });

  // Set viewport
  await page.setViewport({
    width: 1920,
    height: 1080
  });
}

async function getDetectionResults(page) {
  try {
    const results = await page.evaluate(() => {
      const detections = document.getElementById('detections-json');
      if (!detections || !detections.textContent) return null;
      try {
        return JSON.parse(detections.textContent);
      } catch (e) {
        return null;
      }
    });
    return results;
  } catch (e) {
    console.log('Error getting detection results:', e.message);
    return null;
  }
}

async function runDetectionTests(page) {
  console.log('\n=== Running Specific Detection Tests ===');


  try {
    // First define dummyFn in the page context
    await page.evaluate(() => {
      window.dummyFn = function() {
        return true;
      };
    });

    // Test 1: dummyFn
    console.log('\n1. Testing dummyFn:');
    try {
      const result = await page.evaluate(() => {
        return typeof window.dummyFn === 'function';
      });
      console.log('dummyFn test result:', result ? 'Function defined successfully' : 'Function not defined');
      // if (result) {
      await page.evaluate(() => window.dummyFn());
      console.log('dummyFn test completed - Function was called');
      // }
    } catch (e) {
      console.log('dummyFn test error:', e.message);
    }

    // Test 2: sourceUrlLeak
    console.log('\n2. Testing sourceUrlLeak:');
    try {
      const element = await page.evaluate(() => {
        const el = document.getElementById('detections-json');
        return el ? true : false;
      });
      console.log('sourceUrlLeak test completed, element found:', element);
    } catch (e) {
      console.log('sourceUrlLeak test error:', e.message);
    }


    // Test 3: mainWorldExecution
    console.log('\n3. Testing mainWorldExecution:');
    try {
      const elements = await page.evaluate(() => {
        const els = document.getElementsByClassName('div');
        return els.length;
      });
      console.log('mainWorldExecution test completed, found elements:', elements);
    } catch (e) {
      console.log('mainWorldExecution test error:', e.message);
    }

    // Get final detection results
    const results = await getDetectionResults(page);
    if (results) {
      console.log('\nFinal Detection Results:', JSON.stringify(results, null, 2));
    } else {
      console.log('\nNo detection results available');
    }

  } catch (err) {
    console.error('Error during detection tests:', err);
  }
}

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

async function main() {
  let browser;
  try {
    browser = await puppeteer.launch({
      args: minimal_args,
      defaultViewport: null,
      headless: "new",
      // dumpio: true,
    });

    const page = await browser.newPage();
    await setupPage(page);

    const url = process.env.TEST_URL;
    
    await page.goto(url, { 
      waitUntil: ['domcontentloaded', 'networkidle0'],
      timeout: 30000 
    });

    await runDetectionTests(page);

    const finalUrl = await page.url();
    const filteredUrl = new URL(finalUrl).origin.replace(/^https?:\/\//, '');
    
    // Get DNS information using both methods
    console.log('\nFetching DNS information...');
    
    // Traditional DNS resolution
    const dnsInfo = await getDnsInfo(filteredUrl);
    const formattedResults = formatDnsResults(dnsInfo);
    
    // Print the full results with proper formatting
    console.log('DNS Resolution Results:');
    console.log(JSON.stringify(formattedResults, null, 2));
    
    // // DoH backup resolution
    // const dohInfo = await getDohInfo(filteredUrl);
    
    // console.log('\n=== DoH Resolution Results ===');
    // for (const [provider, results] of Object.entries(dohInfo)) {
    //   console.log(`\n${provider.toUpperCase()} Results:`);
    //   console.log(JSON.stringify(results, null, 2));
    // }

    console.log('\n=== Final Results ===');
    console.log('URL:', finalUrl);
    console.log('Timestamp:', dnsInfo.timestamp);
    
  } catch (err) {
    console.error('Error during execution:', err);
  } finally {
    if (browser) {
      await browser.close();
    }
  }
}

main();