const puppeteer = require('puppeteer');
const fs = require("fs");
const axios = require('axios');


var dir = './files';
if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir);
}

let api_key = 'c5f18a0c79fc9b7dc4d18f94ba44741346cb5d901d6a41817b7e622577534251';
(async () => {
    this.options = {
        params: {
            ignoreHTTPSErrors: true,
            headless: false,
            args: [
                '--ash-host-window-bounds=1920x1080',
                '--window-size=1920,1048',
                '--window-position=0,0',
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',

            ],
            defaultViewport: {
                width: 1366,
                height: 768,
            },
        }
    };
    console.log("launching browser");
    const browser = await puppeteer.launch(
        this.options.params
    );
    const page = await browser.newPage();
    let website = process.argv[2] || "www.amazon.in";
    console.log(website);
    await page.goto("http://" + website, {
        timeout: 120000,
        waitUntil: ['load', 'domcontentloaded']
    }); //add your url
    console.log("launching browser successful");
    try {
        await page.addScriptTag({url: 'https://code.jquery.com/jquery-3.2.1.min.js'});
    } catch (e) {
        console.log("jquery injection failed");
    }
    let urls = await page.evaluate(() => {
        let iframes = document.querySelectorAll("iframe");
        let x = [];
        let word = 'javascript:false;';

        for (i = 0; i < iframes.length; i++) {
            if (!iframes[i].src.includes(word)) {
                x.push(iframes[i].src);
            }
        }
        return x;
    });
    console.log("retrieved iframes url");
    console.log(urls);

    let scan_ids = [];
    let duplicate_urls = {}; //hashmap
    if (urls.length !== 0) {
        for (let i = 0; i < urls.length; i++) {
            try {
                if (urls[i] && !duplicate_urls[urls[i]]) {
                    let obj = {};
                    obj.url = urls[i];
                    duplicate_urls[urls[i]] = i + 1;
                    console.log("sending API call:" + (i + 1));
                    let res = await axios.post(`https://www.virustotal.com/vtapi/v2/url/scan?apikey=${api_key}&url=${urls[i]}`);
                    if (res.data.scan_id) {
                        console.log(res.data.scan_id);
                        obj.scan_id = res.data.scan_id;
                        scan_ids.push(obj);
                    }
                } else {
                    console.log("duplicate url found:" + urls[i]);
                }
            } catch (e) {
                console.log(e);
            }

        }
        console.log(scan_ids);
        console.log("now getting reports for each scan_id");
        for (let i = 0; i < scan_ids.length; i++) {
            try {
                console.log("sending API call:" + (i + 1));
                let res = await axios.get(`https://www.virustotal.com/vtapi/v2/url/report?apikey=${api_key}&resource=${scan_ids[i].scan_id}`);
                if (res) {
                    res.data.scans.url = scan_ids[i].url;
                    res.data.scans.website = website;
                    res.data.scans.response_code = res.data.response_code;
                    res.data.scans.positives = res.data.positives;
                    res.data.scans.total_scans = res.data.total;
                    await fs.writeFile(`./files/${scan_ids[i].scan_id}.json`, `${JSON.stringify(res.data.scans, null, 2)}`, function (err) {
                        if (err) throw err;
                        console.log('File is created successfully.');
                    });
                    // console.log(res.data.scans);
                }
            } catch (e) {
                console.log(e);
            }
        }
    } else {
        console.log("no iframes found on this website");
    }
    console.log("No of iframes:", urls.length);

    await browser.close();
})();
