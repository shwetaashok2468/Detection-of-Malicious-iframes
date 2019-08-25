const puppeteer = require('puppeteer');
const fs=require("fs");
const axios=require('axios');
(async () => {
    this.options = {
        params: {
            ignoreHTTPSErrors: true,
            headless: true,
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
    console.log("******************----******************");
    console.log("launching browser");
    const browser = await puppeteer.launch(
        this.options.params
    );
    const page = await browser.newPage();
    let website=process.argv[2];
    console.log(process.argv[2]);
    await page.goto("http://"+website,{
        timeout:120000
    }); //add your url
    console.log("launching browser successful");
    try {
        await page.addScriptTag({url: 'https://code.jquery.com/jquery-3.2.1.min.js'});
    }
    catch (e) {
        console.log("jquery injection failed");
    }
    let urls=await page.evaluate(()=>{
        let iframes=document.querySelectorAll("iframe");
        let x=[];
        let word = 'javascript:false;';

        for(i=0;i<iframes.length;i++){
            if(!iframes[i].src.includes(word))
            {
                x.push(iframes[i].src);
            }
        }
        return x;
    });
    console.log("retrieved iframes url");
    console.log(urls);

    let scan_ids=[];
    let duplicate_urls={};
    if(urls.length!==0) {
        for (let i = 0; i < urls.length; i++) {
            try {
                if (!duplicate_urls[urls[i]]) {
                    let obj = {};
                    obj.url = urls[i];
                    duplicate_urls[urls[i]] = i + 1;
                    console.log("sending API call:" + (i + 1));
                    let res = await axios.post(`https://www.virustotal.com/vtapi/v2/url/scan?apikey=c5f18a0c79fc9b7dc4d18f94ba44741346cb5d901d6a41817b7e622577534251&url=${urls[i]}`);
                    console.log(res.data.scan_id);
                    obj.scan_id = res.data.scan_id;
                    scan_ids.push(obj);
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
                let res = await axios.get(`https://www.virustotal.com/vtapi/v2/url/report?apikey=c5f18a0c79fc9b7dc4d18f94ba44741346cb5d901d6a41817b7e622577534251&resource=${scan_ids[i].scan_id}`);
                if(res) {
                    await fs.writeFile(`./files/${scan_ids[i].scan_id}.json`, `${JSON.stringify(res.data.scans, null, 2)}`, function (err) {
                        if (err) throw err;
                        console.log('File is created successfully.');
                    });
                    console.log(res.data.scans);
                }
            } catch (e) {
                console.log(e);
            }
        }
    }
    else{
        console.log("no iframes found on this website");
    }
    await browser.close();
})();
