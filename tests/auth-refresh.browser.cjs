// @ts-check
const assert = require('node:assert/strict');
const puppeteer = require('puppeteer');

async function main() {
 const browser = await puppeteer.launch({headless:true,acceptInsecureCerts:true,args:['--no-sandbox'],...(process.env.CHROMIUM_PATH ? {executablePath:process.env.CHROMIUM_PATH}: {})});
 try {
  const baseUrl=process.env.TAUTH_REFRESH_TEST_URL;
  const pages=await Promise.all([browser.newPage(),browser.newPage()]);
  await browser.defaultBrowserContext().setCookie({name:process.env.TAUTH_REFRESH_COOKIE,value:process.env.TAUTH_REFRESH_TEST_TOKEN,url:baseUrl,secure:true,httpOnly:true});
  await Promise.all(pages.map(page=>page.goto(baseUrl+'/fixture')));
  const restore=async (page,configuredBaseUrl=baseUrl)=>page.evaluate(async baseUrl=>{
   document.body.textContent='restoring';
   await window.initAuthClient({baseUrl,bootstrapMode:'eager',onAuthenticated:()=>{document.body.textContent='authenticated';},onUnauthenticated:()=>{document.body.textContent='unauthenticated';},onAuthError:()=>{document.body.textContent='error';}});
   return document.body.textContent;
  },configuredBaseUrl);
  assert.deepEqual(await Promise.all(pages.map(page=>restore(page))),['authenticated','authenticated']);
  await browser.defaultBrowserContext().deleteCookie(...(await browser.defaultBrowserContext().cookies()).filter(cookie=>cookie.name===process.env.TAUTH_SESSION_COOKIE));
  const mixed=await Promise.all([pages[0].evaluate(async baseUrl=>(await window.apiFetch(baseUrl+'/me')).status,baseUrl),restore(pages[1])]);
  assert.deepEqual(mixed,[200,'authenticated']);
  await browser.defaultBrowserContext().deleteCookie(...(await browser.defaultBrowserContext().cookies()).filter(cookie=>cookie.name===process.env.TAUTH_SESSION_COOKIE));
  assert.deepEqual(await Promise.all(pages.map(page=>restore(page))),['authenticated','authenticated']);
  await browser.defaultBrowserContext().deleteCookie(...(await browser.defaultBrowserContext().cookies()).filter(cookie=>cookie.name===process.env.TAUTH_SESSION_COOKIE));
  const equivalentUrls=await Promise.all([restore(pages[0]),restore(pages[1],baseUrl+'/')]);
  await browser.defaultBrowserContext().deleteCookie(...(await browser.defaultBrowserContext().cookies()).filter(cookie=>cookie.name===process.env.TAUTH_SESSION_COOKIE));
  const subsequentSession=await restore(pages[0]);
  assert.deepEqual({equivalentUrls,subsequentSession},{equivalentUrls:['authenticated','authenticated'],subsequentSession:'authenticated'});
  console.log('Concurrent tab restore and subsequent refresh passed.');
 } finally {await browser.close();}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
