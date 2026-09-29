import https from 'node:https';
import { lookup } from 'node:dns/promises';
import { isIP, BlockList } from 'node:net';

export class PublicError extends Error {
  constructor(message, status = 400, code = 'INVALID_INPUT') { super(message); this.status = status; this.code = code; }
}
const private4 = new BlockList();
for (const [ip, bits] of [['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['169.254.0.0',16],['172.16.0.0',12],['192.0.0.0',24],['192.0.2.0',24],['192.88.99.0',24],['192.168.0.0',16],['198.18.0.0',15],['198.51.100.0',24],['203.0.113.0',24],['224.0.0.0',4],['240.0.0.0',4]]) private4.addSubnet(ip,bits,'ipv4');
const public6 = new BlockList(); public6.addSubnet('2000::',3,'ipv6');
const private6 = new BlockList();
for (const [ip,bits] of [['2001::',23],['2001:db8::',32],['2002::',16],['3fff::',20]]) private6.addSubnet(ip,bits,'ipv6');
export function publicIP(ip) { const v=isIP(ip); return v===4 ? !private4.check(ip,'ipv4') : v===6 && public6.check(ip,'ipv6') && !private6.check(ip,'ipv6'); }
export function safeURL(value) {
  if (typeof value!=='string' || value.length>2048) throw new PublicError('Укажите публичную HTTPS-ссылку длиной до 2048 символов.');
  let u; try {u=new URL(value.trim());} catch {throw new PublicError('Проверьте ссылку. Она должна начинаться с https://.');}
  const h=u.hostname.replace(/\.$/,'').toLowerCase();
  if (u.protocol!=='https:' || u.username || u.password || u.port || isIP(h) || h.includes(':') || !h.includes('.') || /(?:^|\.)(localhost|local|internal|test|invalid|onion|lan|home|arpa)$/.test(h)) throw new PublicError('Нужна публичная HTTPS-ссылка без пароля и нестандартного порта.');
  if ([...u.searchParams.keys()].some(k=>/^(token|access_token|auth|authorization|password|secret|api[_-]?key|signature|sig)$/i.test(k))) throw new PublicError('В ссылке есть похожий на секрет параметр. Используйте публичную страницу без токена доступа.');
  u.hash=''; return u;
}
export async function resolvePublic(host, resolver=lookup) {
  const addresses=await resolver(host,{all:true,verbatim:true});
  if (!addresses.length || addresses.some(a=>!publicIP(a.address))) throw new PublicError('Эта ссылка ведёт на непубличный адрес.');
  // Prefer IPv4: serverless runtimes often have no IPv6 egress.
  return addresses.find(a=>a.family===4)||addresses[0];
}
// Pin the already-validated DNS answer to the TLS connection. This prevents DNS
// rebinding between validation and connection; TLS still checks the URL hostname.
export async function readPage(url, {signal, resolver=lookup, transport=https.get}={}) {
  let u=safeURL(url);
  for(let redirect=0;redirect<=3;redirect++) {
    signal?.throwIfAborted();
    const addr=await resolvePublic(u.hostname,resolver);
    signal?.throwIfAborted();
    const result=await new Promise((resolve,reject)=>{
      const req=transport(u,{signal,agent:false,servername:u.hostname,headers:{'User-Agent':'TrustConditionsPrototype/1.0','Accept':'text/html,text/plain','Accept-Encoding':'identity'},lookup:(_host,options,cb)=>options.all?cb(null,[addr]):cb(null,addr.address,addr.family)},res=>{
        const status=res.statusCode||0;
        if(status>=300 && status<400) {res.resume();resolve({location:res.headers.location,status});return;}
        const type=res.headers['content-type']||'';
        if(status!==200 || !/^(text\/html|text\/plain|application\/xhtml\+xml)(?:;|$)/i.test(type)) {res.resume();reject(new PublicError('Страница недоступна или её формат не поддерживается. Вставьте текст условий.',422,'PAGE_UNAVAILABLE'));return;}
        if(res.headers['content-encoding'] && res.headers['content-encoding']!=='identity'){res.resume();reject(new PublicError('Не удалось прочитать страницу. Вставьте текст условий.',422,'PAGE_UNAVAILABLE'));return;}
        const chunks=[];let bytes=0;
        res.on('data',chunk=>{bytes+=chunk.length;if(bytes>1_500_000){res.destroy(new PublicError('Страница слишком большая. Вставьте нужный фрагмент условий.',422,'PAGE_TOO_LARGE'));}else chunks.push(chunk);});
        res.on('error',reject);res.on('end',()=>{
          const charset=type.match(/charset\s*=\s*["']?([^\s;"']+)/i)?.[1]||'utf-8';
          try {resolve({html:new TextDecoder(charset).decode(Buffer.concat(chunks)),status});} catch {reject(new PublicError('Не удалось прочитать кодировку. Вставьте текст условий.',422,'PAGE_UNAVAILABLE'));}
        });
      });
      req.setTimeout(9000,()=>req.destroy(new PublicError('Страница долго отвечает. Попробуйте вставить текст условий.',422,'PAGE_TIMEOUT')));req.on('error',e=>reject(e instanceof PublicError||['AbortError','TimeoutError'].includes(e?.name)?e:new PublicError('Не удалось открыть страницу. Вставьте текст условий.',422,'PAGE_UNAVAILABLE')));
    });
    if(result.location) {u=safeURL(new URL(result.location,u).href);continue;}
    if(result.html!==undefined)return {...extractPage(result.html,u.href),url:u.href};
    throw new PublicError('Не удалось открыть страницу. Вставьте текст условий.',422,'PAGE_UNAVAILABLE');
  }
  throw new PublicError('Слишком много перенаправлений. Укажите конечную ссылку.',422,'PAGE_UNAVAILABLE');
}
function decode(s) {return s.replace(/&(#x[\da-f]+|#\d+|amp|lt|gt|quot|apos|nbsp);/gi,(_,e)=>{
  const map={amp:'&',lt:'<',gt:'>',quot:'"',apos:"'",nbsp:' '};if(e[0]!=='#')return map[e.toLowerCase()]||'';
  const n=e[1].toLowerCase()==='x'?parseInt(e.slice(2),16):parseInt(e.slice(1),10);return n>0&&n<=0x10ffff?String.fromCodePoint(n):' ';
});}
export const normalize=s=>String(s).replace(/\s+/g,' ').trim();
export function extractPage(html,url) {
  const cleaned=html.replace(/<!--[\s\S]*?-->/g,' ').replace(/<(script|style|noscript|svg)\b[^>]*>[\s\S]*?<\/\1\s*>/gi,' ');
  const text=normalize(decode(cleaned.replace(/<[^>]*>/g,' '))).slice(0,18000);
  const links=[];
  for(const m of cleaned.matchAll(/<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi)) {
    if(!/оферт|услови|возврат|пользовательск|terms|refund|subscription|billing/i.test(m[1]+' '+m[2]))continue;
    try {const u=safeURL(new URL(decode(m[1]),url).href);if(u.origin===new URL(url).origin&&!links.includes(u.href)&&u.href!==url)links.push(u.href);}catch{/* Ignore unsafe or unrelated links. */}
  }
  return {text,links:links.slice(0,2)};
}
export async function collectSources(input,{signal}={}) {
  if(input.mode==='text')return {sources:[{id:'S1',url:null,title:'Предоставленный текст',text:input.text}],warnings:['Проверен только предоставленный фрагмент. Его подлинность и полнота не проверялись.']};
  const first=await readPage(input.url,{signal});
  if(first.text.length<100 || /captcha|проверка браузера|подтвердите.{0,20}(человек|робот)|access denied/i.test(first.text.slice(0,700)))throw new PublicError('Сайт не дал прочитать содержимое. Вставьте текст оферты вручную.',422,'PAGE_UNAVAILABLE');
  const sources=[{id:'S1',url:first.url,title:new URL(first.url).hostname,text:first.text}];const warnings=[];
  for(const link of first.links){try{const next=await readPage(link,{signal});if(next.text.length>=100)sources.push({id:`S${sources.length+1}`,url:next.url,title:'Условия на сайте продавца',text:next.text});}catch{warnings.push('Одну из связанных страниц условий не удалось прочитать.');}}
  if(sources.length===1)warnings.push('Прочитана одна страница. Полная оферта и условия оплаты могут находиться отдельно.');
  return {sources,warnings:[...new Set(warnings)]};
}
