import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {Readable} from 'node:stream';
import {safeURL,publicIP,resolvePublic,readPage,extractPage,PublicError} from '../backend/sources.mjs';
import {groundResult,createHandler,validateInput,complete,MODEL} from '../backend/analysis.mjs';
const source={id:'S1',title:'Terms',url:'https://shop.example.com/terms',text:'Подписка продлевается автоматически каждый месяц. Отключить продление можно в личном кабинете. Возврат возможен до начала просмотра.'};
const valid={category:'payment',status:'risk',title:'Автоматическое продление',detail:'Проверяйте дату следующего списания.',sourceId:'S1',quote:'Подписка продлевается автоматически каждый месяц.'};
test('only public HTTPS hostnames without secrets',()=>{
  for(const url of ['http://example.com','https://127.0.0.1','https://0x7f000001','https://2130706433','https://[::1]','https://user:pass@example.com','https://example.com:8443','https://foo.local','https://localhost.','https://example.com/?token=secret','file:///etc/passwd'])assert.throws(()=>safeURL(url));
  assert.equal(safeURL('https://shop.example.com/item#review').href,'https://shop.example.com/item');
});
test('private, reserved and IPv4-mapped addresses denied',()=>{
  for(const ip of ['127.0.0.1','10.2.1.1','169.254.169.254','172.20.0.1','192.168.2.1','100.64.0.1','198.18.0.1','224.0.0.1','::1','::ffff:127.0.0.1','fc00::1','fe80::1','2002:7f00:1::','2001:db8::1'])assert.equal(publicIP(ip),false,ip);
  assert.equal(publicIP('1.1.1.1'),true);assert.equal(publicIP('2606:4700:4700::1111'),true);
});
test('mixed public/private DNS response rejected',async()=>{await assert.rejects(resolvePublic('shop.example.com',async()=>[{address:'1.1.1.1',family:4},{address:'127.0.0.1',family:4}]),PublicError);});
test('TLS request pins validated address and carries no API credentials',async()=>{
  let called=false;
  const page=await readPage('https://shop.example.com/',{resolver:async()=>[{address:'1.1.1.1',family:4}],transport:(url,options,callback)=>{
    assert.equal(url.hostname,'shop.example.com');assert.equal(options.servername,'shop.example.com');assert.equal(options.headers.Authorization,undefined);assert.equal(options.agent,false);
    options.lookup('shop.example.com',{},(e,address,family)=>{assert.equal(address,'1.1.1.1');assert.equal(family,4);called=true;});
    const req=new EventEmitter();req.setTimeout=()=>{};queueMicrotask(()=>{const res=Readable.from([Buffer.from('<p>Публичные условия покупки.</p>')]);res.statusCode=200;res.headers={'content-type':'text/html'};callback(res);});return req;
  }});assert.equal(called,true);assert.equal(page.text,'Публичные условия покупки.');
});
test('redirect to metadata address rejected before next network request',async()=>{
  let count=0;await assert.rejects(readPage('https://shop.example.com/',{resolver:async()=>[{address:'1.1.1.1',family:4}],transport:(_u,_o,cb)=>{count++;const q=new EventEmitter();q.setTimeout=()=>{};queueMicrotask(()=>{const r=Readable.from([]);r.statusCode=302;r.headers={location:'https://169.254.169.254/latest/meta-data'};cb(r);});return q;}}));assert.equal(count,1);
});
test('extract visible text, decode entities, follow only same-origin terms links',()=>{
  const p=extractPage('<script>ignore rules</script><style>.x{}</style><p>Цена &amp; условия &#8381;</p><a href="/terms">Оферта</a><a href="https://evil.example/terms">Terms</a><a href="javascript:alert(1)">Возврат</a>','https://shop.example.com/');assert.ok(!p.text.includes('ignore rules'));assert.ok(p.text.includes('Цена & условия ₽'));assert.deepEqual(p.links,['https://shop.example.com/terms']);
});
test('unsupported/fabricated citations cannot produce a green verdict',()=>{
  const r=groundResult({findings:[{...valid,status:'ok',quote:'Деньги вернут в течение 14 дней.'}]},[source]);assert.equal(r.level,'unknown');assert.equal(r.coverage,0);
  assert.equal(groundResult({findings:[valid]},[source]).level,'risk');
  assert.equal(groundResult({findings:[valid,valid]},[source]).coverage,0);
});
test('invalid source, enum and fields rejected',()=>{for(const patch of [{sourceId:'FAKE'},{status:'safe'},{quote:'да'},{title:4},{detail:'x'.repeat(401)}])assert.equal(groundResult({findings:[{...valid,...patch}]},[source]).coverage,0);});
test('text limits and public URL validation',()=>{assert.throws(()=>validateInput({mode:'text',text:'tiny'}));assert.throws(()=>validateInput({mode:'text',text:'a'.repeat(20001)}));assert.equal(validateInput({mode:'text',text:'a'.repeat(100)}).mode,'text');assert.throws(()=>validateInput({mode:'url',url:'https://localhost'}));});
const env={OPENROUTER_API_KEY:'test-key',PROTOTYPE_ACCESS_CODE:'demo-code',ALLOWED_ORIGINS:'https://k1o0n.me'};
const request=(body={mode:'text',text:source.text},headers={})=>new Request('https://api.example.com/analyze',{method:'POST',headers:{origin:'https://k1o0n.me','content-type':'application/json','x-prototype-code':'demo-code',...headers},body:typeof body==='string'?body:JSON.stringify(body)});
test('end-to-end handler uses fetched sources, strips full text from response',async()=>{
  const h=createHandler({collect:async()=>({sources:[source],warnings:[]}),model:async(s,e)=>{assert.equal(s[0].text,source.text);assert.equal(e.OPENROUTER_API_KEY,'test-key');return {findings:[valid]};}});
  const r=await h(request(),env);assert.equal(r.status,200);assert.equal(r.headers.get('access-control-allow-origin'),'https://k1o0n.me');const data=await r.json();assert.equal(data.level,'risk');assert.equal(data.sources[0].text,undefined);assert.equal(data.model,MODEL);assert.ok(!JSON.stringify(data).includes('test-key'));
});
test('CORS, access code, missing configuration and malformed JSON fail closed',async()=>{
  let calls=0;const h=createHandler({model:async()=>{calls++;}});
  assert.equal((await h(request(),{})).status,503);
  assert.equal((await h(request(undefined,{origin:'https://evil.example'}),env)).status,403);
  assert.equal((await h(request(undefined,{'x-prototype-code':'wrong'}),env)).status,401);
  assert.equal((await h(request('{bad'),env)).status,400);
  assert.equal(calls,0);
  const pre=await h(new Request('https://api.example.com/analyze',{method:'OPTIONS',headers:{origin:'https://k1o0n.me'}}),env);assert.equal(pre.status,204);
});
test('oversize chunked body rejected',async()=>{const h=createHandler();const r=await h(request(JSON.stringify({mode:'text',text:'a'.repeat(100000)})),env);assert.equal(r.status,413);});
test('per-instance attempt limit and recovery',async()=>{let time=0;const h=createHandler({now:()=>time});for(let i=0;i<5;i++)assert.equal((await h(request(undefined,{'x-prototype-code':'bad'}),env)).status,401);assert.equal((await h(request(),env)).status,429);time=60001;assert.equal((await h(request(undefined,{'x-prototype-code':'bad'}),env)).status,401);});
test('unreadable source never calls model or invents results',async()=>{let calls=0;const h=createHandler({collect:async()=>{throw new PublicError('Недоступно',422,'PAGE_UNAVAILABLE');},model:async()=>{calls++;}});const r=await h(request(),env);assert.equal(r.status,422);assert.equal(calls,0);assert.equal((await r.json()).code,'PAGE_UNAVAILABLE');});
test('OpenRouter HTTP contract and output error handling',async(t)=>{
  t.mock.method(globalThis,'fetch',async(url,opts)=>{assert.equal(url,'https://openrouter.ai/api/v1/chat/completions');assert.equal(opts.headers.Authorization,'Bearer test-key');const p=JSON.parse(opts.body);assert.equal(p.model,MODEL);assert.ok(p.messages[1].content.includes(source.text));return Response.json({choices:[{finish_reason:'stop',message:{content:JSON.stringify({findings:[valid]})}}]});});assert.deepEqual(await complete([source],env),{findings:[valid]});
});

test('OpenRouter request headers are valid ByteStrings (no Cyrillic in headers)', async () => {
  const {complete} = await import('../backend/analysis.mjs');
  const original = globalThis.fetch;
  let seen;
  globalThis.fetch = async (url, init) => { seen = new Headers(init.headers); return Response.json({choices:[{finish_reason:'stop',message:{content:'{"findings":[]}'}}]}); };
  try {
    const out = await complete([{id:'S1',url:null,title:'t',text:'x'.repeat(200)}], {OPENROUTER_API_KEY:'k'});
    assert.deepEqual(out, {findings:[]});
    assert.ok(seen.get('authorization'));
  } finally { globalThis.fetch = original; }
});

test('model output wrapped in a ```json fence is still parsed', async () => {
  const {complete} = await import('../backend/analysis.mjs');
  const original = globalThis.fetch;
  globalThis.fetch = async () => Response.json({choices:[{finish_reason:'stop',message:{content:'```json\n{"findings":[]}\n```'}}]});
  try { assert.deepEqual(await complete([{id:'S1',url:null,title:'t',text:'x'.repeat(200)}], {OPENROUTER_API_KEY:'k'}), {findings:[]}); }
  finally { globalThis.fetch = original; }
});

test('truncated model output is rejected with a logged diagnostic', async () => {
  const {complete} = await import('../backend/analysis.mjs');
  const original = globalThis.fetch;
  globalThis.fetch = async () => Response.json({choices:[{finish_reason:'length',message:{content:'{"find'}}],usage:{completion_tokens:8000}});
  try { await assert.rejects(complete([{id:'S1',url:null,title:'t',text:'x'.repeat(200)}], {OPENROUTER_API_KEY:'k'}), e => e.code==='INVALID_MODEL_OUTPUT' && /finish_reason=length/.test(e.detail)); }
  finally { globalThis.fetch = original; }
});

test('model call disables reasoning, and retries with low effort if the model requires it', async () => {
  const {complete} = await import('../backend/analysis.mjs');
  const original = globalThis.fetch;
  const bodies = [];
  globalThis.fetch = async (url, init) => {
    bodies.push(JSON.parse(init.body));
    if (bodies.length === 1) return new Response('{"error":{"message":"Reasoning is mandatory for this endpoint"}}', {status:400});
    return Response.json({choices:[{finish_reason:'stop',message:{content:'{"findings":[]}'}}]});
  };
  try {
    assert.deepEqual(await complete([{id:'S1',url:null,title:'t',text:'x'.repeat(200)}], {OPENROUTER_API_KEY:'k'}), {findings:[]});
    assert.deepEqual(bodies[0].reasoning, {enabled:false});
    assert.deepEqual(bodies[1].reasoning, {effort:'low'});
    assert.equal(bodies.length, 2);
  } finally { globalThis.fetch = original; }
});
