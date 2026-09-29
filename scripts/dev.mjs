import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {createHandler} from '../backend/analysis.mjs';
const root=path.resolve(import.meta.dirname,'..');const handle=createHandler();
const port=Number(process.env.PORT)||4173;
const devEnv={...process.env,ALLOWED_ORIGINS:process.env.ALLOWED_ORIGINS||`http://127.0.0.1:${port},http://localhost:${port}`};
const types={'.html':'text/html; charset=utf-8','.css':'text/css','.js':'text/javascript','.svg':'image/svg+xml','.ttf':'font/ttf','.txt':'text/plain'};
const server=createServer(async(req,res)=>{try{
  const u=new URL(req.url,'http://127.0.0.1');
  if(u.pathname.startsWith('/api/')){
    const chunks=[];let size=0;for await(const c of req){size+=c.length;if(size>90000){res.writeHead(413);res.end('Request too large');return;}chunks.push(c);}
    const request=new Request('http://localhost'+u.pathname.slice(4),{method:req.method,headers:req.headers,...(!['GET','HEAD'].includes(req.method)?{body:Buffer.concat(chunks)}:{})});
    const response=await handle(request,devEnv,req.socket.remoteAddress);res.writeHead(response.status,Object.fromEntries(response.headers));res.end(await response.text());return;
  }
  const file=u.pathname==='/'?'index.html':decodeURIComponent(u.pathname.slice(1));
  if(!['index.html','styles.css','app.js','config.js','CNAME'].includes(file)&&!/^assets\/[a-zA-Z0-9_./-]+$/.test(file)){res.writeHead(404);res.end('Not found');return;}
  const resolved=path.resolve(root,file);if(!resolved.startsWith(root+path.sep)){res.writeHead(403);res.end();return;}
  const data=await readFile(resolved);res.writeHead(200,{'Content-Type':types[path.extname(file)]||'application/octet-stream','Cache-Control':'no-store'});res.end(data);
}catch{res.writeHead(404);res.end('Not found');}});
server.listen(port,'127.0.0.1',()=>console.log('Preview: http://127.0.0.1:'+server.address().port));
