import {createHandler} from './analysis.mjs';
const handle=createHandler();
export default async ({req,res,error})=>{
  const method=req.method||'GET';
  const headers=new Headers();for(const [key,value] of Object.entries(req.headers||{}))if(typeof value==='string')headers.set(key,value);
  const request=new Request('https://function.local'+(req.path||'/'),{method,headers,...(!['GET','HEAD'].includes(method)?{body:req.bodyText||''}:{})});
  const response=await handle(request,process.env,req.headers?.['x-appwrite-client-ip']||'unknown',error);
  return res.text(await response.text(),response.status,Object.fromEntries(response.headers));
};
