import {mkdir,copyFile,cp,writeFile} from 'node:fs/promises';
await mkdir('dist',{recursive:true});
// Explicit allowlist: never publish backend, tests, environment files or keys.
for(const file of ['index.html','styles.css','app.js','config.js','CNAME'])await copyFile(file,`dist/${file}`);
await cp('assets','dist/assets',{recursive:true});await writeFile('dist/.nojekyll','');
if(process.env.PUBLIC_API_BASE){const u=new URL(process.env.PUBLIC_API_BASE);if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash||u.pathname!=='/')throw Error('PUBLIC_API_BASE must be an HTTPS origin');await writeFile('dist/config.js',`export const API_BASE = ${JSON.stringify(u.origin)};\n`);}
console.log('Static site built in dist/');
