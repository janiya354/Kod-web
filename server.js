const express = require('express');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const VT = 'https://www.virustotal.com/api/v3';
app.use(express.json({limit:'32kb'}));
app.use(express.static(path.join(__dirname)));

function sleep(ms){ return new Promise(r=>setTimeout(r,ms)); }
function validUrl(value){
  try { const u=new URL(value); return (u.protocol==='http:'||u.protocol==='https:') && u.hostname.length>0 && value.length<=4096 ? u : null; }
  catch { return null; }
}

app.post('/api/check-url', async (req,res)=>{
  const apiKey=process.env.VIRUSTOTAL_API_KEY;
  if(!apiKey) return res.status(503).json({error:'Threat-intelligence backend is not configured. Add VIRUSTOTAL_API_KEY on the server.'});
  const u=validUrl(String(req.body?.url||'').trim());
  if(!u) return res.status(400).json({error:'Please provide a valid HTTP/HTTPS URL.'});
  try{
    const submit=await fetch(`${VT}/urls`,{method:'POST',headers:{'x-apikey':apiKey,'accept':'application/json','content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({url:u.href})});
    const sj=await submit.json().catch(()=>({}));
    if(!submit.ok) return res.status(submit.status).json({error:sj?.error?.message||'VirusTotal URL submission failed.'});
    const id=sj?.data?.id; if(!id) throw new Error('No analysis ID returned.');
    let analysis=null;
    for(let i=0;i<20;i++){
      await sleep(i?2000:500);
      const r=await fetch(`${VT}/analyses/${encodeURIComponent(id)}`,{headers:{'x-apikey':apiKey,'accept':'application/json'}});
      const j=await r.json().catch(()=>({}));
      if(!r.ok) throw new Error(j?.error?.message||'Unable to retrieve analysis.');
      analysis=j?.data;
      if(analysis?.attributes?.status==='completed') break;
    }
    if(!analysis) throw new Error('No analysis result returned.');
    const a=analysis.attributes||{}; const stats=a.stats||{};
    const malicious=Number(stats.malicious||0), suspicious=Number(stats.suspicious||0);
    const verdict=malicious>0?'dangerous':suspicious>0?'suspicious':a.status==='completed'?'safe':'unknown';
    const detections=Object.values(a.results||{}).filter(x=>['malicious','suspicious'].includes(String(x?.category||'').toLowerCase())).slice(0,20).map(x=>({engine:x.engine_name||'Unknown engine',result:x.result||x.category||'Detection',category:x.category||'unknown'}));
    res.json({verdict,source:'VirusTotal',stats:{malicious,suspicious,harmless:Number(stats.harmless||0),undetected:Number(stats.undetected||0),timeout:Number(stats.timeout||0)},detections,message:verdict==='dangerous'?'One or more security engines flagged this URL. Do not open it or enter credentials.':verdict==='suspicious'?'One or more engines marked this URL suspicious. Treat it as unsafe unless you can verify the source.':verdict==='safe'?'No malicious or suspicious detections were returned by the completed scan. This is not a guarantee of safety.':'The analysis did not finish within the allowed wait time.'});
  }catch(err){ console.error(err); res.status(502).json({error:err.message||'Threat-intelligence scan failed.'}); }
});

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'index.html')));
app.listen(PORT,()=>console.log(`KOD server running on port ${PORT}`));
