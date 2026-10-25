const crypto=require('node:crypto');
const reply=(res,code,obj)=>res.status(code).json(obj);
const secret=()=>process.env.BILLAR_SESSION_SECRET||'';
const hash=(x)=>crypto.createHmac('sha256',secret()).update(x).digest('hex');
function sign(role){const exp=Date.now()+12*3600*1000;const msg=role+':'+exp;return msg+'.'+hash(msg)}
function valid(token){if(!token||!secret())return null;const parts=token.split('.');if(parts.length!==2)return null;const msg=parts[0],sig=parts[1],role=msg.split(':')[0],exp=Number(msg.split(':')[1]);if(!['admin','worker'].includes(role)||!Number.isFinite(exp)||exp<Date.now())return null;const expect=hash(msg);return sig.length===expect.length&&crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(expect))?role:null}
const equal=(a,b)=>{const x=Buffer.from(String(a||'')),y=Buffer.from(String(b||''));return x.length===y.length&&crypto.timingSafeEqual(x,y)};
async function db(method,body,query='?id=eq.poolzone_test&select=*'){
 const url=process.env.SUPABASE_URL+'/rest/v1/rmarc_billar_sync_state'+query;
 const r=await fetch(url,{method,headers:{apikey:process.env.SUPABASE_SERVICE_ROLE_KEY,Authorization:'Bearer '+process.env.SUPABASE_SERVICE_ROLE_KEY,'Content-Type':'application/json',Prefer:'return=representation'},...(body?{body:JSON.stringify(body)}:{})});
 const x=await r.json().catch(()=>null);if(!r.ok)throw Error('Error de base de datos '+r.status);return x;
}
function structure(x){return x&&typeof x==='object'&&Array.isArray(x.tables)&&Array.isArray(x.products)&&Array.isArray(x.sales)&&x.tables.length<100&&x.products.length<1000&&x.sales.length<100000}
function authorizedChange(old,now,role){
 if(role==='admin')return true;
 if(old.name!==now.name||old.rate!==now.rate||old.pid!==now.pid)return false;
 if(now.products.length!==old.products.length)return false;
 const oldById=new Map(old.products.map(p=>[p.id,p]));
 for(const p of now.products){const prev=oldById.get(p.id);if(!prev||p.name!==prev.name||p.price!==prev.price||!Number.isFinite(p.stock)||p.stock<0)return false;}
 if(now.sales.length<old.sales.length)return false;
 for(let i=0;i<old.sales.length;i++)if(JSON.stringify(old.sales[i])!==JSON.stringify(now.sales[i]))return false;
 return true;
}
module.exports=async(req,res)=>{
 res.setHeader('Cache-Control','no-store');if(req.method!=='POST')return reply(res,405,{error:'Método no permitido'});
 if(!process.env.BILLAR_ADMIN_PASSWORD||!process.env.BILLAR_WORKER_PASSWORD||!secret()||!process.env.SUPABASE_URL||!process.env.SUPABASE_SERVICE_ROLE_KEY)return reply(res,503,{error:'Faltan variables seguras en Vercel'});
 try{
 const {action,password,role:requestedRole,data,revision}=req.body||{};
 if(action==='login'){
  const role=requestedRole==='admin'?'admin':'worker',expected=role==='admin'?process.env.BILLAR_ADMIN_PASSWORD:process.env.BILLAR_WORKER_PASSWORD;
  if(!equal(password,expected))return reply(res,401,{error:'Contraseña incorrecta'});
  return reply(res,200,{token:sign(role)});
 }
 const role=valid((req.headers.authorization||'').replace(/^Bearer /,''));if(!role)return reply(res,401,{error:'Sesión no autorizada'});
 if(action==='read'){const rows=await db('GET');return reply(res,200,rows.length?{data:rows[0].payload,revision:rows[0].revision}:{data:null,revision:null})}
 if(action==='bootstrap'){
  if(role!=='admin')return reply(res,403,{error:'Solo administrador'});
  if(!structure(data))return reply(res,400,{error:'Respaldo inválido'});
  const existing=await db('GET');if(existing.length)return reply(res,409,{error:'La nube ya tiene registros. No se sobrescribieron. Guarda respaldos y solicita una conciliación.'});
  const rows=await db('POST',{id:'poolzone_test',payload:data,revision:1},'?select=*');
  return reply(res,200,{revision:rows[0].revision});
 }
 if(action==='write'){
  if(!structure(data)||!Number.isSafeInteger(revision)||revision<1)return reply(res,400,{error:'Datos inválidos'});
  const rows=await db('GET');if(!rows.length)return reply(res,409,{error:'Primero inicializa la nube'});
  const old=rows[0];if(old.revision!==revision)return reply(res,409,{error:'Otro dispositivo actualizó los datos. No se sobrescribieron'});
  if(!authorizedChange(old.payload,data,role))return reply(res,403,{error:'Modificación de inventario/configuración reservada al administrador'});
  const updated=await db('PATCH',{payload:data,revision:revision+1},'?id=eq.poolzone_test&revision=eq.'+revision+'&select=*');
  if(!updated.length)return reply(res,409,{error:'Conflicto de sincronización. No se sobrescribieron datos'});
  return reply(res,200,{revision:updated[0].revision});
 }
 return reply(res,400,{error:'Acción inválida'});
 }catch(e){return reply(res,500,{error:e.message})}
};
