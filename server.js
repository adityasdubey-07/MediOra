'use strict';
const http=require('node:http');
const fs=require('node:fs');
const fsp=require('node:fs/promises');
const path=require('node:path');
const os=require('node:os');
const crypto=require('node:crypto');
const {DatabaseSync}=require('node:sqlite');
const Busboy=require('busboy');
const QRCode=require('qrcode');

const ROOT=__dirname;
const DATA=process.env.CC_DATA_DIR||path.join(os.homedir(),'AppData','Local','ConnectedCareLocal');
const FILES=path.join(DATA,'private-files');
const DB_FILE=path.join(DATA,'connected-care.sqlite');
const PORT=Number(process.env.PORT||8000);
const HOST=process.env.HOST||'127.0.0.1';
const MAX_PDF=15*1024*1024;
fs.mkdirSync(FILES,{recursive:true});
const db=new DatabaseSync(DB_FILE);
db.exec('PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;');
db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE, full_name TEXT NOT NULL,
 password_salt TEXT NOT NULL, password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('patient','doctor','hospital_admin')),
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('pending','active','suspended','deactivated')),
 doctor_code_hash TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS sessions(
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS doctor_applications(
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
 qualification TEXT NOT NULL, specialty TEXT NOT NULL, hospital TEXT NOT NULL,
 registration_number TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
 reviewed_by TEXT REFERENCES users(id), reviewed_at TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS medical_records(
 id TEXT PRIMARY KEY, patient_id TEXT NOT NULL REFERENCES users(id), title TEXT NOT NULL,
 record_type TEXT NOT NULL, source_name TEXT NOT NULL DEFAULT '', record_date TEXT,
 file_name TEXT NOT NULL, stored_name TEXT NOT NULL UNIQUE, mime_type TEXT NOT NULL DEFAULT 'application/pdf',
 file_size INTEGER NOT NULL, sha256 TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS records_patient_date_idx ON medical_records(patient_id, record_date DESC, created_at DESC);
CREATE TABLE IF NOT EXISTS shares(
 id TEXT PRIMARY KEY, patient_id TEXT NOT NULL REFERENCES users(id), token_hash TEXT NOT NULL UNIQUE,
 expires_at INTEGER NOT NULL, revoked_at TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS share_records(
 share_id TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
 record_id TEXT NOT NULL REFERENCES medical_records(id), PRIMARY KEY(share_id,record_id)
);
CREATE TABLE IF NOT EXISTS visits(
 id TEXT PRIMARY KEY, patient_id TEXT NOT NULL REFERENCES users(id), doctor_id TEXT NOT NULL REFERENCES users(id),
 share_id TEXT REFERENCES shares(id), hospital TEXT NOT NULL DEFAULT '', summary TEXT NOT NULL DEFAULT '',
 consultation_at TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS visits_patient_idx ON visits(patient_id,consultation_at DESC);
CREATE INDEX IF NOT EXISTS visits_doctor_idx ON visits(doctor_id,consultation_at DESC);
CREATE TABLE IF NOT EXISTS visit_snapshots(
 id TEXT PRIMARY KEY, visit_id TEXT NOT NULL UNIQUE REFERENCES visits(id),
 records_json TEXT NOT NULL, snapshot_hash TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TRIGGER IF NOT EXISTS snapshots_no_update BEFORE UPDATE ON visit_snapshots BEGIN SELECT RAISE(ABORT,'Visit snapshots are immutable'); END;
CREATE TRIGGER IF NOT EXISTS snapshots_no_delete BEFORE DELETE ON visit_snapshots BEGIN SELECT RAISE(ABORT,'Visit snapshots are immutable'); END;
CREATE TABLE IF NOT EXISTS prescriptions(
 id TEXT PRIMARY KEY, visit_id TEXT NOT NULL REFERENCES visits(id), patient_id TEXT NOT NULL REFERENCES users(id),
 doctor_id TEXT NOT NULL REFERENCES users(id), medicine TEXT NOT NULL, dosage TEXT NOT NULL,
 frequency TEXT NOT NULL, duration TEXT NOT NULL, instructions TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS prescriptions_patient_idx ON prescriptions(patient_id,created_at DESC);
CREATE TABLE IF NOT EXISTS audit_logs(
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id TEXT, action TEXT NOT NULL,
 target_type TEXT NOT NULL DEFAULT '', target_id TEXT NOT NULL DEFAULT '', outcome TEXT NOT NULL DEFAULT 'success',
 details TEXT NOT NULL DEFAULT '{}', occurred_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_logs BEGIN SELECT RAISE(ABORT,'Audit logs are append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_logs BEGIN SELECT RAISE(ABORT,'Audit logs are append-only'); END;
`);

const mime={'html':'text/html; charset=utf-8','css':'text/css; charset=utf-8','js':'text/javascript; charset=utf-8','svg':'image/svg+xml','png':'image/png','jpg':'image/jpeg','ico':'image/x-icon'};
const publicFiles=new Set(['index.html','patient.html','doctor.html','records.html','admin.html','styles.css','home.css','patient.css','app.js','home-i18n.js','status-i18n.js','client.js','package.json']);
const stm={userByEmail:db.prepare('SELECT * FROM users WHERE email=? COLLATE NOCASE'),userById:db.prepare('SELECT * FROM users WHERE id=?'),session:db.prepare('SELECT s.user_id,u.email,u.full_name,u.role,u.status FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?'),audit:db.prepare('INSERT INTO audit_logs(actor_id,action,target_type,target_id,outcome,details) VALUES(?,?,?,?,?,?)')};
function id(){return crypto.randomUUID()}
function sha(s){return crypto.createHash('sha256').update(s).digest('hex')}
function hashPassword(password,salt){return crypto.scryptSync(password,salt,64).toString('hex')}
function safeEq(a,b){const x=Buffer.from(a||''),y=Buffer.from(b||'');return x.length===y.length&&crypto.timingSafeEqual(x,y)}
function audit(actor,action,type='',target='',outcome='success',details={}){try{stm.audit.run(actor||null,action,type,target,outcome,JSON.stringify(details).slice(0,4000))}catch{}}
function send(res,status,data,headers={}){const body=Buffer.isBuffer(data)?data:Buffer.from(typeof data==='string'?data:JSON.stringify(data));res.writeHead(status,{'Content-Length':body.length,'X-Content-Type-Options':'nosniff','Cache-Control':'no-store',...headers});res.end(body)}
function json(res,status,obj){send(res,status,obj,{'Content-Type':'application/json; charset=utf-8'})}
function fail(status,message){const e=new Error(message);e.status=status;return e}
function cookie(req,name){const s=req.headers.cookie||'';const m=s.split(';').map(x=>x.trim()).find(x=>x.startsWith(name+'='));return m?decodeURIComponent(m.slice(name.length+1)):''}
function currentUser(req){const token=cookie(req,'cc_session');if(!token)return null;return stm.session.get(sha(token),Date.now())||null}
function requireRole(user,...roles){if(!user)throw fail(401,'Please sign in.');if(user.status!=='active')throw fail(403,'This account is not active.');if(!roles.includes(user.role))throw fail(403,'This role cannot access this service.');return user}
async function bodyJson(req,max=1024*1024){let n=0,parts=[];for await(const c of req){n+=c.length;if(n>max)throw fail(413,'Request is too large.');parts.push(c)}try{return JSON.parse(Buffer.concat(parts).toString('utf8')||'{}')}catch{throw fail(400,'Invalid JSON request.')}}
function checkOrigin(req){const o=req.headers.origin;if(o&&o!=='http://127.0.0.1:'+PORT&&o!=='http://localhost:'+PORT)throw fail(403,'Cross-origin request blocked.')}
function sessionCookie(value,maxAge){return `cc_session=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}`}
function cleanName(s){return path.basename(String(s||'record.pdf')).replace(/[^\w.() -]/g,'_').slice(0,150)||'record.pdf'}
function mimeFor(ext){return mime[ext.replace(/^\./,'').toLowerCase()]||'application/octet-stream'}
function recordForPatient(recordId,patientId){return db.prepare('SELECT * FROM medical_records WHERE id=? AND patient_id=?').get(recordId,patientId)}
function shareForToken(token){if(!token)return null;return db.prepare(`SELECT s.*,u.full_name patient_name FROM shares s JOIN users u ON u.id=s.patient_id WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>?`).get(sha(token),Date.now())||null}
function shareRecordIds(shareId){return db.prepare('SELECT record_id FROM share_records WHERE share_id=?').all(shareId).map(r=>r.record_id)}
function publicRecord(r){return {id:r.id,title:r.title,recordType:r.record_type,source:r.source_name,recordDate:r.record_date,fileName:r.file_name,fileSize:r.file_size,createdAt:r.created_at}}
function pdfRoute(req,res,record,context){const stream=fs.createReadStream(path.join(FILES,record.stored_name));res.writeHead(200,{'Content-Type':'application/pdf','Content-Length':record.file_size,'Content-Disposition':`inline; filename="${cleanName(record.file_name)}"`,'X-Content-Type-Options':'nosniff','Cache-Control':'no-store'});stream.pipe(res)}
async function saveUpload(req,user){
 return await new Promise((resolve,reject)=>{
  let fileInfo=null,fields={},size=0,head=Buffer.alloc(0),chunks=[];let rejected=false;
  const bb=Busboy({headers:req.headers,limits:{files:1,fileSize:MAX_PDF,fields:8,fieldSize:2000}});
  bb.on('field',(name,val)=>fields[name]=val);
  bb.on('file',(name,file,info)=>{
   if(name!=='file'||!/^application\/pdf$/i.test(info.mimeType||'')&&!/\.pdf$/i.test(info.filename||'')){rejected=true;file.resume();return}
   file.on('data',b=>{size+=b.length;if(head.length<8)head=Buffer.concat([head,b.subarray(0,8-head.length)]);chunks.push(b)});
   file.on('limit',()=>{rejected=true});
   file.on('error',reject);fileInfo=info;
  });
  bb.on('error',reject);
  bb.on('finish',async()=>{
   try{
    if(rejected)throw fail(413,'Choose a PDF smaller than 15 MB.');
    const bytes=Buffer.concat(chunks);if(!fileInfo||bytes.length===0)throw fail(400,'Choose a PDF file.');
    if(bytes.subarray(0,5).toString()!=='%PDF-')throw fail(415,'This file does not have a valid PDF signature.');
    if(size>MAX_PDF)throw fail(413,'PDF exceeds the 15 MB limit.');
    const rid=id(),storedName=rid+'.pdf',target=path.join(FILES,storedName);await fsp.writeFile(target,bytes,{flag:'wx'});
    const title=String(fields.title||path.parse(fileInfo.filename).name).trim().slice(0,200)||'Medical record';
    const type=String(fields.recordType||'other').slice(0,40),source=String(fields.source||'').trim().slice(0,200),date=String(fields.recordDate||'').slice(0,10)||null;
    db.prepare(`INSERT INTO medical_records(id,patient_id,title,record_type,source_name,record_date,file_name,stored_name,file_size,sha256) VALUES(?,?,?,?,?,?,?,?,?,?)`).run(rid,user.id,title,type,source,date,cleanName(fileInfo.filename),storedName,size,sha(bytes));
    audit(user.id,'medical_record.upload','medical_record',rid,'success',{size,recordType:type});
    resolve(publicRecord(db.prepare('SELECT * FROM medical_records WHERE id=?').get(rid)));
   }catch(e){reject(e)}
  });
  req.pipe(bb);
 });
}
async function route(req,res){
 const url=new URL(req.url,'http://127.0.0.1');const p=url.pathname;const method=req.method||'GET';
 if(p.startsWith('/api/')&&method!=='GET'&&method!=='HEAD')checkOrigin(req);
 if(p==='/api/health'&&method==='GET')return json(res,200,{ok:true,service:'Connected Care local API',database:'SQLite',storage:'local private directory',warning:'Local development only; do not use real patient data.'});
 if(p==='/api/auth/register-patient'&&method==='POST'){
  const b=await bodyJson(req);const email=String(b.email||'').trim().toLowerCase(),name=String(b.fullName||'').trim(),password=String(b.password||'');
  if(!/^\S+@\S+\.\S+$/.test(email)||name.length<1||name.length>200||password.length<10)throw fail(400,'Enter a valid email, name and password (at least 10 characters).');
  if(stm.userByEmail.get(email))throw fail(409,'An account with this email already exists.');
  const uid=id(),salt=crypto.randomBytes(16).toString('hex');db.prepare('INSERT INTO users(id,email,full_name,password_salt,password_hash,role,status) VALUES(?,?,?,?,?,?,?)').run(uid,email,name,salt,hashPassword(password,salt),'patient','active');
  audit(uid,'patient.register','user',uid);return loginResponse(req,res,uid,email,'patient');
 }
 if(p==='/api/auth/apply-doctor'&&method==='POST'){
  const b=await bodyJson(req);const email=String(b.email||'').trim().toLowerCase(),name=String(b.fullName||'').trim(),password=String(b.password||'');
  const qualification=String(b.qualification||'').trim(),specialty=String(b.specialty||'').trim(),hospital=String(b.hospital||'').trim(),reg=String(b.registrationNumber||'').trim();
  if(!/^\S+@\S+\.\S+$/.test(email)||!name||password.length<10||!qualification||!specialty||!hospital||!reg)throw fail(400,'Complete all required registration fields and use a password of at least 10 characters.');
  if(stm.userByEmail.get(email))throw fail(409,'An account with this email already exists.');
  const uid=id(),salt=crypto.randomBytes(16).toString('hex');db.prepare('INSERT INTO users(id,email,full_name,password_salt,password_hash,role,status) VALUES(?,?,?,?,?,?,?)').run(uid,email,name,salt,hashPassword(password,salt),'doctor','pending');
  db.prepare('INSERT INTO doctor_applications(id,user_id,qualification,specialty,hospital,registration_number) VALUES(?,?,?,?,?,?)').run(id(),uid,qualification,specialty,hospital,reg);
  audit(uid,'doctor.application.submit','doctor_application',uid);return json(res,201,{ok:true,status:'pending',message:'Application submitted. A hospital administrator must verify your details before doctor access is enabled.'});
 }
 if(p==='/api/auth/login'&&method==='POST'){
  const b=await bodyJson(req);const user=stm.userByEmail.get(String(b.email||'').trim().toLowerCase());
  if(!user||!safeEq(hashPassword(String(b.password||''),user.password_salt),user.password_hash)){audit(user?.id||null,'auth.login','user',user?.id||'', 'denied');throw fail(401,'Email or password is incorrect.');}
  if(user.status!=='active')throw fail(403,user.status==='pending'?'Doctor application is awaiting approval.':'This account is not active.');
  if(user.role==='doctor'&&(!user.doctor_code_hash||!safeEq(sha(String(b.doctorCode||'').toUpperCase()),user.doctor_code_hash))){audit(user.id,'auth.doctor_code','user',user.id,'denied');throw fail(401,'Doctor code is incorrect.');}
  return loginResponse(req,res,user.id,user.email,user.role);
 }
 if(p==='/api/auth/logout'&&method==='POST'){
  const u=currentUser(req),token=cookie(req,'cc_session');if(token)db.prepare('DELETE FROM sessions WHERE token_hash=?').run(sha(token));audit(u?.user_id||null,'auth.logout','session','');return json(res,200,{ok:true},{'Set-Cookie':sessionCookie('',0)});
 }
 if(p==='/api/auth/me'&&method==='GET'){
  const u=currentUser(req);if(!u)return json(res,200,{user:null});if(u.status!=='active')return json(res,200,{user:null});return json(res,200,{user:{id:u.user_id,email:u.email,fullName:u.full_name,role:u.role}});
 }
 const user=currentUser(req);
 if(p==='/api/patient/records'&&method==='GET'){
  requireRole(user,'patient');const rows=db.prepare('SELECT * FROM medical_records WHERE patient_id=? ORDER BY COALESCE(record_date,created_at) DESC').all(user.user_id);return json(res,200,{records:rows.map(publicRecord)});
 }
 if(p==='/api/patient/records'&&method==='POST'){
  requireRole(user,'patient');const record=await saveUpload(req,user);return json(res,201,{record});
 }
 if(p.startsWith('/api/patient/records/')&&p.endsWith('/file')&&method==='GET'){
  requireRole(user,'patient');const rid=p.split('/')[4],r=recordForPatient(rid,user.user_id);if(!r)throw fail(404,'Record not found.');audit(user.user_id,'medical_record.download','medical_record',rid);return pdfRoute(req,res,r,'patient');
 }
 if(p==='/api/patient/shares'&&method==='GET'){
  requireRole(user,'patient');const rows=db.prepare(`SELECT s.id,s.expires_at,s.created_at,count(sr.record_id) record_count FROM shares s LEFT JOIN share_records sr ON sr.share_id=s.id WHERE s.patient_id=? AND s.revoked_at IS NULL AND s.expires_at>? GROUP BY s.id ORDER BY s.created_at DESC`).all(user.user_id,Date.now());return json(res,200,{shares:rows.map(s=>({...s,expiresAt:new Date(s.expires_at).toISOString()}))});
 }
 if(p==='/api/patient/shares'&&method==='POST'){
  requireRole(user,'patient');const b=await bodyJson(req);const recIds=[...new Set((Array.isArray(b.recordIds)?b.recordIds:[]).map(String))];if(!recIds.length||recIds.length>30)throw fail(400,'Select between 1 and 30 records to share.');
  const rows=recIds.map(rid=>recordForPatient(rid,user.user_id));if(rows.some(r=>!r))throw fail(403,'One or more selected records do not belong to this patient.');
  const minutes=Math.min(120,Math.max(5,Number(b.expiresMinutes)||30)),token=crypto.randomBytes(24).toString('base64url'),shareId=id(),expires=Date.now()+minutes*60000;
  db.prepare('INSERT INTO shares(id,patient_id,token_hash,expires_at) VALUES(?,?,?,?)').run(shareId,user.user_id,sha(token),expires);
  const insert=db.prepare('INSERT INTO share_records(share_id,record_id) VALUES(?,?)');for(const rid of recIds)insert.run(shareId,rid);
  audit(user.user_id,'share.create','share',shareId,'success',{records:recIds.length,expires});const link=`http://${HOST}:${PORT}/doctor.html?share=${encodeURIComponent(token)}`;
  return json(res,201,{id:shareId,token,link,qrDataUrl:await QRCode.toDataURL(link,{width:240,margin:2}),expiresAt:new Date(expires).toISOString(),records:rows.map(publicRecord)});
 }
 if(p.startsWith('/api/patient/shares/')&&method==='DELETE'){
  requireRole(user,'patient');const sid=p.split('/')[4];const s=db.prepare('SELECT * FROM shares WHERE id=? AND patient_id=?').get(sid,user.user_id);if(!s)throw fail(404,'Share not found.');db.prepare('UPDATE shares SET revoked_at=datetime(\'now\') WHERE id=?').run(sid);audit(user.user_id,'share.revoke','share',sid);return json(res,200,{ok:true});
 }
 if(p==='/api/patient/visits'&&method==='GET'){
  requireRole(user,'patient');const rows=db.prepare(`SELECT v.*,u.full_name doctor_name,s.id snapshot_id,s.records_json,s.snapshot_hash FROM visits v JOIN users u ON u.id=v.doctor_id LEFT JOIN visit_snapshots s ON s.visit_id=v.id WHERE v.patient_id=? ORDER BY v.consultation_at DESC`).all(user.user_id);
  return json(res,200,{visits:rows.map(v=>({...v,records:JSON.parse(v.records_json||'[]'),records_json:undefined}))});
 }
 if(p==='/api/patient/prescriptions'&&method==='GET'){
  requireRole(user,'patient');const rows=db.prepare(`SELECT p.*,u.full_name doctor_name,v.hospital,v.consultation_at FROM prescriptions p JOIN users u ON u.id=p.doctor_id JOIN visits v ON v.id=p.visit_id WHERE p.patient_id=? ORDER BY p.created_at DESC`).all(user.user_id);return json(res,200,{prescriptions:rows});
 }
 if(p==='/api/admin/applications'&&method==='GET'){
  requireRole(user,'hospital_admin');const rows=db.prepare(`SELECT a.*,u.email,u.full_name FROM doctor_applications a JOIN users u ON u.id=a.user_id ORDER BY CASE a.status WHEN 'pending' THEN 0 ELSE 1 END,a.created_at DESC`).all();return json(res,200,{applications:rows});
 }
 const adminDecision=p.match(/^\/api\/admin\/applications\/([0-9a-f-]+)\/(approve|reject)$/);
 if(adminDecision&&method==='POST'){
  requireRole(user,'hospital_admin');const app=db.prepare('SELECT * FROM doctor_applications WHERE id=?').get(adminDecision[1]);if(!app||app.status!=='pending')throw fail(404,'Pending application not found.');
  if(adminDecision[2]==='reject'){db.prepare('UPDATE doctor_applications SET status=\'rejected\',reviewed_by=?,reviewed_at=datetime(\'now\') WHERE id=?').run(user.user_id,app.id);db.prepare('UPDATE users SET status=\'deactivated\' WHERE id=?').run(app.user_id);audit(user.user_id,'doctor.application.reject','doctor_application',app.id);return json(res,200,{ok:true,status:'rejected'});}
  const code=Array.from({length:4},()=>{const chars='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';return chars[crypto.randomInt(chars.length)]}).join('');
  db.prepare('UPDATE doctor_applications SET status=\'approved\',reviewed_by=?,reviewed_at=datetime(\'now\') WHERE id=?').run(user.user_id,app.id);db.prepare('UPDATE users SET status=\'active\',doctor_code_hash=? WHERE id=?').run(sha(code),app.user_id);audit(user.user_id,'doctor.application.approve','doctor_application',app.id);return json(res,200,{ok:true,status:'approved',doctorCode:code});
 }
 if(p==='/api/doctor/patients'&&method==='GET'){
  requireRole(user,'doctor');const rows=db.prepare(`SELECT v.patient_id,p.full_name patient_name,max(v.consultation_at) last_visit,count(v.id) visits FROM visits v JOIN users p ON p.id=v.patient_id WHERE v.doctor_id=? GROUP BY v.patient_id,p.full_name ORDER BY last_visit DESC LIMIT 50`).all(user.user_id);return json(res,200,{patients:rows});
 }
 const shareView=p.match(/^\/api\/doctor\/shares\/([^/]+)$/);
 if(shareView&&method==='GET'){
  requireRole(user,'doctor');const s=shareForToken(shareView[1]);if(!s)throw fail(404,'Share link is expired, revoked or invalid.');const records=db.prepare(`SELECT r.* FROM medical_records r JOIN share_records sr ON sr.record_id=r.id WHERE sr.share_id=? ORDER BY COALESCE(r.record_date,r.created_at) DESC`).all(s.id);audit(user.user_id,'share.view','share',s.id);return json(res,200,{share:{id:s.id,patientId:s.patient_id,patientName:s.patient_name,expiresAt:new Date(s.expires_at).toISOString()},records:records.map(publicRecord)});
 }
 const shareFile=p.match(/^\/api\/doctor\/shares\/([^/]+)\/records\/([^/]+)\/file$/);
 if(shareFile&&method==='GET'){
  requireRole(user,'doctor');const s=shareForToken(shareFile[1]);if(!s)throw fail(404,'Share link is expired or revoked.');const ok=db.prepare('SELECT 1 FROM share_records WHERE share_id=? AND record_id=?').get(s.id,shareFile[2]);if(!ok)throw fail(403,'This record was not included in the patient’s share.');const r=db.prepare('SELECT * FROM medical_records WHERE id=? AND patient_id=?').get(shareFile[2],s.patient_id);if(!r)throw fail(404,'Record not found.');audit(user.user_id,'shared_record.download','medical_record',r.id);return pdfRoute(req,res,r,'doctor-share');
 }
 const visitCreate=p.match(/^\/api\/doctor\/shares\/([^/]+)\/visits$/);
 if(visitCreate&&method==='POST'){
  requireRole(user,'doctor');const s=shareForToken(visitCreate[1]);if(!s)throw fail(404,'Share link is expired or revoked.');const b=await bodyJson(req);const summary=String(b.summary||'').trim().slice(0,5000),hospital=String(b.hospital||'').trim().slice(0,200),date=String(b.consultationAt||new Date().toISOString());if(!summary)throw fail(400,'Add a visit summary before saving.');
  const records=db.prepare(`SELECT r.id,r.title,r.record_type,r.source_name,r.record_date,r.file_name,r.file_size,r.sha256 FROM medical_records r JOIN share_records sr ON sr.record_id=r.id WHERE sr.share_id=?`).all(s.id);
  const visitId=id(),snapshotId=id(),snapshot=JSON.stringify(records),snapshotHash=sha(snapshot);
  db.prepare('INSERT INTO visits(id,patient_id,doctor_id,share_id,hospital,summary,consultation_at) VALUES(?,?,?,?,?,?,?)').run(visitId,s.patient_id,user.user_id,s.id,hospital,summary,date);
  db.prepare('INSERT INTO visit_snapshots(id,visit_id,records_json,snapshot_hash) VALUES(?,?,?,?)').run(snapshotId,visitId,snapshot,snapshotHash);
  audit(user.user_id,'visit.create','visit',visitId,'success',{patientId:s.patient_id,records:records.length});return json(res,201,{visit:{id:visitId,patientId:s.patient_id,doctorId:user.user_id,hospital,summary,consultationAt:date,snapshotId,snapshotHash,records}});
 }
 const rxCreate=p.match(/^\/api\/doctor\/visits\/([^/]+)\/prescriptions$/);
 if(rxCreate&&method==='POST'){
  requireRole(user,'doctor');const visit=db.prepare('SELECT * FROM visits WHERE id=? AND doctor_id=?').get(rxCreate[1],user.user_id);if(!visit)throw fail(404,'Visit not found for this doctor.');const b=await bodyJson(req);const medicine=String(b.medicine||'').trim().slice(0,200),dosage=String(b.dosage||'').trim().slice(0,200),frequency=String(b.frequency||'').trim().slice(0,200),duration=String(b.duration||'').trim().slice(0,200),instructions=String(b.instructions||'').trim().slice(0,1000);if(!medicine||!dosage||!frequency||!duration)throw fail(400,'Medicine, dosage, frequency and duration are required.');const pid=id();db.prepare('INSERT INTO prescriptions(id,visit_id,patient_id,doctor_id,medicine,dosage,frequency,duration,instructions) VALUES(?,?,?,?,?,?,?,?,?)').run(pid,visit.id,visit.patient_id,user.user_id,medicine,dosage,frequency,duration,instructions);audit(user.user_id,'prescription.create','prescription',pid,'success',{visitId:visit.id,patientId:visit.patient_id});return json(res,201,{prescription:db.prepare('SELECT * FROM prescriptions WHERE id=?').get(pid)});
 }
 if(p.startsWith('/api/'))throw fail(404,'API route not found.');
 if(method!=='GET'&&method!=='HEAD')throw fail(405,'Method not allowed.');
 const file=p==='/'?'index.html':decodeURIComponent(p.slice(1));if(!publicFiles.has(file))throw fail(404,'Page not found.');
 const ext=path.extname(file);const data=await fsp.readFile(path.join(ROOT,file));return send(res,200,data,{'Content-Type':mimeFor(ext)});
}
function loginResponse(req,res,userId,email,role){const token=crypto.randomBytes(32).toString('base64url');db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(sha(token),userId,Date.now()+8*60*60*1000);audit(userId,'auth.login','user',userId);return json(res,200,{ok:true,user:{id:userId,email,role}}, {'Set-Cookie':sessionCookie(token,8*60*60)});}
const server=http.createServer((req,res)=>{route(req,res).catch(e=>{const status=e.status||500;if(status>=500)console.error(e);const actor=currentUser(req);if(status>=400&&actor)audit(actor.user_id,'request.denied','route',req.url,'denied',{status});if(!res.headersSent)json(res,status,{error:status>=500?'Server error. Check the local server log.':e.message||'Request failed.'});else res.destroy()})});
server.listen(PORT,HOST,()=>console.log(`Connected Care local API ready at http://${HOST}:${PORT}\nDatabase: ${DB_FILE}\nPrivate PDFs: ${FILES}\nLOCAL DEVELOPMENT ONLY — do not use real patient data.`));
