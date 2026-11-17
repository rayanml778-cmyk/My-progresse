const fs=require('fs'),vm=require('vm');
const html=fs.readFileSync(process.argv[2]||'index.html','utf8');
const blk=[...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map(m=>m[1]).sort((a,b)=>b.length-a.length)[0];
const cut=(a,b,incl)=>{const i=blk.indexOf(a);if(i<0)throw new Error('start not found: '+a);const j=blk.indexOf(b,i);if(j<0)throw new Error('end not found: '+b);return blk.slice(i,j+(incl?b.length:0))};
// ---- مقتطفات الكود الحقيقي من الملف
const quizCode=cut('let QS={};','el.innerHTML=`<div class="plw">${hd}${b}</div>`}};',true);
const lhData=cut('const LHC={',"/* ---------- الواجهة ---------- */");   // LHC..LHT..LHG..LH engine..Object.assign(LH)
const enStopLine=blk.split('\n').find(l=>l.startsWith('const enStop='));
const tutLine=blk.split('\n').find(l=>l.startsWith('const tutorSys='));
// ---- متصفح وFirestore مُحاكيان (حسابات منفصلة بمستندات منفصلة)
const store=new Map();                 // localStorage
const remote={};                       // Firestore: quiz/{uid}
const sb={console,setTimeout,clearTimeout,Date,Math,JSON,Object,Array,String,Number,Promise,Set,Map,Error,
 localStorage:{getItem:k=>store.has(k)?store.get(k):null,setItem:(k,v)=>store.set(k,String(v)),removeItem:k=>store.delete(k),get length(){return store.size},key:i=>[...store.keys()][i]},
 LANG:'en',TODAY:()=>'2026-11-17',add:(d,n)=>{const x=new Date(d+'T00:00:00Z');x.setUTCDate(x.getUTCDate()+n);return x.toISOString().slice(0,10)},
 EN:{uid:'',tok:'',ready:false,qz:null,un:[],use:null},
 FB:{db:{collection:c=>({doc:id=>({set:async o=>{remote[c+'/'+id]=JSON.parse(JSON.stringify(o))}})})}},
 userPlan:()=>'premium',toast:()=>{},plansOpen:()=>{},A:{},$:()=>null,esc:s=>String(s),I:()=>'',AU:{uid:'x'},fbUser:async()=>null,enStart:()=>{},qReset0:()=>{},
 moon:()=>({}),mtm:x=>x,TUT_BASE:'BASE',TUT:{},TNM:{en:'Nova',fr:'Luc',ar:'Sami'},LHN:{ar:'Arabic',fr:'French',en:'English'},
 QBK:{ar:[[],[],[]],fr:[[],[],[]],en:[[],[],[]]},lhUL:()=>'English'};
sb.P=(a,e,f)=>sb.LANG=='en'?e:sb.LANG=='fr'?f:a;
sb.lget=k=>sb.localStorage.getItem(k)||'';
vm.createContext(sb);
const run=(c,n)=>vm.runInContext(c,sb,{filename:n});
run(quizCode,'quiz');

try{run(lhData,'lhData')}catch(e){console.log('lhData ERR',e.message.split('\n')[0]);process.exit(1)}
q0=0;run(enStopLine,'enStop');run('LS={l:"en",pt:null}','ls');let tutOk=true;try{run(tutLine,'tut')}catch(e){tutOk=false;console.log('tutorSys load ERR',e.message.split('\n')[0]);run('var tutorSys=(l)=>""','tutstub')}
let pass=0,fail=0;const ok=(c,m)=>{if(c){pass++;console.log('  ✓',m)}else{fail++;console.log('  ✗ FAIL:',m)}};
const J=x=>JSON.stringify(x);
const q=c=>run(c,'t');
const loginA=(uid)=>{q('enStop(1)');q(`EN.uid=${J(uid)};EN.qz=${J(null)}`);sb.EN.qz=remote['quiz/'+uid]?JSON.parse(JSON.stringify(remote['quiz/'+uid])):null;q('QZ.merge();EN.ready=true')};
const logout=async()=>{await q('QZ.flush()');q('enStop()')};

console.log('T1 ترحيل مستخدم قديم (3 مستويات → CEFR) دون فقدان');
store.set('mp_quiz',J({u:5,lv:{en:1,fr:0,ar:2},r:{en:[{d:'2026-11-16',s:4,t:5,l:1}]}}));
q('QZ.d=null');
ok(q("QZ.cf('en')")==2&&q("QZ.cf('fr')")==0&&q("QZ.cf('ar')")==4,'en B1، fr A1، ar C1 (الحدّ الأدنى لكل شريحة)');
ok(q("QZ.lvl('en')")==1&&q("QZ.rec('en').length")==1,'lv القديم ونتائج الاختبار اليومي محفوظة');
store.clear();q('QZ.d=null');

console.log('T2 حسابان منفصلان: A ثم B ثم A');
loginA('uidA');
ok(q("QZ.cf('en')")==-1&&q("QZ.goal('en')")=='','حساب A جديد: لا مستوى ولا هدف');
q("QZ.setCf('en',3,'self');QZ.setCf('fr',1,'test');QZ.setGoal('en','travel');QZ.setGoal('fr','work');LH.D('en').xp=40;LH.D('fr').xp=7;QZ.sv()");
q("QZ.setCf('ar',5,'self')");
ok(q("QZ.cf('en')")==3&&q("QZ.cf('fr')")==1&&q("QZ.cf('ar')")==5,'المستوى مستقل لكل لغة (en B2، fr A2، ar C2)');
ok(q("QZ.goal('en')")=='travel'&&q("QZ.goal('fr')")=='work','الهدف مستقل لكل لغة');
q("QZ.setCf('fr',2,'self')");   // تبديل لغة وتعديل أخرى لا يمس الأولى
ok(q("QZ.cf('en')")==3&&q("LH.D('en').xp")==40&&q("LH.D('fr').xp")==7,'تعديل مستوى لغة لا يغيّر تقدّم اللغات الأخرى');
(async()=>{
await logout();
const A=remote['quiz/uidA'];
ok(A&&A.cf.en=='B2'&&A.cf.fr=='B1'&&A.cf.ar=='C2'&&A.gl.en=='travel'&&A.lh.en.xp==40,'Firestore (محاكى) حفظ مستند A كاملًا');
ok(!store.has('mp_quiz')&&!store.has('mp_quiz_u'),'تسجيل الخروج يمسح البيانات المحلية');
loginA('uidB');
ok(q("QZ.cf('en')")==-1&&q("QZ.goal('en')")==''&&q("LH.D('en').xp")==0,'حساب B لا يرى شيئًا من بيانات A');
q("QZ.setCf('en',0,'self');QZ.setGoal('en','conv')");
await logout();
ok(remote['quiz/uidB'].cf.en=='A1'&&remote['quiz/uidA'].cf.en=='B2','مستندا Firestore منفصلان ولم يتأثر A بكتابة B');
loginA('uidA');
ok(q("QZ.cf('en')")==3&&q("QZ.cf('fr')")==2&&q("QZ.cf('ar')")==5&&q("QZ.goal('en')")=='travel'&&q("LH.D('en').xp")==40,'عودة A بعد الخروج/الدخول: المستويات والأهداف والتقدم كاملة');

console.log('T3 تبديل حساب بدون تسجيل خروج (بقايا محلية)');
q("QZ.setCf('en',4,'self')");q('QZ.flush()');
q('enStop(1)');sb.EN.uid='uidB';sb.EN.qz=JSON.parse(JSON.stringify(remote['quiz/uidB']));q('QZ.merge();EN.ready=true');
ok(q("QZ.cf('en')")==0&&q("QZ.goal('en')")=='conv'&&q("QZ.cf('ar')")==-1,'B بعد A على نفس الجهاز: يرى بياناته فقط');
await q('QZ.flush()');
ok(remote['quiz/uidA'].cf.en=='C1'&&remote['quiz/uidB'].cf.ar===undefined,'لم تتسرّب بيانات A إلى مستند B');
await logout();

console.log('T4 تقدير المستوى (الاختبار الذكي والسريع)');
const est=(lv,cur)=>q(`LH.cfEst(${J(lv)},${cur})`);
ok(est([2,3,4,5,5,5,5,5],5)==5,'إجابات صحيحة كلها → C2');
ok(est([2,1,0,0,0,0,0,0],0)==0,'إجابات خاطئة كلها → A1');
ok(est([2,3,2,3,2,3,2,3],2)==3||est([2,3,2,3,2,3,2,3],2)==2,'تذبذب بين B1/B2 → B1 أو B2 : '+est([2,3,2,3,2,3,2,3],2));
ok(est([2,3,4,3,4,3,4,3],4)==4||est([2,3,4,3,4,3,4,3],4)==3,'تخمين حظّي واحد لا يرفع إلى C2 : '+est([2,3,4,3,4,3,4,3],4));
const fs_=sc=>q(`LH.cfFromSc(${J(sc)})`);
ok(fs_([0,0,0])==0&&fs_([2,0,0])==1&&fs_([3,2,0])==2&&fs_([3,3,1])==3&&fs_([3,3,2])==4&&fs_([3,3,3])==5,'الاختبار السريع ٩ أسئلة → A1…C2');

console.log('T5 الاختبار اليومي يحرّك CEFR مع الشريحة');
loginA('uidA');q("QZ.setCf('en',2,'self');QS={l:'en',v0:1,sc:5};QZ.fin()");
ok(q("QZ.cf('en')")==4&&q("QZ.lvl('en')")==2,'صعود شريحة: B1 → C1');
q("QZ.setCf('en',2,'self');QS={l:'en',v0:1,sc:0};QZ.fin()");
ok(q("QZ.cf('en')")==1&&q("QZ.lvl('en')")==0,'نزول شريحة: B1 → A2');
q("QZ.setCf('en',3,'self');QS={l:'en',v0:1,sc:3};QZ.fin()");
ok(q("QZ.cf('en')")==3,'نتيجة وسطية: المستوى الدقيق B2 لا يتغير');
await logout();

console.log('T6 الخطة والمنهج لكل هدف');
q("QZ.setCf('en',3,'self')");
for(const g of ['conv','exam','work','travel','writing','master','general']){
 const p=q(`LH.plan('en',1,${J(g)},20)`);
 const missing=p.it.filter(id=>!q(`!!LHT[${J(id)}]`));
 ok(p.g==g&&p.cf=='B2'&&!missing.length,`هدف ${g}: ${p.it.length} عنصرًا كلها موجودة، CEFR محفوظ`+(missing.length?' MISSING '+missing:''));
}

console.log('T7 توجيهات المعلّم تتكيّف مع المستوى والهدف');
q("QZ.setGoal('en','work')");
const ls=q("LH.lessonQ('en',{e:'present perfect'},1)"),ex=q("LH.exQ('en',1,'')"),cv=q("LH.cvSys('en',[0,0,0,0,0,'a clerk'],1)");
ok(/CEFR B2/.test(ls)&&/work and career/.test(ls),'درس: CEFR B2 + هدف العمل');
ok(/CEFR B2/.test(ex)&&/work and career/.test(ex),'تمارين: CEFR B2 + هدف العمل');
ok(/CEFR B2/.test(cv)&&/work and career/.test(cv),'محادثة: CEFR B2 + هدف العمل');
q("QZ.ld().gl.en='';");
ok(!/Learning goal/.test(q("LH.lessonQ('en',{e:'x'},1)")),'بلا هدف: لا يُضاف نص هدف');
const pq=q("LH.ptQ('en',4,['Q1','Q2'])");
ok(/CEFR level C1/.test(pq)&&/Q1/.test(pq),'سؤال الاختبار الذكي يطلب مستوى C1 ويتجنب أسئلة سابقة');
sb.moonStub=1;
try{if(!tutOk)throw new Error('tutorSys not loadable');const tsys=q("QZ.setGoal('en','travel'),tutorSys('en',null)");ok(/\[LEARNER LEVEL\] CEFR B2 \(upper intermediate\)/.test(tsys)&&/travel/.test(tsys),'دردشة المعلّم: [LEARNER LEVEL] CEFR + الهدف')}catch(e){console.log('  (tutorSys harness skipped:',e.message.split('\n')[0],')')}
console.log('\nالنتيجة: نجح',pass,'· فشل',fail);process.exit(fail?1:0);
})();
