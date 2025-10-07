(function(){
'use strict';
var SUPABASE_CFG=getSupabaseConfig();
var SUPABASE_URL=SUPABASE_CFG.url||'';
var SUPABASE_ANON_KEY=SUPABASE_CFG.anonKey||'';
var SUPABASE_TABLE=SUPABASE_CFG.table||'planning_state';
var SUPABASE_KEY_COLUMN=SUPABASE_CFG.keyColumn||'id';
var SUPABASE_DATA_COLUMN=SUPABASE_CFG.dataColumn||'state';
var SUPABASE_EXTRA_TABLES=SUPABASE_CFG.extraTables||{};
var SUPABASE_ADMIN_TABLE=SUPABASE_EXTRA_TABLES.admin||null;
var SUPABASE_USERS_TABLE=SUPABASE_EXTRA_TABLES.users||null;
var SUPABASE_PASSWORDS_TABLE=SUPABASE_EXTRA_TABLES.passwords||null;
var SUPABASE_CHOICES_TABLE=SUPABASE_EXTRA_TABLES.choices||null;
var SUPABASE_AUDIT_TABLE=SUPABASE_EXTRA_TABLES.audit||null;
var SUPABASE_SAVE_DELAY=800;
var supabaseClient=null;
var supabaseSaveTimer=null;
var skipRemoteSync=false;
var supabaseChannel=null;
var supabasePendingState=null;
var hasInitialized=false;
var CLIENT_ID=(function(){
  try{
    if(typeof crypto!=='undefined' && crypto.randomUUID){
      return 'client-'+crypto.randomUUID();
    }
  }catch(err){ /* ignore */ }
  var rand=Math.random().toString(36).slice(2);
  var ts=Date.now().toString(36);
  return 'client-'+rand+'-'+ts;
})();
function getSupabaseConfig(){
  if(typeof window==='undefined') return {};
  var inlineCfg={};
  var inline=document.querySelector('script[data-supabase-config]');
  if(inline){
    try{ inlineCfg=JSON.parse(inline.textContent||'{}')||{}; }
    catch(err){ console.error('Supabase config parse error',err); }
  }
  var existing=window.__SUPABASE_CONFIG__;
  var assign=(typeof Object!=='undefined' && Object.assign) ? Object.assign : function(target){
    for(var i=1;i<arguments.length;i++){
      var src=arguments[i]||{};
      for(var key in src){ if(Object.prototype.hasOwnProperty.call(src,key)) target[key]=src[key]; }
    }
    return target;
  };
  var merged=assign({}, inlineCfg);
  if(existing && typeof existing==='object'){
    merged=assign(merged, existing);
    if(typeof existing.adminPasswordHash==='string' && existing.adminPasswordHash){
      merged.adminPasswordHash=existing.adminPasswordHash;
    }
  }
  window.__SUPABASE_CONFIG__=merged;
  return merged;
}
var KEY="planning_gardes_state_v080";
var ADMIN_PWD=typeof SUPABASE_CFG.adminPassword==='string'?SUPABASE_CFG.adminPassword.trim():"";
var ADMIN_PWD_HASH=typeof SUPABASE_CFG.adminPasswordHash==='string'?SUPABASE_CFG.adminPasswordHash.trim():"";
var ADMIN_ACCESS_ENABLED=ADMIN_PWD.length>0||ADMIN_PWD_HASH.length>0;
var DAYS=["Lun","Mar","Mer","Jeu","Ven","Sam","Dim"];
var MONTHS=["janvier","février","mars","avril","mai","juin","juillet","août","septembre","octobre","novembre","décembre"];
var MONTHS_SHORT=MONTHS.map(function(m){return m.slice(0,4);});
var DAYS_HEADER=DAYS.map(function(d){return '<th>'+d+'</th>';}).join('');
var auditFilters={};
var attribHandle=null;
var swapSource=null;

function toHex(buffer){
  var hex='';
  for(var i=0;i<buffer.length;i++){
    var h=buffer[i].toString(16);
    if(h.length===1) hex+='0';
    hex+=h;
  }
  return hex;
}

function sha256HexSync(message){
  function rightRotate(value, amount){ return (value>>>amount) | (value<<(32-amount)); }
  var mathPow=Math.pow;
  var maxWord=mathPow(2, 32);
  var result='';
  var words=[];
  var asciiBitLength=message.length*8;
  var hash=[], k=[], primeCounter=0;
  var isComposite={};
  for(var candidate=2; primeCounter<64; candidate++){
    if(!isComposite[candidate]){
      for(var i=candidate*candidate;i<2048;i+=candidate){ isComposite[i]=true; }
      hash[primeCounter]=(mathPow(candidate, 0.5)*maxWord)|0;
      k[primeCounter++]=(mathPow(candidate, 1/3)*maxWord)|0;
    }
  }
  message+="\x80";
  while(message.length%64-56) message+="\x00";
  for(var j=0;j<message.length;j++){
    var code=message.charCodeAt(j);
    words[j>>2]|=code<<((3-j)%4)*8;
  }
  words[words.length]=((asciiBitLength/maxWord)|0);
  words[words.length]=(asciiBitLength)&0xffffffff;
  for(var offset=0; offset<words.length;){
    var w=words.slice(offset, offset+=16);
    var oldHash=hash.slice(0);
    for(var i64=0;i64<64;i64++){
      var w15=w[i64-15], w2=w[i64-2];
      var s0=w15!==undefined? (rightRotate(w15,7)^rightRotate(w15,18)^(w15>>>3)) : 0;
      var s1=w2!==undefined? (rightRotate(w2,17)^rightRotate(w2,19)^(w2>>>10)) : 0;
      if(i64<16) w[i64]=w[i64]||0;
      else w[i64]=(w[i64-16]+s0+w[i64-7]+s1)|0;
      var ch=(hash[4]&hash[5])^(~hash[4]&hash[6]);
      var maj=(hash[0]&hash[1])^(hash[0]&hash[2])^(hash[1]&hash[2]);
      var sigma0=rightRotate(hash[0],2)^rightRotate(hash[0],13)^rightRotate(hash[0],22);
      var sigma1=rightRotate(hash[4],6)^rightRotate(hash[4],11)^rightRotate(hash[4],25);
      var t1=(hash[7]+sigma1+ch+k[i64]+w[i64])|0;
      var t2=(sigma0+maj)|0;
      hash=[(t1+t2)|0].concat(hash);
      hash[4]=(hash[4]+t1)|0;
    }
    for(var iHash=0;iHash<8;iHash++) hash[iHash]=(hash[iHash]+oldHash[iHash])|0;
  }
  for(var iOut=0;iOut<8;iOut++){
    for(var jOut=3;jOut+1;jOut--){
      var value=(hash[iOut]>>>(jOut*8))&255;
      result+=((value<16?'0':'')+value.toString(16));
    }
  }
  return result;
}

function sha256Hex(message){
  if(typeof window!=='undefined' && window.crypto && window.crypto.subtle && typeof TextEncoder!=='undefined'){
    try{
      var encoder=new TextEncoder();
      return window.crypto.subtle.digest('SHA-256', encoder.encode(message))
        .then(function(buffer){ return toHex(new Uint8Array(buffer)); })
        .catch(function(){ return sha256HexSync(message); });
    }catch(err){ /* ignore and fallback */ }
  }
  return Promise.resolve(sha256HexSync(message));
}

function verifyAdminPassword(input){
  if(!ADMIN_ACCESS_ENABLED) return Promise.resolve(false);
  if(ADMIN_PWD_HASH){
    return sha256Hex(input).then(function(hash){ return hash===ADMIN_PWD_HASH; });
  }
  return Promise.resolve(input===ADMIN_PWD);
}

function showLoading(){
  var overlay=document.createElement('div');
  overlay.id='loadingOverlay';
  overlay.className='loading-overlay';
  overlay.innerHTML='<div class="loading-spinner"></div>';
  document.body.appendChild(overlay);
}
function hideLoading(){
  var overlay=document.getElementById('loadingOverlay');
  if(overlay) document.body.removeChild(overlay);
}

function setOf(a){var o={};for(var i=0;i<a.length;i++)o[a[i]]=true;return o;}
var TYPE_VISITES=setOf(["1N","2N","3N","4C","5S","6S","N","C","S","VIS"]);
var TYPE_CONSULTS=setOf(["C1COU","C2COU","C1BOU","C2BOU","PFG","C1ANT","C2ANT","C1","C2","C3"]);
var TYPE_TCS=setOf(["TC","TCN"]);
var DEFAULT_COL_TYPES=[
  "1N","2N","3N","4C","5S","6S","VIS","VIS","VIS","VIS","VIS","TC",
  "C1COU","C2COU","C1BOU","C2BOU","PFG","C1ANT","C2ANT","TC","N","C",
  "S","VIS","VIS","VIS","C1COU","C2COU","C1BOU","C2BOU","PFG","C1ANT",
  "C2ANT","TC","VIS","PFG","VIS","VIS","VIS","VIS","VIS","VIS","TCN",
  "VIS","VIS","VIS","VIS","VIS","VIS"
];
var DEFAULT_COLUMN_COUNT=DEFAULT_COL_TYPES.length;

function pad(n){return (n<10?"0":"")+n;}
function trigram(s){if(!s)return"";var t=s.trim().toUpperCase().replace(/[^A-Z]/g,"");return t.slice(0,3);}
function catOf(type){
  var t=(type||"").toUpperCase();
  if(TYPE_TCS[t]) return "tc";
  if(TYPE_CONSULTS[t]) return "consultation";
  if(TYPE_VISITES[t]) return "visite";
  return "";
}
function daysInMonth(y,m){
  var count=new Date(y,m+1,0).getDate();
  var arr=[];
  for(var i=1;i<=count;i++){
    var dt=new Date(y,m,i);
    arr.push({y:y,m:m,d:i,w:(dt.getDay()||7)});
  }
  return arr;
}
function holidaySet(txt){
  var o={};
  (txt||"").split(",").forEach(function(s){
    var m=s.trim().match(/^(\d{2})-(\d{2})-(\d{4})$/);
    if(m) o[m[3]+"-"+m[2]+"-"+m[1]]=true;
  });
  return o;
}
function easterDate(y){
  var a=y%19,b=Math.floor(y/100),c=y%100,d=Math.floor(b/4),e=b%4,f=Math.floor((b+8)/25),
      g=Math.floor((b-f+1)/3),h=(19*a+b-d-g+15)%30,i=Math.floor(c/4),k=c%4,
      l=(32+2*e+2*i-h-k)%7,m=Math.floor((a+11*h+22*l)/451),
      month=Math.floor((h+l-7*m+114)/31),day=1+((h+l-7*m+114)%31);
  return new Date(y,month-1,day);
}
function frenchHolidaysForMonths(y,m1,m2){
  var months={}; months[m1]=true; if(m2!=null) months[m2]=true;
  var easter=easterDate(y);
  var hol=[
    new Date(y,0,1),
    new Date(y,easter.getMonth(),easter.getDate()+1),
    new Date(y,4,1),
    new Date(y,4,8),
    new Date(y,easter.getMonth(),easter.getDate()+39),
    new Date(y,easter.getMonth(),easter.getDate()+50),
    new Date(y,6,14),
    new Date(y,7,15),
    new Date(y,10,1),
    new Date(y,10,11),
    new Date(y,11,25)
  ];
  return hol.filter(function(d){return months[d.getMonth()];})
            .sort(function(a,b){return a-b;})
            .map(function(d){return pad(d.getDate())+'-'+pad(d.getMonth()+1)+'-'+d.getFullYear();})
            .join(', ');
}
function keyOf(y,m,d,col){return y+"-"+pad(m+1)+"-"+pad(d)+"::"+col;}

function keyInfo(st,key){
  if(!key) return {dateStr:"",day:"",col:"",hours:""};
  var parts=key.split("::");
  var dateParts=parts[0].split("-");
  var y=+dateParts[0], m=+dateParts[1]-1, d=+dateParts[2];
  var dateObj=new Date(y,m,d);
  var colId=parts[1];
  var col=st.columns[parseInt(colId.replace("col",""),10)-1]||{};
  return {
    dateStr:pad(d)+"/"+pad(m+1)+"/"+y,
    day:DAYS[(dateObj.getDay()+6)%7],
    col:col.type||colId,
    hours:(col.start||"")+"-"+(col.end||"")
  };
}

function cellKey(cell){
  return keyOf(
    parseInt(cell.getAttribute("data-y"),10),
    parseInt(cell.getAttribute("data-m"),10),
    parseInt(cell.getAttribute("data-d"),10),
    cell.getAttribute("data-col")
  );
}

function formatTs(ts){
  var d=new Date(ts);
  return pad(d.getDate())+"/"+pad(d.getMonth()+1)+"/"+d.getFullYear()+" "+pad(d.getHours())+":"+pad(d.getMinutes());
}

function auditLabel(it){
  if(it.action==='request') return 'Demande';
  if(it.action==='accept') return 'Acceptation';
  if(it.action==='status'){
    if(it.to==='refused') return 'Refus';
    if(it.to==='pending') return 'Remise en attente';
    if(it.to==='accepted') return 'Acceptation';
    return 'Statut '+it.to;
  }
  if(it.action==='assign') return it.by==='auto' ? 'Attribution automatique' : 'Ajout manuel';
  if(it.action==='clear') return 'Suppression';
  if(it.action==='auto-refuse') return 'Refus auto (créneau pris)';
  if(it.action==='auto-refuse-alt') return 'Refus auto (alternative)';
  if(it.action==='swap-propose') return 'Proposition d\'échange';
  if(it.action==='swap-cancelled') return 'Échange annulé';
  if(it.action==='swap-accepted') return 'Échange accepté';
  if(it.action==='swap-refused') return 'Échange refusé';
  if(it.action==='swap-auto-cancelled') return 'Annulation auto (échange conclu)';
  if(it.action==='swap-free') return 'Échange avec garde disponible';
  return it.action;
}

function defaultColumns(){
  var a=[];
  for(var i=1;i<=DEFAULT_COLUMN_COUNT;i++)a.push({
    id:"col"+i,
    type:DEFAULT_COL_TYPES[i-1]||"",
    start:"08:00",
    end:"20:00",
    color:"#1e293b",
    q_wd:"bonne",
    q_sat:"bonne",
    q_sun:"bonne",
    open_m_wd:true,
    open_m_sat:true,
    open_m_sun:true,
    open_b_wd:true,
    open_b_sat:true,
    open_b_sun:true
  });
  return a;
}
function mergeColumnsWithDefaults(existing){
  var defaults=defaultColumns();
  if(existing && existing.length===DEFAULT_COLUMN_COUNT) return existing;
  var merged=[];
  for(var ci=0;ci<DEFAULT_COLUMN_COUNT;ci++){
    var base=defaults[ci];
    var current=(existing&&existing[ci])||{};
    var col={};
    for(var key in base){ if(Object.prototype.hasOwnProperty.call(base,key)) col[key]=base[key]; }
    for(var keyCur in current){ if(Object.prototype.hasOwnProperty.call(current,keyCur)) col[keyCur]=current[keyCur]; }
    col.id=base.id;
    merged[ci]=col;
  }
  return merged;
}
function defaultState(){
  var tours=[];
  for(var i=0;i<10;i++) tours.push({columns:defaultColumns(), consigne:"", choiceType:"simple"});
  return{
    month:(new Date()).getMonth(),month2:null,year:(new Date()).getFullYear(),holidays:"",
    tours:tours,
    columns:tours[0].columns,
    activeTour:null,
    adminTourTab:0,
    users:{associes:[],remplacants:[]},passwords:{},sessions:{},progress:{},
    draftSelections:{},published:{},audit:[],loginLogs:[],
    unavailabilities:{},
    access:{associes:{},remplacants:{}},
    tradeEnabled:true,
    saisieEnabled:true,
    meta:{lastModifiedBy:"",lastModifiedAt:0},
      recapNav:{order:"asc", phase:"m", group:"associes", filterDoc:"", filterEtat:"pending", filterType:"", attrRole:"associes", attrOrder:"asc", attrStart:"", attrType:"simple", attrLoops:1, attrM:1, attrB:1, attrX:0, attrY:0, planPhase:"m", planTour:null}
  };
}

function migrate(prev, st){
  try{
    if(!prev) return st;
    if(prev.month!=null) st.month=prev.month;
    if(prev.month2!=null) st.month2=prev.month2;
    if(prev.year!=null) st.year=prev.year;
    st.holidays=prev.holidays||"";
    if(prev.tours && prev.tours.length===10){
      st.tours=prev.tours;
    }else if(prev.columns && prev.columns.length===DEFAULT_COLUMN_COUNT){
      st.tours[0].columns=prev.columns;
    }
    st.columns=st.tours[0].columns;
    st.activeTour=(typeof prev.activeTour!=='undefined')?prev.activeTour:null;
    st.users=prev.users||st.users; st.passwords=prev.passwords||st.passwords;
    st.sessions={};
    st.progress=prev.progress||st.progress;
    st.draftSelections=prev.draftSelections||st.draftSelections;
    st.published=prev.published||st.published;
    st.audit=prev.audit||st.audit;
    st.loginLogs=prev.loginLogs||st.loginLogs;
    st.access=prev.access||st.access;
    st.tradeEnabled=(typeof prev.tradeEnabled!=="undefined")?prev.tradeEnabled:true;
    st.saisieEnabled=(typeof prev.saisieEnabled!=="undefined")?prev.saisieEnabled:true;
    if(prev.meta){ st.meta=prev.meta; }
    var ph = prev.recapNav && prev.recapNav.phase;
    st.recapNav = prev.recapNav || st.recapNav;
    if(ph==="mauvaises") st.recapNav.phase="m";
    if(ph==="bonnes") st.recapNav.phase="y";
  }catch(e){console.error("migrate error",e);} 
  return st;
}
var currentState=null;
function save(st){
  st.meta=st.meta||{lastModifiedBy:"",lastModifiedAt:0};
  st.meta.lastModifiedBy=CLIENT_ID;
  st.meta.lastModifiedAt=Date.now();
  currentState=st;
  scheduleRemoteSave(st);
}
function load(){
  if(currentState){
    return currentState;
  }
  var st=defaultState();
  try{ normalize(st); }
  catch(e){ console.error("State normalize error",e); }
  currentState=st;
  scheduleRemoteSave(st);
  return currentState;
}
function getSupabaseClient(){
  if(!SUPABASE_URL || !SUPABASE_ANON_KEY) return null;
  if(supabaseClient) return supabaseClient;
  if(typeof window!=='undefined' && window.supabase && typeof window.supabase.createClient==='function'){
    supabaseClient=window.supabase.createClient(SUPABASE_URL,SUPABASE_ANON_KEY);
    return supabaseClient;
  }
  return null;
}
function scheduleRemoteSave(st){
  if(skipRemoteSync) return;
  if(!SUPABASE_TABLE || !SUPABASE_KEY_COLUMN || !SUPABASE_DATA_COLUMN) return;
  var client=getSupabaseClient();
  if(!client) return;
  var serialized;
  supabasePendingState=st;
  try{ serialized=JSON.stringify(st); }
  catch(e){ console.error("Supabase serialize error",e); return; }
  if(supabaseSaveTimer) clearTimeout(supabaseSaveTimer);
  supabaseSaveTimer=setTimeout(function(){
    supabaseSaveTimer=null;
    supabasePersistState(serialized, supabasePendingState);
    supabasePendingState=null;
  }, SUPABASE_SAVE_DELAY);
}
function supabasePersistState(serialized, originalState){
  if(!SUPABASE_TABLE || !SUPABASE_KEY_COLUMN || !SUPABASE_DATA_COLUMN) return;
  var client=getSupabaseClient();
  if(!client) return;
  var payload={};
  payload[SUPABASE_KEY_COLUMN]=KEY;
  try{ payload[SUPABASE_DATA_COLUMN]=JSON.parse(serialized); }
  catch(e){ console.error("Supabase parse error",e); return; }
  client.from(SUPABASE_TABLE).upsert(payload,{onConflict:SUPABASE_KEY_COLUMN})
    .then(function(res){
      if(res && res.error){
        console.error("Supabase save error",res.error);
        return;
      }
      var baseState = originalState || payload[SUPABASE_DATA_COLUMN];
      supabasePersistDerivedTables(baseState);
    })
    .catch(function(err){ console.error("Supabase save failure",err); });
}
function supabasePersistDerivedTables(state){
  if(!state) return;
  var client=getSupabaseClient();
  if(!client) return;
  var tasks=[];
  if(SUPABASE_ADMIN_TABLE){
    var adminRow={
      planning_id:KEY,
      active_tour:(typeof state.activeTour==='number')?state.activeTour:null,
      year:state.year||null,
      month:typeof state.month==='number'?state.month:null,
      month_two:typeof state.month2==='number'?state.month2:null,
      holidays:state.holidays||'',
      trade_enabled:!!state.tradeEnabled,
      saisie_enabled:!!state.saisieEnabled,
      access:state.access||{},
      tours:state.tours||[],
      columns:state.columns||[],
      updated_at:new Date().toISOString()
    };
    tasks.push(
      client.from(SUPABASE_ADMIN_TABLE)
        .upsert(adminRow,{onConflict:'planning_id'})
        .then(function(res){ if(res && res.error) console.error('Supabase admin sync error',res.error); })
        .catch(function(err){ console.error('Supabase admin sync failure',err); })
    );
  }
  if(SUPABASE_USERS_TABLE){
    var userRows=[];
    var assoc=(state.users&&state.users.associes)||[];
    var remp=(state.users&&state.users.remplacants)||[];
    assoc.forEach(function(name){ userRows.push({planning_id:KEY, role:'associe', name:name}); });
    remp.forEach(function(name){ userRows.push({planning_id:KEY, role:'remplacant', name:name}); });
    tasks.push(
      supabaseReplaceRows(SUPABASE_USERS_TABLE,userRows,'planning_id,name')
    );
  }
  if(SUPABASE_PASSWORDS_TABLE){
    var pwdRows=[];
    if(state.passwords){
      Object.keys(state.passwords).forEach(function(name){
        pwdRows.push({planning_id:KEY, name:name, password:state.passwords[name]});
      });
    }
    tasks.push(
      supabaseReplaceRows(SUPABASE_PASSWORDS_TABLE,pwdRows,'planning_id,name')
    );
  }
  if(SUPABASE_CHOICES_TABLE){
    var choiceRows=[];
    if(state.published){
      Object.keys(state.published).forEach(function(user){
        var entries=state.published[user]||{};
        Object.keys(entries).forEach(function(key){
          var item=entries[key];
          if(!item) return;
          var info=keyInfo(state,key);
          choiceRows.push({
            planning_id:KEY,
            user:user,
            cell_key:key,
            status:item.status||'',
            category:item.cat||catOf(info.col),
            level:typeof item.level==='number'?item.level:null,
            alternative:typeof item.alt==='number'?item.alt:null,
            phase:item.phase||'',
            timestamp:item.ts||null,
            date_label:info.dateStr||'',
            day_label:info.day||'',
            column_label:info.col||'',
            hours_label:info.hours||''
          });
        });
      });
    }
    tasks.push(
      supabaseReplaceRows(SUPABASE_CHOICES_TABLE,choiceRows,'planning_id,user,cell_key')
    );
  }
  if(SUPABASE_AUDIT_TABLE){
    var auditRows=[];
    if(state.audit){
      state.audit.forEach(function(entry,idx){
        if(!entry) return;
        auditRows.push({
          planning_id:KEY,
          idx:idx,
          timestamp:entry.ts||entry.time||null,
          actor:entry.by||'',
          action:entry.action||'',
          payload:entry
        });
      });
    }
    tasks.push(
      supabaseReplaceRows(SUPABASE_AUDIT_TABLE,auditRows,'planning_id,idx')
    );
  }
  if(tasks.length){
    Promise.all(tasks).catch(function(err){ console.error('Supabase derived sync failure',err); });
  }
}
function supabaseReplaceRows(tableName, rows, conflict){
  var client=getSupabaseClient();
  if(!client || !tableName) return Promise.resolve();
  return client.from(tableName)
    .delete()
    .eq('planning_id',KEY)
    .then(function(res){
      if(res && res.error){
        console.error('Supabase replace delete error',res.error);
      }
      if(!rows || !rows.length) return null;
      var opts=conflict?{onConflict:conflict}:undefined;
      return client.from(tableName).upsert(rows,opts)
        .then(function(insertRes){
          if(insertRes && insertRes.error) console.error('Supabase replace insert error',insertRes.error);
        })
        .catch(function(err){ console.error('Supabase replace insert failure',err); });
    })
    .catch(function(err){ console.error('Supabase replace delete failure',err); });
}
function supabaseClearDerivedTables(options){
  var client=getSupabaseClient();
  if(!client) return Promise.resolve();
  var opts=options||{};
  var keepAdmin=(typeof opts.keepAdmin==="undefined")?true:!!opts.keepAdmin;
  var keepUsers=!!opts.keepUsers;
  var keepPasswords=!!opts.keepPasswords;
  var keepChoices=!!opts.keepChoices;
  var keepAudit=!!opts.keepAudit;
  var tasks=[];
  function queue(tableName,label){
    if(!tableName) return;
    tasks.push(
      client.from(tableName)
        .delete()
        .eq('planning_id',KEY)
        .then(function(res){ if(res && res.error) console.error('Supabase clear '+label+' error',res.error); })
        .catch(function(err){ console.error('Supabase clear '+label+' failure',err); })
    );
  }
  if(!keepAdmin) queue(SUPABASE_ADMIN_TABLE,'admin');
  if(!keepUsers) queue(SUPABASE_USERS_TABLE,'users');
  if(!keepPasswords) queue(SUPABASE_PASSWORDS_TABLE,'passwords');
  if(!keepChoices) queue(SUPABASE_CHOICES_TABLE,'choices');
  if(!keepAudit) queue(SUPABASE_AUDIT_TABLE,'audit');
  if(opts.clearState && SUPABASE_TABLE && SUPABASE_KEY_COLUMN){
    tasks.push(
      client.from(SUPABASE_TABLE)
        .delete()
        .eq(SUPABASE_KEY_COLUMN,KEY)
        .then(function(res){ if(res && res.error) console.error('Supabase clear state error',res.error); })
        .catch(function(err){ console.error('Supabase clear state failure',err); })
    );
  }
  if(!tasks.length) return Promise.resolve();
  return Promise.all(tasks);
}
function supabaseFetchState(){
  var client=getSupabaseClient();
  if(!client || !SUPABASE_TABLE || !SUPABASE_KEY_COLUMN || !SUPABASE_DATA_COLUMN) return Promise.resolve(null);
  return client.from(SUPABASE_TABLE).select(SUPABASE_DATA_COLUMN)
    .eq(SUPABASE_KEY_COLUMN,KEY)
    .limit(1)
    .then(function(res){
      if(res && res.error){
        if(res.error && res.error.code!=='PGRST116') console.error("Supabase load error",res.error);
        return null;
      }
      if(res && res.data && res.data.length){
        var row=res.data[0]||{};
        var value=row[SUPABASE_DATA_COLUMN];
        if(typeof value==='string'){
          try{ return JSON.parse(value); }
          catch(e){ console.error("Supabase decode error",e); return null; }
        }
        if(value && typeof value==='object') return value;
      }
      return null;
    })
    .catch(function(err){ console.error("Supabase load failure",err); return null; });
}
function applyRemoteState(remote){
  if(!remote) return;
  try{ normalize(remote); }
  catch(e){ console.error("Supabase normalize error",e); return; }
  skipRemoteSync=true;
  try{ currentState=remote; }
  catch(e){ console.error("Supabase apply error",e); }
  skipRemoteSync=false;
}

function rerenderActiveView(){
  if(!hasInitialized) return;
  route();
}

function handleSupabaseRealtime(payload){
  if(!payload || !payload.new) return;
  var row=payload.new;
  if(!row) return;
  var value=row[SUPABASE_DATA_COLUMN];
  var remote=null;
  if(typeof value==='string'){
    try{ remote=JSON.parse(value); }
    catch(err){ console.error('Supabase realtime decode error',err); return; }
  }else if(value && typeof value==='object'){
    remote=value;
  }
  if(!remote) return;
  if(remote.meta && remote.meta.lastModifiedBy===CLIENT_ID) return;
  applyRemoteState(remote);
  rerenderActiveView();
}

function subscribeToRemoteChanges(){
  var client=getSupabaseClient();
  if(!client || typeof client.channel!=="function") return;
  if(supabaseChannel && typeof supabaseChannel.unsubscribe==="function"){
    try{ supabaseChannel.unsubscribe(); }
    catch(err){ console.warn('Supabase unsubscribe error',err); }
  }
  var channel=client.channel('planning-state-'+KEY);
  try{
    channel.on('postgres_changes', {
      event:'*',
      schema:'public',
      table:SUPABASE_TABLE,
      filter:SUPABASE_KEY_COLUMN+'=eq.'+KEY
    }, handleSupabaseRealtime);
    var result=channel.subscribe(function(status){
      if(status==='CHANNEL_ERROR'){ console.error('Supabase realtime channel error'); }
    });
    if(result && typeof result.catch==='function'){
      result.catch(function(err){ console.error('Supabase realtime subscribe error',err); });
    }
  }catch(err){
    console.error('Supabase realtime setup error',err);
  }
  supabaseChannel=channel;
}
function normalize(st){
  if(!st.tours||st.tours.length!==10){
    st.tours=[];
    for(var ti=0;ti<10;ti++) st.tours.push({columns:defaultColumns(), consigne:"", choiceType:"simple"});
  }
  st.tours.forEach(function(t){
    if(!t.columns||t.columns.length!==DEFAULT_COLUMN_COUNT) t.columns=mergeColumnsWithDefaults(t.columns);
    if(typeof t.consigne==="undefined") t.consigne="";
    if(!t.choiceType) t.choiceType="simple";
    t.columns.forEach(function(c,i){
      if(!c.type) c.type=DEFAULT_COL_TYPES[i];
      if(typeof c.open_m_wd==="undefined") c.open_m_wd=true;
      if(typeof c.open_m_sat==="undefined") c.open_m_sat=true;
      if(typeof c.open_m_sun==="undefined") c.open_m_sun=true;
      if(typeof c.open_b_wd==="undefined") c.open_b_wd=true;
      if(typeof c.open_b_sat==="undefined") c.open_b_sat=true;
      if(typeof c.open_b_sun==="undefined") c.open_b_sun=true;
      if(!c.color) c.color="#1e293b";
      if(!c.q_wd)c.q_wd="bonne";
      if(!c.q_sat)c.q_sat="bonne";
      if(!c.q_sun)c.q_sun="bonne";
    });
  });
  for(var ci=0; ci<st.tours[0].columns.length; ci++){
    var base=st.tours[0].columns[ci];
    st.tours.forEach(function(t,ti){
      if(ti===0) return;
      t.columns[ci].q_wd=base.q_wd;
      t.columns[ci].q_sat=base.q_sat;
      t.columns[ci].q_sun=base.q_sun;
    });
  }
  if(typeof st.activeTour==="undefined") st.activeTour=null;
  if(typeof st.adminTourTab==="undefined") st.adminTourTab=0;
  st.columns=(st.activeTour!=null && st.tours[st.activeTour])?st.tours[st.activeTour].columns:st.tours[0].columns;
  st.columns.forEach(function(c,i){
    if(!c.type) c.type=DEFAULT_COL_TYPES[i];
    if(typeof c.open_m_wd==="undefined") c.open_m_wd=true;
    if(typeof c.open_m_sat==="undefined") c.open_m_sat=true;
    if(typeof c.open_m_sun==="undefined") c.open_m_sun=true;
    if(typeof c.open_b_wd==="undefined") c.open_b_wd=true;
    if(typeof c.open_b_sat==="undefined") c.open_b_sat=true;
    if(typeof c.open_b_sun==="undefined") c.open_b_sun=true;
    if(!c.color) c.color="#1e293b";
    if(!c.q_wd)c.q_wd="bonne";
    if(!c.q_sat)c.q_sat="bonne";
    if(!c.q_sun)c.q_sun="bonne";
  });
  st.users=st.users||{associes:[],remplacants:[]}; st.passwords=st.passwords||{}; st.sessions=st.sessions||{};
  st.progress=st.progress||{};
  Object.keys(st.progress).forEach(function(n){
    var pr=st.progress[n];
    if(typeof pr.m==="undefined") pr.m=false;
    var bx=(pr.x&&pr.y);
    if(typeof pr.b==="undefined") pr.b=bx;
    if(typeof pr.r==="undefined") pr.r=false;
    delete pr.x; delete pr.y;
  });
  st.draftSelections=st.draftSelections||{}; st.published=st.published||{}; st.audit=st.audit||[]; st.loginLogs=st.loginLogs||[];
  st.unavailabilities=st.unavailabilities||{};
  st.access=st.access||{associes:{},remplacants:{}};
  st.users.associes.forEach(function(n){ if(typeof st.access.associes[n]==="undefined") st.access.associes[n]=true; });
  st.users.remplacants.forEach(function(n){ if(typeof st.access.remplacants[n]==="undefined") st.access.remplacants[n]=false; });
  Object.keys(st.access.associes).forEach(function(n){ if(st.users.associes.indexOf(n)===-1) delete st.access.associes[n]; });
  Object.keys(st.access.remplacants).forEach(function(n){ if(st.users.remplacants.indexOf(n)===-1) delete st.access.remplacants[n]; });
  if(typeof st.tradeEnabled==="undefined") st.tradeEnabled=true;
  if(typeof st.saisieEnabled==="undefined") st.saisieEnabled=true;
  st.meta=st.meta||{lastModifiedBy:"",lastModifiedAt:0};
  if(typeof st.meta.lastModifiedBy!=="string") st.meta.lastModifiedBy="";
  if(typeof st.meta.lastModifiedAt!=="number") st.meta.lastModifiedAt=0;
  st.recapNav=st.recapNav||{order:"asc", phase:"m", group:"associes", filterDoc:"", filterEtat:"pending", filterType:"", attrRole:"associes", attrOrder:"asc", attrStart:"", attrType:"simple", attrLoops:1, attrM:1, attrB:1, attrX:0, attrY:0, planPhase:"m", planTour:null};
  if(st.recapNav.phase==='x' || st.recapNav.phase==='y') st.recapNav.phase='b';
  if(st.recapNav.planPhase==='x' || st.recapNav.planPhase==='y') st.recapNav.planPhase='b';
  if(!st.recapNav.group) st.recapNav.group="associes";
  if(!st.recapNav.attrRole) st.recapNav.attrRole="associes";
  if(!st.recapNav.attrOrder) st.recapNav.attrOrder="asc";
  if(typeof st.recapNav.attrStart==="undefined") st.recapNav.attrStart="";
  if(typeof st.recapNav.attrType==="undefined") st.recapNav.attrType="simple";
  if(typeof st.recapNav.attrLoops==="undefined") st.recapNav.attrLoops=1;
  if(typeof st.recapNav.attrM==="undefined") st.recapNav.attrM=1;
  if(typeof st.recapNav.attrB==="undefined") st.recapNav.attrB=1;
  if(typeof st.recapNav.attrX==="undefined") st.recapNav.attrX=0;
  if(typeof st.recapNav.attrY==="undefined") st.recapNav.attrY=0;
  if(typeof st.recapNav.planPhase==="undefined") st.recapNav.planPhase="m";
  if(typeof st.recapNav.planTour==="undefined") st.recapNav.planTour=null;
  if(typeof st.month2==="undefined")st.month2=null; if(typeof st.holidays==="undefined")st.holidays="";
}

// Router
function route(){
  var h=location.hash||"#/saisie-associes";
  var tabs=document.querySelectorAll(".tabs a");for(var i=0;i<tabs.length;i++)tabs[i].classList.remove("active");
  if(h.indexOf("#/admin")===0)document.getElementById("tab-admin").classList.add("active");
  else if(h.indexOf("#/recapitulatif")===0)document.getElementById("tab-recap").classList.add("active");
  else if(h.indexOf("#/saisie-remplacants")===0)document.getElementById("tab-remplacants").classList.add("active");
  else document.getElementById("tab-associes").classList.add("active");
  if(h==="#/admin")renderAdmin();
  else if(h==="#/recapitulatif")renderRecap();
  else if(h==="#/saisie-remplacants")renderSaisie("remplacants");
  else renderSaisie("associes");
}
window.addEventListener("hashchange",route);
document.addEventListener("DOMContentLoaded",function(){if(!location.hash)location.hash="#/saisie-associes";route();});

function buildIndispoMonth(y,m,sel){
  var days=daysInMonth(y,m);
  var first=days.length?days[0].w:1;
  var html=['<div class="indispo-month"><div class="month-label">',MONTHS[m],' ',y,'</div><table class="indispo-grid"><thead><tr>',DAYS_HEADER,'</tr></thead><tbody><tr>'];
  var w=1;
  for(var i=1;i<first;i++,w++) html.push('<td class="empty"></td>');
  days.forEach(function(d){
    var key=d.y+'-'+pad(d.m+1)+'-'+pad(d.d);
    html.push('<td class="day-cell',sel[key]?' selected':'','" data-date="',key,'">',d.d,'</td>');
    if(w%7===0) html.push('</tr><tr>');
    w++;
  });
  while((w-1)%7!==0){ html.push('<td class="empty"></td>'); w++; }
  html.push('</tr></tbody></table></div>');
  return html.join('');
}

function renderIndispo(role,st,name){
  var app=document.getElementById("app");app.innerHTML="";
  var prog=document.getElementById('attribProgress');
  if(prog) prog.remove();
  var status=document.getElementById('attribStatus');
  if(status) status.remove();
  var tourLabel = st.activeTour!=null ? 'Tour '+(st.activeTour+1) : 'Tour non défini';
  var tourTitle=document.createElement('h1');
  tourTitle.className='tour-title';
  tourTitle.textContent=tourLabel;
  app.appendChild(tourTitle);
  if(st.activeTour!=null && st.tours[st.activeTour].consigne){
    var cBox=document.createElement('div');
    cBox.className='consigne-box';
    cBox.textContent=st.tours[st.activeTour].consigne;
    app.appendChild(cBox);
  }
  var sel=Object.assign({},(st.unavailabilities[name]||{}));
  var card=document.createElement("div");card.className="card";
  var html='<div class="row"><span class="badge">Connecté : '+name+'</span><button class="button ghost" id="logoutBtn">Se déconnecter</button></div>'
    +'<h2>Indisponibilités</h2>'
    + buildIndispoMonth(st.year,st.month,sel);
  if(st.month2!==null && st.month2!=="" && !isNaN(st.month2)) html+=buildIndispoMonth(st.year,st.month2,sel);
  html+='<div class="row" style="margin-top:12px"><button class="button" id="saveIndispo">Suivant</button></div>';
  card.innerHTML=html;
  app.appendChild(card);
  card.addEventListener("click",function(e){
    if(e.target&&e.target.id==="logoutBtn"){ st.loginLogs.push({ts:Date.now(), role:(role==='associes'?'medecin':'remplacant'), name:name, type:'logout'}); delete st.sessions[role]; save(st); route(); return; }
    if(e.target.classList&&e.target.classList.contains('day-cell')){
      var dt=e.target.getAttribute('data-date');
      if(sel[dt]){ delete sel[dt]; e.target.classList.remove('selected'); }
      else { sel[dt]=true; e.target.classList.add('selected'); }
      return;
    }
    if(e.target&&e.target.id==="saveIndispo"){
      st.unavailabilities[name]=sel;
      save(st);
      renderSaisie(role);
    }
  });
}

// Admin
function renderAdmin(){
  var st=load();var app=document.getElementById("app");app.innerHTML="";
  var card=document.createElement("div");card.className="card";
  if(!ADMIN_ACCESS_ENABLED && st.sessions._adminOK){
    delete st.sessions._adminOK;
    save(st);
  }
  if(!st.sessions._adminOK){
    if(!ADMIN_ACCESS_ENABLED){
      card.innerHTML='<h2>Admin</h2><p class="notice">Aucun mot de passe administrateur n\'est configuré. Définissez la propriété <code>adminPasswordHash</code> (ou <code>adminPassword</code>) via <code>docs/js/config.js</code>, un script inline ou <code>window.__SUPABASE_RUNTIME_ENV__</code> pour activer cette section.</p>';
      app.appendChild(card);
      return;
    }
    card.innerHTML='<h2>Admin</h2><div class="row"><div class="input"><label>Mot de passe</label><input id="admPwd" type="password" placeholder="••••••"></div><button class="button" id="admLogin">Valider</button></div>';
    app.appendChild(card);
    card.addEventListener("click",function(e){
      if(e.target&&e.target.id==="admLogin"){
        var v=card.querySelector("#admPwd").value;
        verifyAdminPassword(v).then(function(ok){
          if(ok){
            st.sessions._adminOK=true;
            st.loginLogs.push({ts:Date.now(),role:'admin',name:'admin',type:'login'});
            save(st);
            renderAdmin();
          }else{
            alert("Mot de passe incorrect");
          }
        });
      }
    });
    return;
  }
    card.innerHTML='<h2>Administration</h2>'
      +'<div class="row"><div class="input"><label>Tour actif</label><select id="activeTourSel"></select></div></div>'
      +'<div class="row">'
        +'<div class="input"><label>Mois</label><select id="monthSel"></select></div>'
        +'<div class="input"><label>Mois 2</label><select id="month2Sel"></select></div>'
        +'<div class="input"><label>Année</label><select id="yearSel"></select></div>'
        +'<div class="input"><label>Jours fériés (JJ-MM-AAAA, séparés par des virgules)</label><input id="holidaysInp" value="'+(st.holidays||'')+'"></div>'
        +'<button class="button" id="saveCalendar">Enregistrer</button>'
      +'</div>'
      +'<div class="row"><label for="saisieToggle">Autoriser la saisie</label><label class="switch"><input type="checkbox" id="saisieToggle"'+(st.saisieEnabled?' checked':'')+'><span class="slider"></span></label></div>'
      +'<div class="row"><label for="tradeToggle">Autoriser les échanges de garde</label><label class="switch"><input type="checkbox" id="tradeToggle"'+(st.tradeEnabled?' checked':'')+'><span class="slider"></span></label></div>';

  st.columns=st.tours[st.adminTourTab].columns;

  var activeSel=card.querySelector("#activeTourSel"),ms=card.querySelector("#monthSel"),m2=card.querySelector("#month2Sel"),ys=card.querySelector("#yearSel");
  var optClose=document.createElement("option"); optClose.value=""; optClose.textContent="Fermer la saisie"; activeSel.appendChild(optClose);
  for(var t=0;t<10;t++){ var oTour=document.createElement("option"); oTour.value=t; oTour.textContent="Tour "+(t+1); if(st.activeTour===t)oTour.selected=true; activeSel.appendChild(oTour); }
  for(var m=0;m<12;m++){var o=document.createElement("option");o.value=m;o.textContent=MONTHS[m];if(m===st.month)o.selected=true;ms.appendChild(o);}
  var blank=document.createElement("option");blank.value="";blank.textContent="—";if(st.month2===null)blank.selected=true;m2.appendChild(blank);
  for(var m2i=0;m2i<12;m2i++){var o2=document.createElement("option");o2.value=m2i;o2.textContent=MONTHS[m2i];if(st.month2===m2i)o2.selected=true;m2.appendChild(o2);}
  for(var y=2024;y<=2028;y++){var oy=document.createElement("option");oy.value=y;oy.textContent=y;if(y===st.year)oy.selected=true;ys.appendChild(oy);}

  var holInp=card.querySelector("#holidaysInp");
  function autoHolidays(){
    var y=parseInt(ys.value,10);
    var m1=parseInt(ms.value,10);
    var m2v=(m2.value!==""?parseInt(m2.value,10):null);
    holInp.value=frenchHolidaysForMonths(y,m1,m2v);
  }
  ms.addEventListener("change",autoHolidays);
  m2.addEventListener("change",autoHolidays);
  ys.addEventListener("change",autoHolidays);
  if(!st.holidays) autoHolidays();

  var tabs='<div class="tour-tabs">';
  for(var tt=0;tt<10;tt++) tabs+='<div class="tour-tab'+(st.adminTourTab===tt?' active':'')+'" data-tour="'+tt+'">Tour '+(tt+1)+'</div>';
  tabs+='</div>';
  card.insertAdjacentHTML("beforeend",tabs);

  var consRow='<div class="row"><div class="input" style="flex:1"><label>Consignes du tour</label><textarea id="tourConsigne" rows="3"></textarea></div>'
    +'<div class="input"><label>Type de choix</label><select id="choiceTypeSel"><option value="simple">Choix simple</option><option value="bonus">Choix bonus</option></select></div>'
    +'<button class="button" id="saveConsigne">Enregistrer</button></div>';
  card.insertAdjacentHTML("beforeend",consRow);
  card.querySelector('#tourConsigne').value = st.tours[st.adminTourTab].consigne || '';
  card.querySelector('#choiceTypeSel').value = st.tours[st.adminTourTab].choiceType || 'simple';

  var model='<div class="row model-row"><span class="badge">Modèle</span>'
    +'<select data-model="type">'+typeOptions('')+'</select>'
    +'<span style="white-space:nowrap"><input data-model="start" style="width:72px"> – <input data-model="end" style="width:72px"></span>'
    +'<input data-model="color" type="color" value="#1e293b" style="width:80px">'
    +'<select data-model="open_m_wd"><option value="true">Oui</option><option value="false">Non</option></select>'
    +'<select data-model="open_m_sat"><option value="true">Oui</option><option value="false">Non</option></select>'
    +'<select data-model="open_m_sun"><option value="true">Oui</option><option value="false">Non</option></select>'
    +'<select data-model="open_b_wd"><option value="true">Oui</option><option value="false">Non</option></select>'
    +'<select data-model="open_b_sat"><option value="true">Oui</option><option value="false">Non</option></select>'
    +'<select data-model="open_b_sun"><option value="true">Oui</option><option value="false">Non</option></select>'
    +'<select data-model="q_wd">'+qualOptions('bonne')+'</select>'
    +'<select data-model="q_sat">'+qualOptions('bonne')+'</select>'
    +'<select data-model="q_sun">'+qualOptions('bonne')+'</select>'
    +'<button class="button" id="applyModel">Appliquer les valeurs</button></div>';
  var html='<div class="card"><h3>Colonnes ('+DEFAULT_COLUMN_COUNT+')</h3>'+model+'<div class="row"><button class="button" id="saveTour">Enregistrer les paramètres du tour</button></div><table class="table"><thead><tr><th></th><th>#</th><th>Type</th><th>Horaires</th><th>Couleur</th><th>Ouverte M L‑V</th><th>Ouverte M Sam</th><th>Ouverte M Dim/férié</th><th>Ouverte B L‑V</th><th>Ouverte B Sam</th><th>Ouverte B Dim/férié</th><th>Qualité L‑V</th><th>Qualité Sam</th><th>Qualité Dim/férié</th></tr></thead><tbody>';
  st.columns.forEach(function(c,i){
    html+='<tr data-col="'+c.id+'"><td><input type="checkbox" class="colCheck"></td><td>'+(i+1)+'</td>'
      +'<td><select data-field="type">'+typeOptions(c.type)+'</select></td>'
      +'<td style="white-space:nowrap"><input data-field="start" value="'+(c.start||'')+'" style="width:72px"> – <input data-field="end" value="'+(c.end||'')+'" style="width:72px"></td>'
      +'<td><input data-field="color" type="color" value="'+(c.color||'#1e293b')+'" style="width:80px"></td>'
      +'<td><select data-field="open_m_wd"><option value="true" '+(c.open_m_wd?"selected":"")+'>Oui</option><option value="false" '+(c.open_m_wd?"":"selected")+'>Non</option></select></td>'
      +'<td><select data-field="open_m_sat"><option value="true" '+(c.open_m_sat?"selected":"")+'>Oui</option><option value="false" '+(c.open_m_sat?"":"selected")+'>Non</option></select></td>'
      +'<td><select data-field="open_m_sun"><option value="true" '+(c.open_m_sun?"selected":"")+'>Oui</option><option value="false" '+(c.open_m_sun?"":"selected")+'>Non</option></select></td>'
      +'<td><select data-field="open_b_wd"><option value="true" '+(c.open_b_wd?"selected":"")+'>Oui</option><option value="false" '+(c.open_b_wd?"":"selected")+'>Non</option></select></td>'
      +'<td><select data-field="open_b_sat"><option value="true" '+(c.open_b_sat?"selected":"")+'>Oui</option><option value="false" '+(c.open_b_sat?"":"selected")+'>Non</option></select></td>'
      +'<td><select data-field="open_b_sun"><option value="true" '+(c.open_b_sun?"selected":"")+'>Oui</option><option value="false" '+(c.open_b_sun?"":"selected")+'>Non</option></select></td>'
      +'<td><select data-field="q_wd">'+qualOptions(c.q_wd)+'</select></td>'
      +'<td><select data-field="q_sat">'+qualOptions(c.q_sat)+'</select></td>'
      +'<td><select data-field="q_sun">'+qualOptions(c.q_sun)+'</select></td>'
      +'</tr>';
  });
  html+='</tbody></table></div>';

  html+='<div class="card"><h3>Utilisateurs</h3><div class="row">'
    + listEditor("associes","Associés",st)
    + listEditor("remplacants","Remplaçants",st)
    +'</div></div>';

  html+='<div class="card"><h3>Participants (ON/OFF)</h3>'+participantsEditor(st)+'</div>';

  card.insertAdjacentHTML("beforeend",html);
  card.insertAdjacentHTML("beforeend",'<div class="row" style="margin-top:12px"><button class="button ghost" id="resetPlanning">Réinitialiser le planning</button></div>');
  document.getElementById("app").appendChild(card);

  function showApplyModelPopup(modelVals){
    var params=[
      {key:'type',label:'Type'},
      {key:'start',label:'Heure début'},
      {key:'end',label:'Heure fin'},
      {key:'color',label:'Couleur'},
      {key:'open_m_wd',label:'Ouverte M L‑V'},
      {key:'open_m_sat',label:'Ouverte M Sam'},
      {key:'open_m_sun',label:'Ouverte M Dim/férié'},
      {key:'open_b_wd',label:'Ouverte B L‑V'},
      {key:'open_b_sat',label:'Ouverte B Sam'},
      {key:'open_b_sun',label:'Ouverte B Dim/férié'},
      {key:'q_wd',label:'Qualité L‑V'},
      {key:'q_sat',label:'Qualité Sam'},
      {key:'q_sun',label:'Qualité Dim/férié'}
    ];
    var overlay=document.createElement('div');
    overlay.className='popup-overlay';
    var inner='<div class="popup"><h3>Paramètres à appliquer</h3>';
    params.forEach(function(p){
      inner+='<label><input type="checkbox" data-key="'+p.key+'" checked> '+p.label+'</label>';
    });
    inner+='<div class="row"><button class="button" id="popupApply">Appliquer</button><button class="button ghost" id="popupCancel">Annuler</button></div></div>';
    overlay.innerHTML=inner;
    document.body.appendChild(overlay);
    overlay.addEventListener('click',function(ev){
      if(ev.target.id==='popupApply'){
        var selected={};
        overlay.querySelectorAll('input[data-key]').forEach(function(cb){ if(cb.checked) selected[cb.getAttribute('data-key')]=true; });
        applySelected(selected);
        document.body.removeChild(overlay);
      }else if(ev.target.id==='popupCancel' || ev.target===overlay){
        document.body.removeChild(overlay);
      }
    });
    function applySelected(selected){
      card.querySelectorAll('tbody tr[data-col]').forEach(function(tr){
        var chk=tr.querySelector('.colCheck');
        if(chk && chk.checked){
          var id=tr.getAttribute('data-col');
          var idx=parseInt(id.replace('col',''),10)-1;
          var col=st.columns[idx];
          Object.keys(selected).forEach(function(k){
            col[k]=modelVals[k];
            if(['type','start','end','color','q_wd','q_sat','q_sun'].indexOf(k)>=0){
              st.tours.forEach(function(t){ t.columns[idx][k]=modelVals[k]; });
            }
            var el=tr.querySelector('[data-field="'+k+'"]');
            if(el){
              if(k.indexOf('open_')===0){
                el.value=modelVals[k]?"true":"false";
              }else{
                el.value=modelVals[k];
              }
            }
          });
        }
      });
      save(st);
    }
  }

  card.addEventListener("input",function(e){
    var tr=e.target.closest("tr[data-col]");
    if(tr){ var id=tr.getAttribute("data-col"), f=e.target.getAttribute("data-field"); if(!f)return;
      var v=e.target.value; var idx=parseInt(id.replace("col",""),10)-1; var col=st.columns[idx];
      if(f.indexOf('open_')===0){ col[f] = (v==="true"); save(st); return; }
      col[f]=v;
      if(['type','start','end','color','q_wd','q_sat','q_sun'].indexOf(f)>=0){
        st.tours.forEach(function(t){ t.columns[idx][f]=v; });
      }
      save(st); return;
    }
  });
  card.addEventListener("change",function(e){
    if(e.target&&e.target.id==="activeTourSel"){
      var val=e.target.value;
      if(!confirm("Changer de tour effacera tous les choix non attribués. Continuer ?")){
        e.target.value=(st.activeTour===null?"":st.activeTour);
        return;
      }
      st.draftSelections={};
      st.progress={};
      for(var u in st.published){
        var map=st.published[u];
        Object.keys(map).forEach(function(k){ if(map[k].status!=="accepted") delete map[k]; });
        if(Object.keys(map).length===0) delete st.published[u];
      }
      if(val===""){ st.activeTour=null; st.recapNav.attrType='simple'; }
      else{ st.activeTour=parseInt(val,10); st.columns=st.tours[st.activeTour].columns; st.recapNav.attrType = st.tours[st.activeTour].choiceType || 'simple'; }
      save(st);
      return;
    }
    if(e.target&&e.target.id==="tradeToggle"){
      st.tradeEnabled=e.target.checked;
      save(st);
      return;
    }
    if(e.target&&e.target.id==="saisieToggle"){
      st.saisieEnabled=e.target.checked;
      save(st);
      return;
    }
  });
  card.addEventListener("click",function(e){
    var tab=e.target.closest&&e.target.closest('.tour-tab');
    if(tab){
      st.adminTourTab=parseInt(tab.getAttribute('data-tour'),10);
      save(st);
      renderAdmin();
      return;
    }
    if(e.target&&e.target.id==="saveConsigne"){ 
      st.tours[st.adminTourTab].consigne=card.querySelector('#tourConsigne').value; 
      var ctVal=card.querySelector('#choiceTypeSel').value;
      st.tours[st.adminTourTab].choiceType=ctVal; 
      if(st.adminTourTab===st.activeTour){ st.recapNav.attrType=ctVal; }
      save(st); alert('Consignes enregistrées.'); return; }
    if(e.target&&e.target.id==="saveTour"){ save(st); alert('Paramètres du tour enregistrés.'); return; }
    if(e.target&&e.target.id==="applyModel"){
      var modelVals={};
      card.querySelectorAll('[data-model]').forEach(function(inp){
        var f=inp.getAttribute('data-model');
        var v=inp.value;
        if(f.indexOf('open_')===0) modelVals[f]=(v==="true"); else modelVals[f]=v;
      });
      showApplyModelPopup(modelVals);
      return;
    }
    if(e.target&&e.target.id==="saveCalendar"){
      st.month=parseInt(card.querySelector("#monthSel").value,10);
      var m2El=card.querySelector("#month2Sel"); st.month2=(m2El&&m2El.value!==""?parseInt(m2El.value,10):null);
      st.year=parseInt(card.querySelector("#yearSel").value,10);
      st.holidays=(card.querySelector("#holidaysInp").value||"");
      save(st); alert("Calendrier enregistré.");
    }
    var pbtn=e.target.closest('button[data-part][data-name]');
    if(pbtn){
      var role=pbtn.getAttribute('data-part');
      var name=pbtn.getAttribute('data-name');
      var val=!st.access[role][name];
      st.access[role][name]=val;
      pbtn.classList.toggle('on',val);
      pbtn.classList.toggle('off',!val);
      save(st);
      return;
    }
    var bulk=e.target.closest('button[data-part][data-bulk]');
    if(bulk){
      var roleB=bulk.getAttribute('data-part');
      var on=bulk.getAttribute('data-bulk')==='on';
      (st.users[roleB]||[]).forEach(function(n){ st.access[roleB][n]=on; });
      card.querySelectorAll('button[data-part="'+roleB+'"][data-name]').forEach(function(b){
        b.classList.toggle('on',on);
        b.classList.toggle('off',!on);
      });
      save(st);
      return;
    }
    var btn=e.target.closest("button[data-op]"); if(btn){ var role=btn.getAttribute("data-role"),op=btn.getAttribute("data-op");
      if(op==="add"){ var inp=card.querySelector("input[data-role='"+role+"']"); var name=(inp.value||"").trim(); if(name){ if(st.users[role].indexOf(name)===-1){ st.users[role].push(name); st.access[role][name]=(role==='associes'); } inp.value=""; save(st); renderAdmin(); } }
      if(op==="del"){ var name=btn.getAttribute("data-name"); st.users[role]=st.users[role].filter(function(x){return x!==name}); delete st.access[role][name]; save(st); renderAdmin(); }
      if(op==="pwd"){ var name=btn.getAttribute("data-name"); var v=prompt("Nouveau mot de passe pour "+name, st.passwords[name]||""); if(v!==null){ st.passwords[name]=v; save(st); alert("OK"); } }
    }
    if(e.target&&e.target.id==="admLogin"){}
    if(e.target&&e.target.id==="resetPlanning"){
      if(confirm("Tout effacer ?")){
        showLoading();
        st.progress={};
        st.draftSelections={};
        st.published={};
        st.audit=[];
        st.loginLogs=[];
        st.sessions={};
        st.unavailabilities={};
        st.passwords={};
        st.meta=st.meta||{};
        st.meta.lastModifiedBy=CLIENT_ID;
        st.meta.lastModifiedAt=Date.now();
        var clearPromise=supabaseClearDerivedTables({keepUsers:true, keepAdmin:true});
        save(st);
        Promise.resolve(clearPromise)
          .catch(function(err){ console.error('Supabase reset clear failure',err); })
          .finally(function(){
            hideLoading();
            alert("Planning réinitialisé.");
            renderAdmin();
          });
      }
      return;
    }
  });
}
function typeOptions(val){var all=["","1N","2N","3N","4C","5S","6S","TC","TCN","C1COU","C2COU","C1BOU","C2BOU","PFG","C1ANT","C2ANT","N","C","S","VIS","C1","C2","C3"];var s="";for(var i=0;i<all.length;i++){var t=all[i];s+='<option value="'+t+'"'+(t===val?' selected':'')+'>'+t+'</option>';}return s;}
function qualOptions(v){var a=["bonne","mauvaise"],s="";for(var i=0;i<a.length;i++){s+='<option value="'+a[i]+'"'+(a[i]===v?' selected':'')+'>'+a[i]+'</option>';}return s;}
function listEditor(role,label,st){
  var html='<div class="card" style="min-width:320px"><h4>'+label+'</h4><div class="row">'
   +'<input data-role="'+role+'" placeholder="Nom">'
   +'<button class="button" data-role="'+role+'" data-op="add">Ajouter</button></div><div>';
  st.users[role].forEach(function(n){
    html+='<div class="row"><span class="badge">'+n+'</span>'
      +'<button class="button ghost" data-role="'+role+'" data-op="pwd" data-name="'+n+'">Mot de passe</button>'
      +'<button class="button ghost" data-role="'+role+'" data-op="del" data-name="'+n+'">Supprimer</button></div>';
  }); return html+'</div></div>';
}

function participantsEditor(st){
  function block(role,label){
    var controls='<div class="row"><button class="button ghost" data-part="'+role+'" data-bulk="on">Tout activer</button><button class="button ghost" data-part="'+role+'" data-bulk="off">Tout désactiver</button></div>';
    var btns='<div class="row">';
    st.users[role].forEach(function(n){
      var on=!!st.access[role][n];
      btns+='<button class="button participant '+(on?'on':'off')+'" data-part="'+role+'" data-name="'+n+'">'+trigram(n)+'</button>';
    });
    btns+='</div>';
    return '<div><h4>'+label+'</h4>'+controls+btns+'</div>';
  }
  return block('associes','Médecins')+block('remplacants','Remplaçants');
}

// Saisie
function ensureProgress(st,name){
  st.progress[name]=st.progress[name]||{m:false,b:false,r:false};
  if(typeof st.progress[name].b==="undefined") st.progress[name].b=false;
  if(typeof st.progress[name].r==="undefined") st.progress[name].r=false;
  return st.progress[name];
}
function nextPhaseFor(st,name){
  var pr=ensureProgress(st,name);
  var tour = (st.activeTour!=null && st.tours[st.activeTour]) ? st.tours[st.activeTour] : null;
  var type = tour && tour.choiceType ? tour.choiceType : "simple";
  if(!pr.m) return "m";
  if(type!=="simple"){
    if(!pr.b) return "b";
  }
  if(!pr.r) return "r";
  return null;
}

function resetUserChoices(st,name){
  delete st.draftSelections[name];
  var pub=st.published[name];
  if(pub){
    Object.keys(pub).forEach(function(k){
      if(pub[k].status==='pending') delete pub[k];
    });
    if(Object.keys(pub).length===0) delete st.published[name];
  }
  st.progress[name]={m:false,b:false,r:false};
}

  function renderSaisie(role){
    var st=load();var app=document.getElementById("app");app.innerHTML="";
    // Remove floating attribution indicators outside admin/recap
    var prog=document.getElementById('attribProgress');
    if(prog) prog.remove();
    var status=document.getElementById('attribStatus');
    if(status) status.remove();
    swapSource=null;
    var tourLabel = st.activeTour!=null ? 'Tour '+(st.activeTour+1) : 'Tour non défini';
    var tourTitle=document.createElement('h1');
    tourTitle.className='tour-title';
    tourTitle.textContent=tourLabel;
    app.appendChild(tourTitle);
    if(st.activeTour!=null && st.tours[st.activeTour].consigne){
      var cBox=document.createElement('div');
      cBox.className='consigne-box';
      cBox.textContent=st.tours[st.activeTour].consigne;
      app.appendChild(cBox);
    }
    var card=document.createElement("div");card.className="card";card.classList.add("saisie");
    if(!st.saisieEnabled || st.activeTour===null){
      card.innerHTML='<h2>Saisie '+(role==="associes"?'associés':'remplaçants')+'</h2><div class="row"><span class="closed-icon">🚫</span><span>Les tours sont actuellement fermés.</span></div>';
      app.appendChild(card);
      return;
    }
    var sess=st.sessions[role]||{}; var logged=!!sess.name;
  if(!logged){
    var opts=st.users[role].map(function(n){return '<option value="'+n+'">'+n+'</option>';}).join("");
    card.innerHTML='<h2>Saisie '+(role==="associes"?'associés':'remplaçants')+'</h2>'
      +'<div class="row"><div class="input"><label>Utilisateur</label><select id="userSel">'+opts+'</select></div>'
      +'<div class="input"><label>Mot de passe</label><input id="pwdInp" type="password" placeholder="••••"></div>'
      +'<button class="button" id="loginBtn">Se connecter</button></div>';
    app.appendChild(card);
    card.addEventListener("click",function(e){
      if(e.target&&e.target.id==="loginBtn"){
        var n=card.querySelector("#userSel").value, p=card.querySelector("#pwdInp").value;
        if(!n) return alert("Sélectionnez un utilisateur.");
        if(!st.saisieEnabled) return alert("Le tour est fermé.");
        if(!st.access[role][n]) return alert("Ce médecin n\u0027est pas autorisé à participer au tour.");
        if((st.passwords[n]||"")!==p) return alert("Mot de passe invalide.");
        st.sessions[role]={name:n,activeLevel:1};
        st.loginLogs.push({ts:Date.now(), role:(role==='associes'?'medecin':'remplacant'), name:n, type:'login'});
        save(st); renderSaisie(role);
      }
    });
    return;
  }
  var name=sess.name;
  // Reindex choices on each login
  reindexLevels(st,name,'m');
  if(st.tours[st.activeTour].choiceType !== 'simple'){
    reindexLevels(st,name,'b');
  }
  save(st);
  if(!st.unavailabilities[name]){ renderIndispo(role,st,name); return; }
  var phaseTag=nextPhaseFor(st,name); // "m" | "b" | "r" | null
  if(sess.activePhase!==phaseTag){ sess.activePhase=phaseTag; sess.activeLevel=1; st.sessions[role]=sess; save(st); }
  if(phaseTag==="r"){ renderRecapStep(st,role,name); return; }
  var totalSteps = st.tours[st.activeTour].choiceType === 'simple' ? 2 : 3;
  var phaseLabel = phaseTag==="m" ? "Étape 1/"+totalSteps+" — Choix des gardes"
    : "Étape 2/"+totalSteps+" — Choix des bonus";
  if(phaseTag===null){
    card.classList.add("planning");
      card.innerHTML='<div class="row"><span class="badge">Connecté : '+name+'</span><button class="button ghost" id="logoutBtn">Se déconnecter</button><button class="button ghost" id="editIndispo">Modifier mes disponibilités</button><button class="button ghost" id="resetChoices">Réinitialiser mes choix</button></div>'
      +'<p>Toutes les étapes sont terminées pour '+name+'.</p>'
        +'<div class="row"><button class="button" id="resumeSaisie">Ajouter des gardes</button></div>'
        +'<div class="row"><div class="counter total" id="cntVisAttrib">Visites attribuées : 0</div><div class="counter total" id="cntConsAttrib">Consultations attribuées : 0</div><div class="counter total" id="cntTCAttrib">Téléconsultations attribuées : 0</div></div>'
          + buildCalendar(st,name,"b");
      app.appendChild(card);
      updateCounters(st,name,card,null);
      card.addEventListener("click",function(e){ if(e.target&&e.target.id==="logoutBtn"){ st.loginLogs.push({ts:Date.now(), role:(role==='associes'?'medecin':'remplacant'), name:name, type:'logout'}); delete st.sessions[role]; save(st); route(); } if(e.target&&e.target.id==="resumeSaisie"){ st.progress[name]={m:false,b:false,r:false}; save(st); renderSaisie(role); } if(e.target&&e.target.id==="editIndispo"){ renderIndispo(role,st,name); } if(e.target&&e.target.id==="resetChoices"){ resetUserChoices(st,name); save(st); renderSaisie(role); } });
      return;
  }
    var phaseClass = phaseTag==="m"?"bad":"bonus";
      card.classList.add("planning"); card.classList.add('phase-'+phaseTag);
        card.innerHTML='<div class="row" style="margin:0"><button class="button" id="nextPhase">Étape suivante</button></div>'
        +'<div class="row"><span class="badge">Connecté : '+name+'</span><span class="phase-pill '+phaseClass+'">'+phaseLabel+'</span><button class="button ghost" id="logoutBtn">Se déconnecter</button><button class="button ghost" id="editIndispo">Modifier mes disponibilités</button><button class="button ghost" id="resetChoices">Réinitialiser mes choix</button></div>'
        +(st.tradeEnabled?'<div class="row" style="margin-top:6px"><button class="button ghost" id="viewTrades">Propositions en attente<span id="tradeCount" class="notif"></span></button><button class="button ghost" id="viewMyTrades">Mes propositions</button><button class="button ghost" id="cancelSwapMode" style="display:none">Retour</button></div>':'')
        +'<div class="row"><div class="counter total" id="cntVisAttrib">Visites attribuées : 0</div><div class="counter total" id="cntConsAttrib">Consultations attribuées : 0</div><div class="counter total" id="cntTCAttrib">Téléconsultations attribuées : 0</div></div>'
        +'<div class="row" style="margin-top:12px"><button class="button ghost" id="refreshOrder">Actualiser l\'ordre de mes choix</button></div>'
      +'<div class="levelbar" id="levelBar">'+(function(){var h="";for(var i=1;i<=20;i++)h+='<button class="levelbtn'+(i===(+sess.activeLevel||1)?' active':'')+'" data-level="'+i+'">'+i+'</button>';return h;})()+'</div>'
    + buildCalendar(st,name,phaseTag);
    app.appendChild(card);

  card.addEventListener("click",function(e){
    if(e.target&&e.target.id==="logoutBtn"){ st.loginLogs.push({ts:Date.now(), role:(role==='associes'?'medecin':'remplacant'), name:name, type:'logout'}); delete st.sessions[role]; save(st); route(); return; }
    if(e.target&&e.target.id==="editIndispo"){ renderIndispo(role,st,name); return; }
    if(e.target&&e.target.id==="resetChoices"){ resetUserChoices(st,name); save(st); renderSaisie(role); return; }
    var b=e.target.closest(".levelbtn"); if(b){ sess.activeLevel=parseInt(b.getAttribute("data-level"),10)||1; st.sessions[role]=sess; save(st);
      var btns=card.querySelectorAll(".levelbtn"); for(var i=0;i<btns.length;i++) btns[i].classList.remove("active"); b.classList.add("active"); return; }
    var cell=e.target.closest("td.cell");
      if(cell){
        if(st.tradeEnabled && swapSource){
          if(swapSource.mode==='free'){
            if(cell.classList.contains('swap-source')){
              if(swapSource.cell) swapSource.cell.classList.remove('swap-source');
              swapSource=null;
              exitSwapMode();
              return;
            }
            if(!cell.classList.contains('swap-disabled')){ openFreeSwapPopup(st,name,cell,role); return; }
            return;
          } else if(cell.classList.contains("taken")){ openSwapPopup(st,name,cell); return; }
        }
        if(st.tradeEnabled && cell.classList.contains("accepted")){ openSwapChoicePopup(st,name,cell,role); return; }
        if(!st.tradeEnabled && cell.classList.contains("accepted")) return;
        onToggleCell(st,name,cell,role,phaseTag); updateCounters(st,name,card,phaseTag); return;
      }
      if(st.tradeEnabled && e.target&&e.target.id==="viewTrades"){ 
        if(swapSource && swapSource.cell) swapSource.cell.classList.remove('swap-source');
        swapSource=null;
        exitSwapMode();
        showTradeList(st,role,name); 
        return; 
      }
      if(st.tradeEnabled && e.target&&e.target.id==="viewMyTrades"){ 
        if(swapSource && swapSource.cell) swapSource.cell.classList.remove('swap-source');
        swapSource=null;
        exitSwapMode();
        showMyTradeList(st,role,name); 
        return; 
      }
      if(st.tradeEnabled && e.target&&e.target.id==="cancelSwapMode"){ 
        if(swapSource && swapSource.cell) swapSource.cell.classList.remove('swap-source');
        swapSource=null;
        exitSwapMode();
        return;
      }
    if(e.target&&e.target.id==="nextPhase"){ var pr=ensureProgress(st,name); if(phaseTag==="m") pr.m=true; else if(phaseTag==="b") pr.b=true; save(st); renderSaisie(role); return; }
    if(e.target&&e.target.id==="refreshOrder"){ reindexLevels(st,name,phaseTag); renderSaisie(role); return; }
  });
  updateCounters(st,name,card,phaseTag);
  if(st.tradeEnabled) updateTradeCount(st,name,card);
}

function updateCounters(st,name,root,phaseTag){
    var el;
    if((el=root.querySelector("#cntVis"))) el.textContent="Visites : "+countCat(st,name,"visite",phaseTag);
    if((el=root.querySelector("#cntCons"))) el.textContent="Consultations : "+countCat(st,name,"consultation",phaseTag);
    if((el=root.querySelector("#cntTC"))) el.textContent="Téléconsultations : "+countCat(st,name,"tc",phaseTag);
  if((el=root.querySelector("#cntVisAttrib"))) el.textContent="Visites attribuées : "+countAssignedCat(st,name,"visite");
  if((el=root.querySelector("#cntConsAttrib"))) el.textContent="Consultations attribuées : "+countAssignedCat(st,name,"consultation");
  if((el=root.querySelector("#cntTCAttrib"))) el.textContent="Téléconsultations attribuées : "+countAssignedCat(st,name,"tc");
}

function countAssignedCat(st,name,cat){
  var c=0;
  var p=st.published[name]||{};
  Object.values(p).forEach(function(it){ if(it.cat===cat && it.status==="accepted") c++; });
  return c;
}

function renderRecapStep(st,role,name){
  var app=document.getElementById("app");app.innerHTML="";
  var tourLabel = st.activeTour!=null ? 'Tour '+(st.activeTour+1) : 'Tour non défini';
  var tourTitle=document.createElement('h1');
  tourTitle.className='tour-title';
  tourTitle.textContent=tourLabel;
  app.appendChild(tourTitle);
  if(st.activeTour!=null && st.tours[st.activeTour].consigne){
    var cBox=document.createElement('div');
    cBox.className='consigne-box';
    cBox.textContent=st.tours[st.activeTour].consigne;
    app.appendChild(cBox);
  }
  var pub=st.published[name]||{};
  var drafts=st.draftSelections[name]||{};
  Object.keys(pub).forEach(function(k){
    var it=pub[k];
    if(it.status==='pending'){
      it.status='draft';
      drafts[k]=it;
      delete pub[k];
    }
  });
  st.published[name]=pub;
  st.draftSelections[name]=drafts;
  reindexLevels(st,name,'m');
  if(st.tours[st.activeTour].choiceType!=='simple'){
    reindexLevels(st,name,'b');
  }
  save(st);
  var card=document.createElement("div");card.className="card";card.classList.add("recap-step");
    card.innerHTML='<div class="row"><span class="badge">Connecté : '+name+'</span><button class="button ghost" id="logoutBtn">Se déconnecter</button><button class="button ghost" id="editIndispo">Modifier mes disponibilités</button><button class="button ghost" id="resetChoices">Réinitialiser mes choix</button></div>'
      +'<div class="row"><div class="counter total" id="cntVisAttrib">Visites attribuées : 0</div><div class="counter total" id="cntConsAttrib">Consultations attribuées : 0</div><div class="counter total" id="cntTCAttrib">Téléconsultations attribuées : 0</div></div>'
      +'<div class="row" style="margin-top:12px"><button class="button ghost" id="refreshOrder">Actualiser l\'ordre de mes choix</button></div>'
      + (function(){
            var blocs='<div class="bloc">'+buildChoiceList(st,name,'m')+'</div>';
            if(st.tours[st.activeTour].choiceType!=='simple'){
              blocs+='<div class="bloc">'+buildChoiceList(st,name,'x')+'</div>';
              blocs+='<div class="bloc">'+buildChoiceList(st,name,'y')+'</div>';
            }
            return '<div class="row recap-choix">'+blocs+'</div>';
          })()
      +'<div class="row" style="margin-top:12px"><button class="button" id="submitDraft">Transmettre mes choix</button></div>';
    app.appendChild(card);
    updateCounters(st,name,card,null);
    card.addEventListener("click",function(e){
    if(e.target&&e.target.id==="logoutBtn"){ st.loginLogs.push({ts:Date.now(), role:(role==='associes'?'medecin':'remplacant'), name:name, type:'logout'}); delete st.sessions[role]; save(st); route(); return; }
      if(e.target&&e.target.id==="editIndispo"){ renderIndispo(role,st,name); return; }
      if(e.target&&e.target.id==="resetChoices"){ resetUserChoices(st,name); save(st); renderSaisie(role); return; }
      if(e.target&&e.target.id==="submitDraft"){ publishDraft(st,name,'m'); if(st.tours[st.activeTour].choiceType!=='simple'){ publishDraft(st,name,'b'); } var pr=ensureProgress(st,name); pr.r=true; st.loginLogs.push({ts:Date.now(), role:(role==='associes'?'medecin':'remplacant'), name:name, type:'logout'}); save(st); delete st.sessions[role]; save(st); alert("Choix transmis. Vous êtes déconnecté."); route(); }
      if(e.target&&e.target.id==="refreshOrder"){ reindexLevels(st,name,'m'); if(st.tours[st.activeTour].choiceType!=='simple'){ reindexLevels(st,name,'b'); } renderRecapStep(st,role,name); return; }
    var del=e.target.closest('.del-choice');
    if(del){
      var li=del.closest('li');
      var key=li&&li.getAttribute('data-key');
      if(key){ delete st.draftSelections[name][key]; li.remove(); recomputeList(li.parentNode,st,name); }
    }
  });
  card.querySelectorAll('.prio-list').forEach(function(list){ enableDrag(list,st,name); });
}

function buildChoiceList(st,name,ph){
  var u=st.draftSelections[name]||{}; var items=[];
  Object.keys(u).forEach(function(k){
    var it=u[k];
    var phOk = ph==='b' ? (it.phase==='x' || it.phase==='y') : it.phase===ph;
    if(phOk && it.status==='draft' && isKeyOpen(st,k,it.phase)){
      var p=k.split('::')[0].split('-'); var Y=+p[0], m=+p[1]-1, d=+p[2]; var colId=k.split('::')[1];
      var col=st.columns[parseInt(colId.replace('col',''),10)-1]||{};
      items.push({key:k,level:it.level,alt:it.alt,phase:it.phase,date:d+'/'+pad(m+1)+'/'+Y,col:(col.type||colId)+' '+(col.start||'')+'-'+(col.end||'')});
    }
  });
  items.sort(function(a,b){ if(a.level!==b.level) return a.level-b.level; return a.alt-b.alt; });
  var cls, title;
  if(ph==='m'){ cls='bad'; title='Gardes'; }
  else if(ph==='b'){ cls='bonus-list'; title='Bonus'; }
  else if(ph==='x'){ cls='bonus-bad'; title='Mauvais bonus'; }
  else { cls='bonus-good'; title='Bons bonus'; }
  var html='<h3>'+title+'</h3><ul class="prio-list '+cls+'" data-phase="'+ph+'">';
  items.forEach(function(it){
    var label=it.alt>1? (it.level+'.'+(it.alt-1)) : ''+it.level;
    var itemCls = (it.phase==='y')?'bonus-good':'bonus-bad';
    html+='<li draggable="true" data-key="'+it.key+'" class="'+(it.alt>1?'alt':'main')+' '+itemCls+'">'
      +'<span class="prio">'+label+'</span>'+it.date+' — '+it.col+'<span class="del-choice" title="Supprimer">🗑️</span>'
      +'</li>';
  });
  return html+'</ul>';
}

function enableDrag(list,st,name){
  var dragged=null;
  list.addEventListener('dragstart',function(e){
    if(e.target.closest('.del-choice')) return;
    var li=e.target.closest('li'); if(!li) return; dragged=li; li.classList.add('dragging'); e.dataTransfer.effectAllowed='move';
  });
  list.addEventListener('dragover',function(e){
    e.preventDefault();
    var listRect=list.getBoundingClientRect();
    var isMain=(e.clientX-listRect.left)<40;
    if(dragged){
      dragged.classList.toggle('alt',!isMain);
      dragged.classList.toggle('main',isMain);
    }
    var li=e.target.closest('li'); if(!li||li===dragged) return;
    var rect=li.getBoundingClientRect();
    var next=(e.clientY-rect.top)/(rect.bottom-rect.top)>0.5;
    list.insertBefore(dragged,next?li.nextSibling:li);
  });
  list.addEventListener('drop',function(e){ e.preventDefault(); });
  list.addEventListener('dragend',function(){ if(dragged){ dragged.classList.remove('dragging'); dragged=null; recomputeList(list,st,name); } });
}

function recomputeList(list,st,name){
  var ph=list.getAttribute('data-phase');
  var p=st.published[name]||{}; var pending={}, maxLevel=0;
  Object.keys(p).forEach(function(k){
    var it=p[k];
    var phOk = ph==='b' ? (it.phase==='x' || it.phase==='y') : it.phase===ph;
    if(phOk && it.status==="pending" && isKeyOpen(st,k,it.phase)){
      if(it.level>maxLevel) maxLevel=it.level;
      var key=it.level+"|"+it.cat; pending[key]=(pending[key]||0)+1;
    }
  });
  var rows=list.querySelectorAll('li'); var level=maxLevel, curLevel=null;
  rows.forEach(function(li){
    var key=li.getAttribute('data-key'); var it=st.draftSelections[name][key]; if(!it){ it=p[key]; }
    if(!it) return;
    var phase=it.phase;
    var phOk = ph==='b' ? (phase==='x' || phase==='y') : phase===ph;
    if(!phOk || !isKeyOpen(st,key,phase)) return; var cat=it.cat;
    if(curLevel===null || li.classList.contains('main')){
      level++; curLevel=level; li.classList.add('main'); li.classList.remove('alt');
      var off=pending[curLevel+'|'+cat]||0; it.level=curLevel; it.alt=off+1; pending[curLevel+'|'+cat]=off+1;
    } else {
      li.classList.add('alt'); li.classList.remove('main');
      var off2=pending[curLevel+'|'+cat]||0; off2++; it.level=curLevel; it.alt=off2; pending[curLevel+'|'+cat]=off2;
    }
    li.querySelector('.prio').textContent = it.alt>1? (it.level+'.'+(it.alt-1)) : ''+it.level;
  });
  save(st);
}

function qualityOf(st,c,day,hol){
  var isHoliday=!!hol[day.y+"-"+pad(day.m+1)+"-"+pad(day.d)] || (day.w===7); // Dimanche = férié
  var q = isHoliday ? c.q_sun : (day.w===6 ? c.q_sat : c.q_wd);
  return q==="bonne" ? "good" : "bad";
}
function isOpen(c,day,hol,phaseTag){
  var isHoliday=!!hol[day.y+"-"+pad(day.m+1)+"-"+pad(day.d)] || (day.w===7);
  var q=isHoliday ? c.q_sun : (day.w===6 ? c.q_sat : c.q_wd);
  var isGood=q==="bonne";
  if(phaseTag==="m"){
    return isHoliday ? c.open_m_sun : (day.w===6 ? c.open_m_sat : c.open_m_wd);
  } else if(phaseTag==="x"){
    if(isGood) return false;
    return isHoliday ? c.open_b_sun : (day.w===6 ? c.open_b_sat : c.open_b_wd);
  } else if(phaseTag==="y"){
    if(!isGood) return false;
    return isHoliday ? c.open_b_sun : (day.w===6 ? c.open_b_sat : c.open_b_wd);
  } else {
    return isHoliday ? c.open_b_sun : (day.w===6 ? c.open_b_sat : c.open_b_wd);
  }
}
function isKeyOpen(st,key,ph){
  if(!key) return false;
  var parts=key.split("::"); if(parts.length<2) return false;
  var dateParts=parts[0].split("-");
  var y=+dateParts[0], m=+dateParts[1]-1, d=+dateParts[2];
  var colId=parts[1];
  var col=st.columns[parseInt(colId.replace("col",""),10)-1];
  if(!col) return false;
  var hol=holidaySet(st.holidays);
  var day={y:y,m:m,d:d,w:(new Date(y,m,d).getDay()||7)};
  return isOpen(col,day,hol,ph);
}
function takenBy(st, key){
  for(var u in st.published){
    var m=st.published[u]; if(!m)continue; var it=m[key]; if(it && it.status==="accepted") return u;
  }
  return null;
}
function findDraft(st,user,key,ph){
  var u=st.draftSelections[user]||{}; var it=u[key];
  if(ph==='b'){
    if(it && (it.phase==='x' || it.phase==='y') && it.status==="draft" && isKeyOpen(st,key,it.phase)) return it;
  }else{
    if(it && it.phase===ph && it.status==="draft" && isKeyOpen(st,key,ph)) return it;
  }
  return null;
}
function findPending(st,user,key,ph){
  var u=st.published[user]||{}; var it=u[key];
  if(ph==='b'){
    if(it && (it.phase==='x' || it.phase==='y') && it.status==="pending" && isKeyOpen(st,key,it.phase)) return it;
  }else{
    if(it && it.phase===ph && it.status==="pending" && isKeyOpen(st,key,ph)) return it;
  }
  return null;
}
function pendingCountAll(st,key,ph){
  var c=0;
  for(var u in st.published){
    var it=st.published[u][key];
    if(!it || it.status!=="pending") continue;
    if(ph==='b'){
      if((it.phase==='x' || it.phase==='y') && isKeyOpen(st,key,it.phase)) c++;
    } else {
      if(it.phase===ph && isKeyOpen(st,key,ph)) c++;
    }
  }
  return c;
}
function pendingTrigrams(st,key,ph){
  var a=[];
  for(var u in st.published){
    var it=st.published[u][key];
    if(!it || it.status!=="pending") continue;
    if(ph==='b'){
      if((it.phase==='x' || it.phase==='y') && isKeyOpen(st,key,it.phase)) a.push(trigram(u));
    } else {
      if(it.phase===ph && isKeyOpen(st,key,ph)) a.push(trigram(u));
    }
  }
  return a;
}

function buildCalendar(st,name,phaseTag){
  var m1=st.month,y=st.year, m2=st.month2; var hol=holidaySet(st.holidays);
  function tableFor(mo){ var days=daysInMonth(y,mo);
    var head='<table class="grid"><thead><tr><th class="day-head month-head"><div>'+MONTHS_SHORT[mo]+'</div><div class="small">'+y+'</div></th>';
    st.columns.forEach(function(c,i){
      var headTitle=((c.type||('Col '+(i+1)))+' '+(c.start||'')+' – '+(c.end||'')).replace(/"/g,'&quot;');
      var label = c.type || ('Col '+(i+1));
      if(/^C[123][A-Z]{3}$/.test(label)){
        label = label.slice(0,2)+'<br>'+label.slice(2);
      }
      head+='<th title="'+headTitle+'"><div class="col-head"><div>'+label+'</div><div class="small">'+(c.start||'')+' – '+(c.end||'')+'</div></div></th>';
    }); head+='</tr></thead><tbody>';
    var rows=''; days.forEach(function(d){
      var dateLabel=DAYS[d.w-1]+' '+d.d; rows+='<tr><th class="day-head">'+dateLabel+'</th>';
      st.columns.forEach(function(c){
        var q=qualityOf(st,c,d,hol);
        var cls='cell '+q;
        var open = isOpen(c,d,hol,phaseTag);
        var dateKey=d.y+'-'+pad(d.m+1)+'-'+pad(d.d);
        if(!open || (name!=='__all__' && st.unavailabilities && st.unavailabilities[name] && st.unavailabilities[name][dateKey])) cls+=' disabled';
        var k=keyOf(d.y,d.m,d.d,c.id);
        var taken = takenBy(st,k);
        if(taken && taken!==name) cls+=' taken'+(name==='__all__'?'':' disabled');
        var ownAccepted = (taken===name);
        if(ownAccepted){
          cls+=' accepted';
          var tradePend=(st.tradeRequests||[]).some(function(r){return r.status==='pending' && (r.source===k||r.target===k);});
          if(tradePend) cls+=' trade-pending';
        }
        var sel;
        if(phaseTag==='b'){
          sel = findDraft(st,name,k,'x') || findDraft(st,name,k,'y') || findPending(st,name,k,'x') || findPending(st,name,k,'y');
        } else {
          sel = findDraft(st,name,k,phaseTag) || findPending(st,name,k,phaseTag);
        }
        if(sel) cls+=' selected';
        var colTitle=(c.type||('Col '+c.id.replace('col','')));
        var range=(c.start||'')+' – '+(c.end||'');
        var cellTitle=(colTitle+' '+range).replace(/"/g,'&quot;');
        var cellHTML='<td class="'+cls+'" data-y="'+d.y+'" data-m="'+d.m+'" data-d="'+d.d+'" data-col="'+c.id+'" title="'+cellTitle+'">';
        cellHTML+='<div class="col-tint" style="background:'+(c.color||'#1e293b')+'"></div>';
        if(ownAccepted){ cellHTML+='<div class="tri">'+trigram(name)+'</div>'; }
        else if(taken && taken!==name){ cellHTML+='<div class="tri">'+trigram(taken)+'</div>'; }
        else{
          if(sel){ var label = sel.level? (sel.alt>1? (sel.level+"."+(sel.alt-1)) : (""+sel.level)) : ""; cellHTML+='<span class="prio">'+label+'</span>'; }
        }
        if(phaseTag==='b'){
          if(name==='__all__'){
            var pc=pendingCountAll(st,k,'x')+pendingCountAll(st,k,'y');
            if(pc>0){
              var pl=pendingTrigrams(st,k,'x').concat(pendingTrigrams(st,k,'y')).join(", ");
              cellHTML+='<div class="qual-flag" data-tip="'+pl+'">'+pc+'</div>';
            } else {
              cellHTML+='<div class="qual-flag"></div>';
            }
          } else {
            cellHTML+='<div class="qual-flag"></div>';
          }
        } else {
          var pcount=pendingCountAll(st,k,phaseTag);
          if(pcount>0){
            var plist=pendingTrigrams(st,k,phaseTag).join(", ");
            cellHTML+='<div class="qual-flag" data-tip="'+plist+'">'+pcount+'</div>';
          } else {
            cellHTML+='<div class="qual-flag"></div>';
          }
        }
        cellHTML+='</td>';
        rows+=cellHTML;
      });
      rows+='</tr>';
    });
    rows+='</tbody></table>';
    return head+rows;
  }
  var html = tableFor(m1);
  if(m2!==null && m2!=="" && !isNaN(m2)) html += '<div style="height:14px"></div>'+tableFor(m2);
  return html;
}

function exportPlanningCSV(st){
  var cols=st.columns;
  var header=['Date'];
  cols.forEach(function(c,i){
    header.push('"'+(c.type||('Col '+(i+1)))+'"');
  });
  var rows=[header.join(';')];
  function pushMonth(mo){
    var days=daysInMonth(st.year,mo);
    days.forEach(function(d){
      var dateStr=pad(d.d)+'/'+pad(mo+1)+'/'+st.year;
      var row=[dateStr];
      cols.forEach(function(c){
        var k=keyOf(d.y,d.m,d.d,c.id);
        var taken=takenBy(st,k);
        row.push(taken?trigram(taken):'');
      });
      rows.push(row.join(';'));
    });
  }
  pushMonth(st.month);
  if(st.month2!==null && st.month2!=="" && !isNaN(st.month2)) pushMonth(st.month2);
  var csv=rows.join('\n');
  var blob=new Blob([csv],{type:'text/csv'});
  var link=document.createElement('a');
  link.href=URL.createObjectURL(blob);
  link.download='planning.csv';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

function onToggleCell(st,name,cell,role,phaseTag){
  if(cell.classList.contains("disabled")) return;
  var y=parseInt(cell.getAttribute("data-y"),10), m=parseInt(cell.getAttribute("data-m"),10), d=parseInt(cell.getAttribute("data-d"),10);
  var colId=cell.getAttribute("data-col");
  var col=st.columns[parseInt(colId.replace("col",""),10)-1];
  var k=keyOf(y,m,d,colId);
  var taken=takenBy(st,k);
  if(taken && taken!==name) return; // occupée par un autre
  if(taken===name) return; // déjà acceptée pour soi

  st.draftSelections[name]=st.draftSelections[name]||{};
  st.published[name]=st.published[name]||{};
  var exists, pend;
  if(phaseTag==='b'){
    exists = findDraft(st,name,k,'x') || findDraft(st,name,k,'y');
    pend   = findPending(st,name,k,'x') || findPending(st,name,k,'y');
  } else {
    exists = findDraft(st,name,k,phaseTag);
    pend   = findPending(st,name,k,phaseTag);
  }
  var hol=holidaySet(st.holidays);
  var day={y:y,m:m,d:d,w:(new Date(y,m,d).getDay()||7)};
  var qual=qualityOf(st,col,day,hol);
  var phase=phaseTag==='b'?(qual==='good'?'y':'x'):phaseTag;
  if(exists){
    delete st.draftSelections[name][k];
    // réindexer les alternatives (draft uniquement) à ce niveau/phase
    reindexDraftAlts(st,name,exists.level,exists.phase);
    renderSaisie(role);
    return;
  } else if(pend){
    delete st.published[name][k];
    // réindexer les alternatives publiées pour maintenir l'ordre
    reindexPendingAlts(st,name,pend.level,pend.phase);
    renderSaisie(role);
    return;
  } else {
    var level=(st.sessions[role]&&st.sessions[role].activeLevel)||1;
    var cat=catOf(col.type);
    var alt=nextDraftAlt(st,name,level,phase);
    st.draftSelections[name][k]={status:"draft", cat:cat, level:level, alt:alt, phase:phase, ts:Date.now()};
    save(st);
  }
  // rafraîchir affichage local de la case
  var sel;
  if(phaseTag==='b'){
    sel = findDraft(st,name,k,'x') || findDraft(st,name,k,'y')
      || findPending(st,name,k,'x') || findPending(st,name,k,'y');
  } else {
    sel = findDraft(st,name,k,phaseTag) || findPending(st,name,k,phaseTag);
  }
  var pr = cell.querySelector(".prio"); if(pr) pr.remove();
  if(sel){
    cell.classList.add("selected");
    var label= sel.level? (sel.alt>1? (sel.level+"."+(sel.alt-1)) : (""+sel.level)) : "";
    var sp=document.createElement("span"); sp.className="prio"; sp.textContent=label; cell.appendChild(sp);
  }
}

function nextDraftAlt(st,name,level,ph){
  var cnt=0;
  var u=st.draftSelections[name]||{};
  Object.keys(u).forEach(function(k){ var it=u[k]; if(it.phase===ph && it.level===level && it.status==="draft" && isKeyOpen(st,k,ph)) cnt++; });
  // tenir compte des gardes déjà envoyées mais encore en attente
  var p=st.published[name]||{};
  Object.keys(p).forEach(function(k){ var it=p[k]; if(it.phase===ph && it.level===level && it.status==="pending" && isKeyOpen(st,k,ph)) cnt++; });
  return cnt+1;
}
function reindexDraftAlts(st,name,level,ph){
  // reindex uniquement sur les DRAFT pour laisser l'ordre des déjà envoyés intact côté récap
  var items=[]; var u=st.draftSelections[name]||{};
  Object.keys(u).forEach(function(k){
    var it=u[k]; if(it.phase===ph && it.level===level && it.status==="draft" && isKeyOpen(st,k,ph)) items.push({k:k, ts:it.ts});
  });
  items.sort(function(a,b){return a.ts-b.ts;});
  var p=st.published[name]||{}; var off=0;
  Object.keys(p).forEach(function(k){ var it=p[k]; if(it.phase===ph && it.level===level && it.status==="pending" && isKeyOpen(st,k,ph)) off++; });
  for(var i=0;i<items.length;i++){ st.draftSelections[name][items[i].k].alt=off+i+1; }
  save(st);
}

function reindexPendingAlts(st,name,level,ph){
  var items=[]; var u=st.published[name]||{};
  Object.keys(u).forEach(function(k){
    var it=u[k]; if(it.phase===ph && it.level===level && it.status==="pending" && isKeyOpen(st,k,ph)) items.push({k:k, ts:it.ts});
  });
  items.sort(function(a,b){return a.ts-b.ts;});
  for(var i=0;i<items.length;i++){ st.published[name][items[i].k].alt=i+1; }
  save(st);
}

function openSwapChoicePopup(st,name,cell,role){
  if(!st.tradeEnabled) return;
  var overlay=document.createElement('div');
  overlay.className='popup-overlay';
  overlay.innerHTML='<div class="popup" style="position:relative"><button class="button ghost" id="closeSwapChoice" style="position:absolute;top:8px;right:8px">✕</button><h3>Échanger cette garde</h3><div class="row"><button class="button" id="swapWithColleague">Échanger avec un confrère</button></div><div class="row"><button class="button" id="swapWithFree">Échanger contre une garde disponible</button></div></div>';
  document.body.appendChild(overlay);
  overlay.addEventListener('click',function(e){
    e.stopPropagation();
    if(e.target.id==='closeSwapChoice' || e.target===overlay){ document.body.removeChild(overlay); return; }
    if(e.target.id==='swapWithColleague'){ document.body.removeChild(overlay); setTimeout(function(){ onSwapSelect(st,name,cell); },0); return; }
    if(e.target.id==='swapWithFree'){ document.body.removeChild(overlay); setTimeout(function(){ startAvailableSwap(st,name,cell,role); },0); return; }
  });
}

function startAvailableSwap(st,name,cell,role){
  var k=cellKey(cell);
  var y=parseInt(cell.getAttribute('data-y'),10), m=parseInt(cell.getAttribute('data-m'),10), d=parseInt(cell.getAttribute('data-d'),10);
  var colId=cell.getAttribute('data-col');
  var col=st.columns[parseInt(colId.replace('col',''),10)-1]||{};
  var day={y:y,m:m,d:d,w:(new Date(y,m,d).getDay()||7)};
  var hol=holidaySet(st.holidays);
  var q=qualityOf(st,col,day,hol);
  var isHoliday=!!hol[y+'-'+pad(m+1)+'-'+pad(d)] || day.w===7;
  var period=isHoliday? 'sun' : (day.w===6 ? 'sat' : 'wd');
  if(swapSource && swapSource.cell) swapSource.cell.classList.remove('swap-source');
  swapSource={key:k,cell:cell,mode:'free',criteria:{type:col.type,quality:q,period:period},role:role,name:name};
  cell.classList.add('swap-source');
  enterFreeSwapMode(st,swapSource.criteria);
}

function enterFreeSwapMode(st,crit){
  var card=document.querySelector('.card.planning');
  if(!card) return;
  card.classList.add('swap-mode');
  card.classList.remove('swap-colleague');
  var cells=card.querySelectorAll('td.cell');
  var hol=holidaySet(st.holidays);
  cells.forEach(function(c){
    if(c.classList.contains('swap-source')) return;
    if(c.classList.contains('taken') || c.classList.contains('accepted') || c.classList.contains('disabled')){ c.classList.add('swap-disabled'); return; }
    var colId=c.getAttribute('data-col'); var col=st.columns[parseInt(colId.replace('col',''),10)-1]||{};
    if(col.type!==crit.type){ c.classList.add('swap-disabled'); return; }
    var y=parseInt(c.getAttribute('data-y'),10), m=parseInt(c.getAttribute('data-m'),10), d=parseInt(c.getAttribute('data-d'),10);
    var day={y:y,m:m,d:d,w:(new Date(y,m,d).getDay()||7)};
    var q=qualityOf(st,col,day,hol);
    if(q!==crit.quality){ c.classList.add('swap-disabled'); return; }
    var isHoliday=!!hol[y+'-'+pad(m+1)+'-'+pad(d)] || day.w===7;
    var period=isHoliday? 'sun' : (day.w===6 ? 'sat' : 'wd');
    if(period!==crit.period){ c.classList.add('swap-disabled'); return; }
  });
  var btn=document.getElementById('cancelSwapMode');
  if(btn) btn.style.display='inline-block';
}

function openFreeSwapPopup(st,name,targetCell,role){
  if(!swapSource || swapSource.mode!=='free') return;
  var tKey=cellKey(targetCell);
  var sInfo=keyInfo(st,swapSource.key);
  var tInfo=keyInfo(st,tKey);
  var overlay=document.createElement('div');
  overlay.className='popup-overlay';
  overlay.innerHTML='<div class="popup" style="position:relative"><button class="button ghost" id="closeFreeSwap" style="position:absolute;top:8px;right:8px">✕</button><h3>Confirmer l\'échange</h3><p>Votre garde : '+sInfo.day+' '+sInfo.dateStr+' '+sInfo.hours+' ('+sInfo.col+')</p><p>Garde disponible : '+tInfo.day+' '+tInfo.dateStr+' '+tInfo.hours+' ('+tInfo.col+')</p><div class="row"><button class="button" id="confirmFreeSwap">Valider</button><button class="button ghost" id="cancelFreeSwap">Annuler</button></div></div>';
  document.body.appendChild(overlay);
  overlay.addEventListener('click',function(e){
    e.stopPropagation();
    if(e.target.id==='closeFreeSwap' || e.target.id==='cancelFreeSwap' || e.target===overlay){ document.body.removeChild(overlay); return; }
    if(e.target.id==='confirmFreeSwap'){
      document.body.removeChild(overlay);
      showLoading();
      requestAnimationFrame(function(){
        performFreeSwap(st,name,swapSource.key,tKey,role);
        hideLoading();
      });
    }
  });
}

function performFreeSwap(st,name,sKey,tKey,role){
  var pub=st.published[name]||{};
  var item=pub[sKey];
  if(item){
    pub[tKey]=item;
    delete pub[sKey];
    pub[tKey].status='accepted';
  }
  st.tradeRequests=(st.tradeRequests||[]).filter(function(r){
    if(r.status==='pending' && (r.source===sKey || r.target===sKey)){
      st.audit.push({ts:Date.now(),action:'swap-auto-cancelled',by:name,user:r.from,from:r.source,to:r.target});
      return false;
    }
    return true;
  });
  st.published[name]=pub;
  st.audit.push({ts:Date.now(),action:'swap-free',by:name,user:name,from:sKey,to:tKey});
  save(st);
  if(swapSource && swapSource.cell) swapSource.cell.classList.remove('swap-source');
  swapSource=null;
  exitSwapMode();
  renderSaisie(role);
}

function onSwapSelect(st,name,cell){
  if(!st.tradeEnabled) return;
  var k=cellKey(cell);
  if(swapSource && swapSource.key===k){
    cell.classList.remove("swap-source");
    swapSource=null;
    exitSwapMode();
    return;
  }
  if(swapSource && swapSource.cell){
    swapSource.cell.classList.remove("swap-source");
  }
  swapSource={key:k,cell:cell,name:name};
  cell.classList.add("swap-source");
  enterSwapMode(st);
}

function enterSwapMode(st){
  if(!swapSource) return;
  var card=document.querySelector('.card.planning');
  if(!card) return;
  card.classList.add('swap-mode','swap-colleague');
  var cells=card.querySelectorAll('td.cell');
  cells.forEach(function(c){
    if(c.classList.contains('swap-source')) return;
    var tUser=takenBy(st,cellKey(c));
    if(!tUser || tUser===swapSource.name){
      c.classList.add('swap-disabled');
    } else {
      c.classList.remove('swap-disabled');
    }
  });
  var btn=document.getElementById('cancelSwapMode');
  if(btn) btn.style.display='inline-block';
}

function exitSwapMode(){
  var card=document.querySelector('.card.planning');
  if(!card) return;
  card.classList.remove('swap-mode','swap-colleague');
  var cells=card.querySelectorAll('td.cell');
  cells.forEach(function(c){ c.classList.remove('swap-disabled'); });
  var btn=document.getElementById('cancelSwapMode');
  if(btn) btn.style.display='none';
}

function openSwapPopup(st,name,targetCell){
  if(!st.tradeEnabled) return;
  var tKey=cellKey(targetCell);
  var tUser=takenBy(st,tKey);
  if(!swapSource || !tUser || tUser===name) return;
  var sInfo=keyInfo(st,swapSource.key);
  var tInfo=keyInfo(st,tKey);
  var overlay=document.createElement("div");
  overlay.className="popup-overlay";
  overlay.innerHTML='<div class="popup" style="position:relative"><button class="button ghost" id="closePopup" style="position:absolute;top:8px;right:8px">✕</button><h3>Proposer un échange</h3><p>Votre garde : '+sInfo.day+' '+sInfo.dateStr+' '+sInfo.hours+' ('+sInfo.col+')</p><p>Garde de '+tUser+' : '+tInfo.day+' '+tInfo.dateStr+' '+tInfo.hours+' ('+tInfo.col+')</p><div class="row"><button class="button" id="confirmSwap">Valider</button><button class="button ghost" id="cancelSwap">Annuler</button></div></div>';
  document.body.appendChild(overlay);
  overlay.addEventListener("click",function(e){
    e.stopPropagation();
    if(e.target.id==="closePopup"||e.target.id==="cancelSwap"||e.target===overlay){
      document.body.removeChild(overlay);
      return;
    }
    if(e.target.id==="confirmSwap"){
      document.body.removeChild(overlay);
      showLoading();
      requestAnimationFrame(function(){
        sendSwapRequest(st,name,tUser,swapSource.key,tKey);
        hideLoading();
      });
    }
  });
}

function sendSwapRequest(st,from,to,sourceKey,targetKey){
  if(!st.tradeEnabled) return;
  st.tradeRequests=st.tradeRequests||[];
  var existing=st.tradeRequests.filter(function(r){return r.from===from && r.source===sourceKey && r.status==='pending';});
  if(existing.length>=3){
    alert('Limite de trois propositions en attente pour cette garde.');
    if(swapSource && swapSource.cell) swapSource.cell.classList.remove('swap-source');
    swapSource=null;
    exitSwapMode();
    return;
  }
  st.tradeRequests.push({id:Date.now(),from:from,to:to,source:sourceKey,target:targetKey,status:"pending"});
  st.audit.push({ts:Date.now(),action:"swap-propose",by:from,user:to,from:sourceKey,to:targetKey});
  save(st);
  if(swapSource && swapSource.cell){
    swapSource.cell.classList.remove("swap-source");
    swapSource.cell.classList.add("trade-pending");
  }
  swapSource=null;
  exitSwapMode();
}

function updateTradeCount(st,name,root){
  var cnt=(st.tradeRequests||[]).filter(function(r){return r.to===name && r.status==='pending';}).length;
  var badge=root.querySelector('#tradeCount');
  if(badge){
    if(cnt>0){ badge.textContent=cnt; badge.classList.add('show'); }
    else { badge.classList.remove('show'); }
  }
}

function showTradeList(st,role,name){
  if(!st.tradeEnabled) return;
  var overlay=document.createElement('div');
  overlay.className='popup-overlay';

  function render(){
    var list=(st.tradeRequests||[]).filter(function(r){return r.to===name && r.status==='pending';});
    var html='<div class="popup" style="position:relative"><button class="button ghost" id="closeTrades" style="position:absolute;top:8px;right:8px">✕</button><h3>Propositions en attente</h3>';
    if(list.length===0){
      html+='<p>Aucune proposition.</p>';
    } else {
      list.forEach(function(r){
        var sInfo=keyInfo(st,r.source), tInfo=keyInfo(st,r.target);
        html+='<div class="row" data-id="'+r.id+'"><div>'+r.from+' propose '+sInfo.day+' '+sInfo.dateStr+' ('+sInfo.col+') contre '+tInfo.day+' '+tInfo.dateStr+' ('+tInfo.col+')</div><div style="display:flex;gap:4px;margin-top:6px"><button class="button" data-act="accept" data-id="'+r.id+'">✔️</button><button class="button danger" data-act="refuse" data-id="'+r.id+'">✖️</button></div></div>';
      });
    }
    html+='</div>';
    overlay.innerHTML=html;
  }

  render();
  document.body.appendChild(overlay);
  overlay.addEventListener('click',function(e){
    if(e.target.id==='closeTrades'){ document.body.removeChild(overlay); return; }
    var act=e.target.getAttribute('data-act');
    var id=e.target.getAttribute('data-id');
    if(act==='accept'){
      showLoading();
      requestAnimationFrame(function(){
        acceptTrade(st,name,id); render(); renderSaisie(role); hideLoading();
      });
    }
    if(act==='refuse'){
      showLoading();
      requestAnimationFrame(function(){
        refuseTrade(st,name,id); render(); renderSaisie(role); hideLoading();
      });
    }
  });
}

function showMyTradeList(st,role,name){
  if(!st.tradeEnabled) return;
  var overlay=document.createElement('div');
  overlay.className='popup-overlay';

  function render(){
    var all=(st.tradeRequests||[]).filter(function(r){return r.from===name;});
    var pending=all.filter(function(r){return r.status==='pending';});
    var processed=all.filter(function(r){return r.status!=='pending';})
                       .sort(function(a,b){return b.id-a.id;})
                       .slice(0,10);
    var html='<div class="popup" style="position:relative"><button class="button ghost" id="closeMyTrades" style="position:absolute;top:8px;right:8px">✕</button><h3>Mes propositions</h3>';
    if(pending.length===0 && processed.length===0){
      html+='<p>Aucune proposition.</p>';
    } else {
      pending.forEach(function(r){
        var sInfo=keyInfo(st,r.source), tInfo=keyInfo(st,r.target);
        html+='<div class="row" data-id="'+r.id+'"><div>À '+r.to+' : '+sInfo.day+' '+sInfo.dateStr+' ('+sInfo.col+') contre '+tInfo.day+' '+tInfo.dateStr+' ('+tInfo.col+')</div><div style="display:flex;gap:4px;margin-top:6px"><button class="button danger" data-act="cancel" data-id="'+r.id+'">Annuler</button></div></div>';
      });
      if(processed.length>0){
        processed.forEach(function(r){
          var sInfo=keyInfo(st,r.source), tInfo=keyInfo(st,r.target);
          var cls=r.status==='accepted'?'accepted':'refused';
          var label=r.status==='accepted'?'Acceptée':'Refusée';
          html+='<div class="row trade-row '+cls+'" data-id="'+r.id+'"><div>À '+r.to+' : '+sInfo.day+' '+sInfo.dateStr+' ('+sInfo.col+') contre '+tInfo.day+' '+tInfo.dateStr+' ('+tInfo.col+') — '+label+'</div></div>';
        });
      }
    }
    html+='</div>';
    overlay.innerHTML=html;
  }

  render();
  document.body.appendChild(overlay);
  overlay.addEventListener('click',function(e){
    if(e.target.id==='closeMyTrades'){ document.body.removeChild(overlay); return; }
    var act=e.target.getAttribute('data-act');
    var id=e.target.getAttribute('data-id');
    if(act==='cancel'){ cancelTrade(st,name,id); render(); renderSaisie(role); }
  });
}

function cancelTrade(st,name,id){
  var list=st.tradeRequests||[];
  var idx=list.findIndex(function(r){return r.id==id && r.from===name && r.status==='pending';});
  if(idx===-1) return;
  var req=list[idx];
  st.audit.push({ts:Date.now(),action:'swap-cancelled',by:name,user:req.to,from:req.source,to:req.target});
  list.splice(idx,1);
  st.tradeRequests=list;
  save(st);
}

function pruneProcessedTrades(st,user){
  var list=st.tradeRequests||[];
  var processed=list.filter(function(r){return r.from===user && r.status!=='pending';});
  if(processed.length<=10) return;
  processed.sort(function(a,b){return a.id-b.id;});
  var excess=processed.length-10;
  var removeIds=processed.slice(0,excess).map(function(r){return r.id;});
  st.tradeRequests=list.filter(function(r){return removeIds.indexOf(r.id)===-1;});
}

function acceptTrade(st,name,id){
  var list=st.tradeRequests||[];
  var req=list.find(function(r){return r.id==id && r.to===name && r.status==='pending';});
  if(!req) return;
  req.status='accepted';
  var from=req.from,to=req.to, sKey=req.source, tKey=req.target;
  var fromPub=st.published[from]||{}, toPub=st.published[to]||{};
  var sItem=fromPub[sKey], tItem=toPub[tKey];
  if(sItem && tItem){
    fromPub[tKey]=tItem; delete fromPub[sKey];
    toPub[sKey]=sItem; delete toPub[tKey];
    fromPub[tKey].status='accepted'; toPub[sKey].status='accepted';
  }
  st.tradeRequests=list.filter(function(r){
    if(r.id===req.id) return true;
    if(r.status==='pending' && (r.source===sKey || r.source===tKey || r.target===sKey || r.target===tKey)){
      st.audit.push({ts:Date.now(),action:'swap-auto-cancelled',by:name,user:r.from,from:r.source,to:r.target});
      return false;
    }
    return true;
  });
  st.published[from]=fromPub; st.published[to]=toPub;
  st.audit.push({ts:Date.now(),action:'swap-accepted',by:name,user:from,from:sKey,to:tKey});
  pruneProcessedTrades(st,from);
  save(st);
}

function refuseTrade(st,name,id){
  var req=(st.tradeRequests||[]).find(function(r){return r.id==id && r.to===name && r.status==='pending';});
  if(!req) return;
  req.status='refused';
  st.audit.push({ts:Date.now(),action:'swap-refused',by:name,user:req.from,from:req.source,to:req.target});
  pruneProcessedTrades(st,req.from);
  save(st);
}

function reindexLevels(st,name,ph){
  var items=[]; var u=st.draftSelections[name]||{}; var p=st.published[name]||{};
  Object.keys(u).forEach(function(k){ var it=u[k]; var phOk = ph==='b' ? (it.phase==='x' || it.phase==='y') : it.phase===ph; if(phOk && it.status==='draft' && isKeyOpen(st,k,it.phase)) items.push({src:'draft',k:k,cat:it.cat,level:it.level,alt:it.alt,ts:it.ts}); });
  Object.keys(p).forEach(function(k){ var it=p[k]; var phOk = ph==='b' ? (it.phase==='x' || it.phase==='y') : it.phase===ph; if(phOk && it.status==='pending' && isKeyOpen(st,k,it.phase)) items.push({src:'published',k:k,cat:it.cat,level:it.level,alt:it.alt,ts:it.ts}); });
  items.sort(function(a,b){ return (a.level-b.level)|| (a.alt-b.alt)|| (a.ts-b.ts); });
  var groups=[];
  items.forEach(function(it){
    var last=groups[groups.length-1];
    var key=it.level;
    if(!last || last.key!==key){ groups.push({key:key,items:[it]}); }
    else { last.items.push(it); }
  });
  var newLevel=1;
  groups.forEach(function(g){
    var hasMain=g.items.some(function(it){ return it.alt===1; });
    var altCounter=2;
    g.items.forEach(function(it){
      var newAlt;
      if(hasMain && it.alt===1){ newAlt=1; }
      else { newAlt=altCounter++; }
      if(it.src==='draft'){ st.draftSelections[name][it.k].level=newLevel; st.draftSelections[name][it.k].alt=newAlt; }
      else { st.published[name][it.k].level=newLevel; st.published[name][it.k].alt=newAlt; }
    });
    newLevel++;
  });
  save(st);
}

function countCat(st,name,cat,ph){
  var c=0;
  var u=st.draftSelections[name]||{};
  Object.keys(u).forEach(function(k){
    var it=u[k];
    var phOk = !ph ? true : (ph==='b' ? (it.phase==='x' || it.phase==='y') : it.phase===ph);
    if(phOk && it.cat===cat && it.status==="draft" && isKeyOpen(st,k,it.phase)) c++;
  });
  var p=st.published[name]||{};
  Object.keys(p).forEach(function(k){
    var it=p[k];
    var phOk = !ph ? true : (ph==='b' ? (it.phase==='x' || it.phase==='y') : it.phase===ph);
    if(phOk && it.cat===cat && it.status==="pending" && isKeyOpen(st,k,it.phase)) c++;
  });
  return c;
}

function publishDraft(st,name,ph){
  var u=st.draftSelections[name]||{};
  st.published[name]=st.published[name]||{};
  Object.keys(u).forEach(function(k){
    var it=u[k];
    var phOk = ph==='b' ? (it.phase==='x' || it.phase==='y') : it.phase===ph;
    if(!phOk || it.status!=="draft") return;
    if(!isKeyOpen(st,k,it.phase)) return;
    it.status="pending";
    st.published[name][k]=it; // move/overwrite
    st.audit.push({ts:Date.now(),action:'request',by:name,user:name,key:k});
    delete u[k];
  });
  st.draftSelections[name]=u;
  save(st);
}

// Récapitulatif
function renderRecap(){
  var st=load();var app=document.getElementById("app");app.innerHTML="";
  var tourLabel = st.activeTour!=null ? 'Tour '+(st.activeTour+1) : 'Tour non défini';
  var tourTitle=document.createElement('h1');
  tourTitle.className='tour-title';
  tourTitle.textContent=tourLabel;
  app.appendChild(tourTitle);
  if(st.activeTour!=null && st.tours[st.activeTour].consigne){
    var cBox=document.createElement('div');
    cBox.className='consigne-box';
    cBox.textContent=st.tours[st.activeTour].consigne;
    app.appendChild(cBox);
  }
  var card=document.createElement("div");card.className="card";
  if(!ADMIN_ACCESS_ENABLED && st.sessions._recapOK){
    delete st.sessions._recapOK;
    save(st);
  }
  if(!st.sessions._recapOK){
    if(!ADMIN_ACCESS_ENABLED){
      card.innerHTML='<h2>Récapitulatif</h2><p class="notice">L\'accès au récapitulatif est protégé par un mot de passe administrateur. Définissez la propriété <code>adminPasswordHash</code> (ou <code>adminPassword</code>) via la configuration Supabase pour consulter ces données.</p>';
      app.appendChild(card);
      return;
    }
    card.innerHTML='<h2>Récapitulatif</h2><div class="row"><div class="input"><label>Mot de passe</label><input id="recPwd" type="password"></div><button class="button" id="recLogin">Valider</button></div>';
    app.appendChild(card);
    card.addEventListener("click",function(e){
      if(e.target&&e.target.id==="recLogin"){
        var v=card.querySelector("#recPwd").value;
        verifyAdminPassword(v).then(function(ok){
          if(ok){
            st.sessions._recapOK=true;
            st.loginLogs.push({ts:Date.now(),role:'admin',name:'admin',type:'login'});
            save(st);
            renderRecap();
          }else{
            alert("Mot de passe incorrect");
          }
        });
      }
    });
    return;
  }
  var rn=st.recapNav;
  if(st.activeTour!=null){
    rn.attrType = st.tours[st.activeTour].choiceType || 'simple';
    save(st);
  }
  var group = rn.group || 'associes';
  if(group==='planning' && typeof rn.planTour!=="number") rn.planTour = st.activeTour;
  var navTabs='<nav class="tabs" id="recapTabs">'
    +'<a href="#" data-group="associes"'+(group==='associes'?' class="active"':'')+'>Médecins</a>'
    +'<a href="#" data-group="remplacants"'+(group==='remplacants'?' class="active"':'')+'>Remplaçants</a>'
    +'<a href="#" data-group="planning"'+(group==='planning'?' class="active"':'')+'>Planning</a>'
    +'<a href="#" data-group="attribution"'+(group==='attribution'?' class="active"':'')+'>Attribution automatique</a>'
    +'<a href="#" data-group="historique"'+(group==='historique'?' class="active"':'')+'>Historique</a>'
    +'<a href="#" data-group="connexion"'+(group==='connexion'?' class="active"':'')+'>Connexion</a>'
    +'</nav>';

  if(group==='attribution'){
    card.classList.add('recap-attrib');
    var role = rn.attrRole || 'associes';
    var usersList = (st.users[role]||[]).slice().sort(function(a,b){ return a.localeCompare(b); });
    var opts = usersList.map(function(n){ return '<option value="'+n+'"'+(rn.attrStart===n?' selected':'')+'>'+trigram(n)+'</option>'; }).join('');
    var typeSel = (st.tours[st.activeTour] && st.tours[st.activeTour].choiceType) || 'simple';
    rn.attrType = typeSel;
    var typeField = '<div class="input"><label>Type de choix</label><select id="attrType"><option value="simple"'+(typeSel==='simple'?' selected':'')+'>Choix simple</option><option value="bonus"'+(typeSel==='bonus'?' selected':'')+'>Choix bonus</option></select></div>';
    var fields = '<div class="input"><label>Boucles par médecin</label><input type="number" id="attrLoops" min="1" value="'+rn.attrLoops+'"></div>'
      +'<div class="input"><label>Nombre de gardes attribuées</label><input type="number" id="attrM" min="0" value="'+rn.attrM+'"></div>';
    if(typeSel==='bonus'){
      fields += '<div class="input"><label>Nombre de bonus attribués</label><input type="number" id="attrB" min="0" value="'+rn.attrB+'"></div>'
        +'<div class="input"><label>Maximum de bons bonus par boucle</label><input type="number" id="attrX" min="0" value="'+rn.attrX+'"></div>';
    }
    card.innerHTML='<h2>Récapitulatif — Attribution automatique <span class="badge tour-name">'+tourLabel+'</span></h2>'+navTabs
      +'<div class="row">'
      +'<div class="input"><label>Tour</label><select id="attrRole"><option value="associes"'+(role==='associes'?' selected':'')+'>Médecins</option><option value="remplacants"'+(role==='remplacants'?' selected':'')+'>Remplaçants</option></select></div>'
      +'<div class="input"><label>Début</label><select id="attrStart"><option value=""></option>'+opts+'</select></div>'
      +'<div class="input"><label>Ordre</label><select id="attrOrder"><option value="asc"'+(rn.attrOrder==='asc'?' selected':'')+'>A→Z</option><option value="desc"'+(rn.attrOrder==='desc'?' selected':'')+'>Z→A</option></select></div>'
      + typeField
      + fields
      +'<button class="button" id="launchAttrib">Lancer l\'attribution automatique</button>'
      +'</div>';
    app.appendChild(card);
    card.addEventListener('input',function(e){
      if(e.target.id==='attrRole'){ st.recapNav.attrRole=e.target.value; st.recapNav.attrStart=''; save(st); renderRecap(); }
      if(e.target.id==='attrStart'){ st.recapNav.attrStart=e.target.value; save(st); }
      if(e.target.id==='attrOrder'){ st.recapNav.attrOrder=e.target.value; save(st); }
      if(e.target.id==='attrType'){ st.recapNav.attrType=e.target.value; if(st.activeTour!=null){ st.tours[st.activeTour].choiceType=e.target.value; } save(st); renderRecap(); }
      if(e.target.id==='attrLoops'){ st.recapNav.attrLoops=parseInt(e.target.value,10)||1; save(st); }
      if(e.target.id==='attrM'){ st.recapNav.attrM=parseInt(e.target.value,10)||0; save(st); }
      if(e.target.id==='attrB'){ st.recapNav.attrB=parseInt(e.target.value,10)||0; st.recapNav.attrY=st.recapNav.attrB-st.recapNav.attrX; save(st); }
      if(e.target.id==='attrX'){ st.recapNav.attrX=parseInt(e.target.value,10)||0; st.recapNav.attrY=st.recapNav.attrB-st.recapNav.attrX; save(st); }
    });
    card.addEventListener('click',function(e){
      var tab=e.target.closest('#recapTabs a');
      if(tab){
        e.preventDefault();
        var ng=tab.getAttribute('data-group');
        st.recapNav.group=ng;
        if(ng==='planning'){ st.recapNav.planTour=st.activeTour; st.recapNav.planPhase='m'; }
        save(st); renderRecap();
        return;
      }
      if(e.target && e.target.id==='launchAttrib'){
        var roleSel=card.querySelector('#attrRole').value;
        var startSel=card.querySelector('#attrStart').value;
        var orderSel=card.querySelector('#attrOrder').value;
        var typeSel=card.querySelector('#attrType').value;
        var loopsSel=parseInt(card.querySelector('#attrLoops').value,10)||1;
        var mSel=parseInt(card.querySelector('#attrM').value,10)||0;
        var bSel=0, xSel=0, ySel=0;
        if(typeSel==='bonus'){
          bSel=parseInt(card.querySelector('#attrB').value,10)||0;
          xSel=parseInt(card.querySelector('#attrX').value,10)||0;
          if(xSel > bSel){
            alert('Le maximum de bons bonus ne peut pas dépasser le nombre total de bonus.');
            return;
          }
          ySel=bSel - xSel;
        }
        st.recapNav.attrY = ySel;
        var people=(st.users[roleSel]||[]).slice();
        st.recapNav.group='planning';
        save(st); renderRecap();
        var prog=document.getElementById('attribProgress');
        if(!prog){
          prog=document.createElement('div');
          prog.id='attribProgress';
          prog.className='attrib-counter';
          prog.innerHTML='<span class="text"></span> <button class="button danger" id="stopAttrib">Arrêter</button>';
          document.body.appendChild(prog);
        }
        var progText=prog.querySelector('.text');
        var stopBtn=prog.querySelector('#stopAttrib');
        progText.textContent='';
        stopBtn.disabled=false;
        stopBtn.onclick=function(){ if(attribHandle) attribHandle.stop(); };
        var statusBox=document.getElementById('attribStatus');
        if(!statusBox){
          statusBox=document.createElement('div');
          statusBox.id='attribStatus';
          statusBox.className='attrib-status';
          statusBox.innerHTML=people.map(function(p){ return '<span data-p="'+p+'" class="on">'+trigram(p)+'</span>'; }).join('');
          document.body.appendChild(statusBox);
        }
        var choiceLabel=typeSel==='bonus'?'Choix bonus':'Choix simple';
        attribHandle=attribution.run(st,{people:people,start:startSel||undefined,order:orderSel,loops:loopsSel,m:mSel,b:bSel,x:xSel},function(type, logs, info){
          if(info && info.counts){
            var txt='Type: '+choiceLabel+' — Gardes attribuées: '+info.counts.m;
            if(typeSel==='bonus'){
              txt+=' | Bonus attribués: '+(info.counts.x+info.counts.y)+' (bons: '+info.counts.x+')';
            }
            txt+=' | En attente: '+info.counts.pending+' | Boucle médecin: '+info.loop;
            progText.textContent=txt;
            if(statusBox && info.on){
              for(var p in info.on){
                var el=statusBox.querySelector('span[data-p="'+p+'"]');
                if(el){ el.className=info.on[p]? 'on' : 'off'; }
              }
            }
            if(type==='done'){
              var doneTxt='Processus terminé — Gardes attribuées: '+info.counts.m;
              if(typeSel==='bonus'){
                doneTxt+=' | Bons bonus attribués: '+info.counts.x+' | Mauvais bonus attribués: '+info.counts.y;
              }
              progText.textContent=doneTxt;
              stopBtn.disabled=true; attribHandle=null;
              if(statusBox) statusBox.remove();
            }
            if(type==='stopped'){
              progText.textContent+=' — Processus arrêté';
              stopBtn.disabled=true; attribHandle=null;
              if(statusBox) statusBox.remove();
            }
          }
          save(st); renderRecap();
        });
        return;
      }
    });
    return;
  }

  if(group==='planning'){
    card.classList.add('planning','recap-plan');
    var ph=rn.planPhase||'m';
    var pt=(typeof rn.planTour==='number')?rn.planTour:st.activeTour;
    var tourLabel=pt!=null ? 'Tour '+(pt+1) : 'Tour non défini';
    var phaseTabs='<nav class="tabs" id="planPhaseTabs">'
      +'<a href="#" data-phase="m"'+(ph==='m'?' class="active"':'')+'>Gardes</a>'
      +'<a href="#" data-phase="b"'+(ph==='b'?' class="active"':'')+'>Bonus</a>'
      +'</nav>';
    var tourOpts='';
    for(var tt=0;tt<10;tt++) tourOpts+='<option value="'+tt+'"'+(tt===pt?' selected':'')+'>Tour '+(tt+1)+'</option>';
    var prevCols=st.columns; st.columns=st.tours[pt].columns;
    var calHtml=buildCalendar(st,'__all__',ph);
    st.columns=prevCols;
    card.innerHTML='<h2>Récapitulatif — Planning <span class="badge tour-name">'+tourLabel+'</span></h2>'+navTabs
      +'<div class="row"><div class="input"><label>Tour</label><select id="planTourSel">'+tourOpts+'</select></div><button class="button" id="exportCsv">Export CSV</button></div>'
      +phaseTabs+calHtml;
    app.appendChild(card);
    card.addEventListener('click',function(e){
      var tab=e.target.closest('#recapTabs a');
      if(tab){
        e.preventDefault();
        var ng=tab.getAttribute('data-group');
        st.recapNav.group = ng;
        st.recapNav.filterDoc="";
        if(ng==='planning'){ st.recapNav.planTour=st.activeTour; st.recapNav.planPhase='m'; }
        save(st); renderRecap();
        return;
      }
      var phaseTab=e.target.closest('#planPhaseTabs a');
      if(phaseTab){
        e.preventDefault();
        st.recapNav.planPhase=phaseTab.getAttribute('data-phase');
        save(st); renderRecap();
        return;
      }
      if(e.target && e.target.id==='exportCsv'){
        var prev=st.columns; st.columns=st.tours[pt].columns; exportPlanningCSV(st); st.columns=prev;
        return;
      }
      var cell=e.target.closest('td.cell');
      if(cell){ var prevC=st.columns; st.columns=st.tours[pt].columns; editPlanningCell(st,cell); st.columns=prevC; }
    });
    card.addEventListener('change',function(e){
      if(e.target && e.target.id==='planTourSel'){
        st.recapNav.planTour=parseInt(e.target.value,10); save(st); renderRecap();
      }
    });
    return;
  }

  if(group==='historique'){
    card.classList.add('recap-hist');
    card.innerHTML='<h2>Récapitulatif — Historique <span class="badge tour-name">'+tourLabel+'</span></h2>'+navTabs+'<button class="button ghost" id="auditReset">Réinitialiser les filtres</button><div class="card" id="auditWrap"></div>';
    app.appendChild(card);
    drawAuditTable(card, st);
    card.addEventListener('click',function(e){
      var tab=e.target.closest('#recapTabs a');
      if(tab){
        e.preventDefault();
        var ng=tab.getAttribute('data-group');
        st.recapNav.group = ng;
        if(ng==='planning'){ st.recapNav.planTour=st.activeTour; st.recapNav.planPhase='m'; }
        save(st); renderRecap();
        return;
      }
      if(e.target && e.target.id==='auditReset'){
        auditFilters={};
        drawAuditTable(card, st);
      }
    });
    return;
  }

  if(group==='connexion'){
    card.classList.add('recap-conn');
    var logs=st.loginLogs.slice().sort(function(a,b){return b.ts-a.ts;});
    var rows=logs.map(function(l){
      var r=l.role==='medecin'? 'Médecin' : (l.role==='remplacant'? 'Remplaçant' : 'Admin');
      var action=l.type==='logout'? 'Déconnexion' : 'Connexion';
      return '<tr><td>'+formatTs(l.ts)+'</td><td>'+action+'</td><td>'+r+'</td><td>'+(l.name||'')+'</td></tr>';
    }).join('');
    if(!rows) rows='<tr><td colspan="4">Aucune connexion</td></tr>';
    card.innerHTML='<h2>Récapitulatif — Connexion <span class="badge tour-name">'+tourLabel+'</span></h2>'+navTabs+'<div class="card"><table class="table"><thead><tr><th>Date</th><th>Action</th><th>Rôle</th><th>Utilisateur</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
    app.appendChild(card);
    card.addEventListener('click',function(e){
      var tab=e.target.closest('#recapTabs a');
      if(tab){
        e.preventDefault();
        var ng=tab.getAttribute('data-group');
        st.recapNav.group=ng;
        if(ng==='planning'){ st.recapNav.planTour=st.activeTour; st.recapNav.planPhase='m'; }
        save(st); renderRecap();
      }
    });
    return;
  }

  var allUsers = (st.users[group]||[]).slice();
  allUsers.sort(function(a,b){ return a.localeCompare(b); });
  var uOpts = ['<option value="">(Tous)</option>'].concat(allUsers.map(function(n){return '<option value="'+n+'" '+(rn.filterDoc===n?'selected':'')+'>'+n+'</option>'; }));
  var labelDoc = group === 'remplacants' ? 'Remplaçant' : 'Médecin';
  var btnLabel = group === 'remplacants' ? 'Remplaçant suivant' : 'Médecin suivant';
  card.innerHTML='<h2>Récapitulatif — Demandes <span class="badge tour-name">'+tourLabel+'</span></h2>'
    + navTabs
    +'<div class="row">'
      +'<div class="input"><label>Phase</label><select id="fPhase"><option value="m" '+(rn.phase==="m"?'selected':'')+'>Gardes</option><option value="b" '+(rn.phase==="b"?'selected':'')+'>Bonus</option></select></div>'
      +'<div class="input"><label>'+labelDoc+'</label><select id="fDoc">'+uOpts.join("")+'</select></div>'
      +'<div class="input"><label>État</label><select id="fEtat"><option value="pending" '+(rn.filterEtat==="pending"?'selected':'')+'>En attente</option><option value="accepted" '+(rn.filterEtat==="accepted"?'selected':'')+'>Acceptées</option><option value="refused" '+(rn.filterEtat==="refused"?'selected':'')+'>Refusées</option><option value="incompatible" '+(rn.filterEtat==="incompatible"?'selected':'')+'>Incompatible tour en cours</option><option value="" '+(rn.filterEtat===""?'selected':'')+'>Tous</option></select></div>'
      +'<div class="input"><label>Type</label><select id="fType"><option value="" '+(rn.filterType===""?'selected':'')+'>Tous</option><option value="visite" '+(rn.filterType==="visite"?'selected':'')+'>Visite</option><option value="consultation" '+(rn.filterType==="consultation"?'selected':'')+'>Consultation</option><option value="tc" '+(rn.filterType==="tc"?'selected':'')+'>Téléconsultation</option></select></div>'
      +'<div class="input"><label>Ordre</label><select id="fOrder"><option value="asc" '+(rn.order==="asc"?'selected':'')+'>A→Z</option><option value="desc" '+(rn.order==="desc"?'selected':'')+'>Z→A</option></select></div>'
      +'<button class="button" id="btnNext">'+btnLabel+'</button>'
      +'<button class="button ghost" id="btnReset">Réinitialiser les filtres</button>'
    +'</div>'
    +'<div class="row kpi" id="kpiBox"></div>'
    +'<div class="card" id="tableWrap"></div>';
  app.appendChild(card);
  drawRecapTable(card, st);

  card.addEventListener("input",function(e){
    if(e.target.id==="fPhase"){ st.recapNav.phase=e.target.value; save(st); drawRecapTable(card,st); }
    if(e.target.id==="fDoc"){ st.recapNav.filterDoc=e.target.value; save(st); drawRecapTable(card,st); }
    if(e.target.id==="fEtat"){ st.recapNav.filterEtat=e.target.value; save(st); drawRecapTable(card,st); }
    if(e.target.id==="fType"){ st.recapNav.filterType=e.target.value; save(st); drawRecapTable(card,st); }
    if(e.target.id==="fOrder"){ st.recapNav.order=e.target.value; save(st); }
  });
  card.addEventListener("click",function(e){
    var tab=e.target.closest('#recapTabs a');
    if(tab){
      e.preventDefault();
      var ng=tab.getAttribute('data-group');
      st.recapNav.group = ng;
      st.recapNav.filterDoc = "";
      if(ng==='planning'){ st.recapNav.planTour=st.activeTour; st.recapNav.planPhase='m'; }
      save(st);
      renderRecap();
      return;
    }
    if(e.target&&e.target.id==="btnReset"){
      st.recapNav.phase="m";
      st.recapNav.filterDoc="";
      st.recapNav.filterEtat="pending";
      st.recapNav.filterType="";
      st.recapNav.order="asc";
      save(st);
      card.querySelector("#fPhase").value="m";
      card.querySelector("#fDoc").value="";
      card.querySelector("#fEtat").value="pending";
      card.querySelector("#fType").value="";
      card.querySelector("#fOrder").value="asc";
      drawRecapTable(card, st);
    }
    if(e.target&&e.target.id==="btnNext"){ nextDoctor(st,card); }
    var a=e.target.closest("button[data-act]"); if(a){
      var act=a.getAttribute("data-act"), user=a.getAttribute("data-user"), key=a.getAttribute("data-key");
      if(act==="accept") acceptOne(st,user,key);
      if(act==="refuse") setStatus(st,user,key,"refused");
      if(act==="pending") setStatus(st,user,key,"pending");
      save(st); drawRecapTable(card,st);
    }
  });
}

function editPlanningCell(st,cell){
  if(cell.querySelector('select')) return;
  var y=parseInt(cell.getAttribute('data-y'),10),
      m=parseInt(cell.getAttribute('data-m'),10),
      d=parseInt(cell.getAttribute('data-d'),10),
      colId=cell.getAttribute('data-col');
  var k=keyOf(y,m,d,colId);
  var list=(st.users.associes||[]).concat(st.users.remplacants||[]);
  list.sort(function(a,b){ return a.localeCompare(b); });
  var opts=['<option value=""></option>']
    .concat(list.map(function(n){ return '<option value="'+n+'">'+trigram(n)+'</option>'; }));
  var cur=takenBy(st,k)||"";
  cell.innerHTML='<select class="tri-select">'+opts.join('')+'</select>';
  var sel=cell.querySelector('select');
  sel.value=cur;
  sel.focus();
  sel.addEventListener('change',apply);
  sel.addEventListener('blur',function(){ renderRecap(); });

  function apply(){
    var val=sel.value;
    for(var u in st.published){ if(st.published[u][k]) delete st.published[u][k]; }
    if(val){
      st.published[val]=st.published[val]||{};
      var col=st.columns[parseInt(colId.replace('col',''),10)-1]||{};
      var hol=holidaySet(st.holidays);
      var day={y:y,m:m,d:d,w:(new Date(y,m,d).getDay()||7)};
      var isHoliday=!!hol[day.y+"-"+pad(day.m+1)+"-"+pad(day.d)] || (day.w===7);
      var q=isHoliday ? col.q_sun : (day.w===6 ? col.q_sat : col.q_wd);
      var phase=isOpen(col,day,hol,'b')?(q==="bonne"?'y':'x'):'m';
      st.published[val][k]={status:'accepted',cat:catOf(col.type),level:1,alt:1,phase:phase,ts:Date.now()};
      if(cur && cur!==val) st.audit.push({ts:Date.now(),action:'clear',by:'admin',user:cur,key:k});
      if(val!==cur) st.audit.push({ts:Date.now(),action:'assign',by:'admin',user:val,key:k});
    }else{
      if(cur) st.audit.push({ts:Date.now(),action:'clear',by:'admin',user:cur,key:k});
    }
    save(st);
    renderRecap();
  }
}

function nextDoctor(st, card){
  var rn=st.recapNav;
  var all = (st.users[rn.group]||[]).slice();
  all.sort(function(a,b){
    return rn.order === "asc" ? a.localeCompare(b) : b.localeCompare(a);
  });
  var idx = all.indexOf(rn.filterDoc || "");
  idx = (idx + 1) % (all.length || 1);
  st.recapNav.filterDoc = all[idx] || "";
  save(st);
  drawRecapTable(card, st);
}

function drawRecapTable(card, st){
  var rn=st.recapNav, ph=rn.phase||"m";
  var tbl=card.querySelector("#tableWrap");
  var kpi=card.querySelector("#kpiBox");
  var rows=[];
  var users = rn.filterDoc? [rn.filterDoc] : Object.keys(st.published);
  var allowed = st.users[rn.group] || [];
  users = users.filter(function(u){ return allowed.indexOf(u)!==-1; });
  if(users.length===0) users = allowed.slice();
  var kVis={pending:0,accepted:0,refused:0}, kCon={pending:0,accepted:0,refused:0}, kTC={pending:0,accepted:0,refused:0};
  users.forEach(function(u){
    var map=st.published[u]||{};
    Object.keys(map).forEach(function(k){
      var it=map[k];
      var open = isKeyOpen(st,k,it.phase);
      var status = it.status;
      if(status==="pending" && !open) status="incompatible";
      // KPI counters ignore phase and état filters
      if(!rn.filterType || it.cat===rn.filterType){
        if(status!=="incompatible"){
          var g = it.cat==="tc"?kTC:(it.cat==="consultation"?kCon:kVis);
          g[status]++;
        }
      }
      // Table rows respect phase and état filters
      if(ph==='b'){ if(it.phase!=='x' && it.phase!=='y') return; }
      else if(it.phase!==ph) return;
      if(rn.filterEtat && status!==rn.filterEtat) return;
      if(rn.filterType && it.cat!==rn.filterType) return;
      var p=k.split("::")[0].split("-"); var Y=+p[0], m=+p[1]-1, d=+p[2]; var colId=k.split("::")[1];
      var col=st.columns[parseInt(colId.replace("col",""),10)-1]||{};
      rows.push({
        user:u, tri:trigram(u), key:k, date:new Date(Y,m,d), dateStr:p[2]+"/"+p[1]+"/"+p[0],
        col: (col.type||colId), hours: (col.start||"")+"-"+(col.end||""), type: col.type||"", cat: it.cat,
        level: it.level||0, alt: it.alt||0, status: status, phase: it.phase
      });
    });
  });
  rows.sort(function(a,b){
    if(a.user!==b.user){ return a.user>b.user?1:-1; }
    if(a.level!==b.level) return a.level-b.level;
    if(a.alt!==b.alt) return a.alt-b.alt;
    return a.date-b.date;
  });
  // KPI
  kpi.innerHTML='<span class="badge">Visites — Validées: '+kVis.accepted+' | En attente: '+kVis.pending+' | Refusées: '+kVis.refused+'</span>'
               +'<span class="badge">Consultations — Validées: '+kCon.accepted+' | En attente: '+kCon.pending+' | Refusées: '+kCon.refused+'</span>'
               +'<span class="badge">Téléconsultations — Validées: '+kTC.accepted+' | En attente: '+kTC.pending+' | Refusées: '+kTC.refused+'</span>';

  function statusLabel(s){
    if(s==="accepted") return "Acceptée";
    if(s==="refused") return "Refusée";
    if(s==="incompatible") return "Incompatible tour en cours";
    return "En attente";
  }

  var html='<table class="table"><thead><tr><th>Prio</th><th>Date</th><th>Colonne</th><th>Type</th><th>Médecin</th><th>État</th><th>Actions</th></tr></thead><tbody>';
  rows.forEach(function(r){
    var pr = r.level+(r.alt>1?("."+(r.alt-1)):"")+(r.phase==="m"?"M":(r.phase==="x"?"V":"B"));
    var actions='';
    if(r.status!=="incompatible"){
      actions+= (r.status!=="accepted"? '<button class="button" data-act="accept" data-user="'+r.user+'" data-key="'+r.key+'">Accepter</button> ' : '' );
      actions+= (r.status!=="refused"? '<button class="button ghost" data-act="refuse" data-user="'+r.user+'" data-key="'+r.key+'">Refuser</button> ' : '' );
      actions+= (r.status!=="pending"? '<button class="button ghost" data-act="pending" data-user="'+r.user+'" data-key="'+r.key+'">Repasser en attente</button>' : '' );
    }
    html+='<tr><td>'+pr+'</td><td>'+r.dateStr+'</td><td>'+r.col+' <span class="small">('+r.hours+')</span></td><td>'+r.type+'</td><td>'+r.user+' <span class="small">['+r.tri+']</span></td><td>'+statusLabel(r.status)+'</td><td>'+actions+'</td></tr>';
  });
  html+='</tbody></table>';
  tbl.innerHTML=html;
}

function drawAuditTable(card, st){
  var tbl=card.querySelector('#auditWrap');
  var rows=st.audit.slice().sort(function(a,b){ return b.ts-a.ts; });
  function userDisplay(it){
    if(it.action && it.action.indexOf('swap')===0){
      return it.action==='swap-free' ? (it.by||'') : (it.by||'')+' → '+(it.user||'');
    }
    return it.user || '';
  }
  var sets={action:{},by:{},user:{},day:{},col:{},hours:{}};
  rows.forEach(function(it){
    var uDisp=userDisplay(it);
    sets.action[auditLabel(it)]=true;
    sets.by[it.by||'']=true;
    sets.user[uDisp]=true;
    if(it.action && it.action.indexOf('swap')===0){
      var infoFrom=keyInfo(st,it.from||'');
      var infoTo=keyInfo(st,it.to||'');
      var dayStrFrom=infoFrom.day? (infoFrom.day+' '+infoFrom.dateStr):'';
      var dayStrTo=infoTo.day? (infoTo.day+' '+infoTo.dateStr):'';
      sets.day[dayStrFrom+' → '+dayStrTo]=true;
      sets.col[infoFrom.col+' → '+infoTo.col]=true;
      sets.hours[infoFrom.hours+' → '+infoTo.hours]=true;
    }else{
      var info=keyInfo(st,it.key||'');
      sets.day[info.day? (info.day+' '+info.dateStr):'']=true;
      sets.col[info.col]=true;
      sets.hours[info.hours]=true;
    }
  });
  function arr(o){return Object.keys(o).filter(Boolean).sort();}
  var actions=arr(sets.action),bys=arr(sets.by),users=arr(sets.user),days=arr(sets.day),cols=arr(sets.col),hrs=arr(sets.hours);
  function selHtml(name,opts){ var h='<select data-filter="'+name+'"><option value="">(Tous)</option>'; opts.forEach(function(o){ var s=auditFilters[name]===o?' selected':''; h+='<option value="'+o+'"'+s+'>'+o+'</option>'; }); return h+'</select>'; }
  rows=rows.filter(function(it){
    var dayStr,colStr,hourStr,uDisp=userDisplay(it);
    if(it.action && it.action.indexOf('swap')===0){
      var infoFrom=keyInfo(st,it.from||'');
      var infoTo=keyInfo(st,it.to||'');
      dayStr=(infoFrom.day? (infoFrom.day+' '+infoFrom.dateStr):'')+' → '+(infoTo.day? (infoTo.day+' '+infoTo.dateStr):'');
      colStr=infoFrom.col+' → '+infoTo.col;
      hourStr=infoFrom.hours+' → '+infoTo.hours;
    }else{
      var info=keyInfo(st,it.key||'');
      dayStr=info.day? (info.day+' '+info.dateStr):'';
      colStr=info.col;
      hourStr=info.hours;
    }
    return (!auditFilters.action || auditLabel(it)===auditFilters.action)
      && (!auditFilters.by || (it.by||'')===auditFilters.by)
      && (!auditFilters.user || uDisp===auditFilters.user)
      && (!auditFilters.day || dayStr===auditFilters.day)
      && (!auditFilters.col || colStr===auditFilters.col)
      && (!auditFilters.hours || hourStr===auditFilters.hours);
  });
  var html='<table class="table"><thead><tr><th>Date op.</th><th data-col="action">Action</th><th data-col="by">Par</th><th data-col="user">Médecin</th><th data-col="day">Jour</th><th data-col="col">Colonne</th><th data-col="hours">Horaire</th></tr>'
    +'<tr class="filters"><th></th><th>'+selHtml('action',actions)+'</th><th>'+selHtml('by',bys)+'</th><th>'+selHtml('user',users)+'</th><th>'+selHtml('day',days)+'</th><th>'+selHtml('col',cols)+'</th><th>'+selHtml('hours',hrs)+'</th></tr></thead><tbody>';
  rows.forEach(function(it){
    if(it.action && it.action.indexOf('swap')===0){
      var infoFrom=keyInfo(st,it.from||'');
      var infoTo=keyInfo(st,it.to||'');
      html+='<tr><td>'+formatTs(it.ts)+'</td><td>'+auditLabel(it)+'</td><td>'+(it.by||'')+'</td><td>'+userDisplay(it)+'</td><td>'+
        (infoFrom.day? (infoFrom.day+' '+infoFrom.dateStr):'')+' → '+(infoTo.day? (infoTo.day+' '+infoTo.dateStr):'')+
        '</td><td>'+infoFrom.col+' → '+infoTo.col+'</td><td>'+infoFrom.hours+' → '+infoTo.hours+'</td></tr>';
    }else{
      var info=keyInfo(st,it.key||'');
      html+='<tr><td>'+formatTs(it.ts)+'</td><td>'+auditLabel(it)+'</td><td>'+(it.by||'')+'</td><td>'+userDisplay(it)+'</td><td>'+(info.day? (info.day+' '+info.dateStr):'')+'</td><td>'+info.col+'</td><td>'+info.hours+'</td></tr>';
    }
  });
  html+='</tbody></table>';
  tbl.innerHTML=html;
  tbl.querySelectorAll('select[data-filter]').forEach(function(sel){
    sel.addEventListener('change',function(){
      auditFilters[this.getAttribute('data-filter')]=this.value;
      drawAuditTable(card, st);
    });
  });
}

function setStatus(st,user,key,status){
  st.published[user]=st.published[user]||{};
  if(!st.published[user][key]) return;
  st.published[user][key].status=status;
  st.audit.push({ts:Date.now(), action:"status", by:"admin", user:user, key:key, to:status});
}
function acceptOne(st,user,key){
  st.published[user]=st.published[user]||{}; var it=st.published[user][key]; if(!it) return;
  it.status="accepted";
  st.audit.push({ts:Date.now(), action:"accept", by:"admin", user:user, key:key});
  // refuser autres demandes sur la même case
  for(var u in st.published){
    if(u===user) continue;
    var jt=st.published[u][key];
    if(jt && jt.phase===it.phase && jt.status==="pending"){ jt.status="refused"; st.audit.push({ts:Date.now(), action:"auto-refuse", by:"system", user:u, key:key}); }
  }
  // refuser alternatives du même niveau/cat/phase pour ce médecin
  var map=st.published[user]; for(var k in map){ if(k===key) continue; var x=map[k];
    if(x.phase===it.phase && x.status==="pending" && x.level===it.level && x.cat===it.cat){ x.status="refused"; st.audit.push({ts:Date.now(), action:"auto-refuse-alt", by:"system", user:user, key:k}); }
  }
  save(st);
}

// Tooltip for quality flag (trigram list)
document.addEventListener("mouseover",function(e){
  var tip=e.target.closest(".qual-flag"); var el=document.getElementById("tooltip");
  if(tip && tip.getAttribute("data-tip")){ el.textContent=tip.getAttribute("data-tip"); el.style.display="block"; positionTooltip(el,e); }
});
document.addEventListener("mousemove",function(e){
  var el=document.getElementById("tooltip"); if(el.style.display==="block") positionTooltip(el,e);
});
document.addEventListener("mouseout",function(e){
  var el=document.getElementById("tooltip"); if(!e.relatedTarget || !e.relatedTarget.closest || !e.relatedTarget.closest(".qual-flag")) el.style.display="none";
});
function positionTooltip(el,e){ var x=e.clientX+12, y=e.clientY+12; el.style.left=x+"px"; el.style.top=y+"px"; }

document.addEventListener("click",function(e){
  var ch=e.target.closest(".col-head");
  if(ch && ch.closest(".saisie")) ch.classList.toggle("show");
});

// Boot
function init(){
  if(!location.hash) location.hash="#/saisie-associes";
  hasInitialized=true;
  route();
}
function bootstrap(){
  if(!SUPABASE_URL || !SUPABASE_ANON_KEY){
    console.info('Supabase non configuré : les données seront conservées en mémoire uniquement.');
  }
  var client=getSupabaseClient();
  if(!client){ init(); return; }
  showLoading();
  supabaseFetchState()
    .then(function(remote){ if(remote) applyRemoteState(remote); })
    .catch(function(err){ console.error("Supabase bootstrap error",err); })
    .then(function(){ hideLoading(); init(); subscribeToRemoteChanges(); });
}
document.addEventListener("DOMContentLoaded",bootstrap);
})();
