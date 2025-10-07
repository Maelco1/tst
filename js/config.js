(function(){
  'use strict';

  function assign(target){
    target = target || {};
    for(var i = 1; i < arguments.length; i++){
      var src = arguments[i] || {};
      for(var key in src){
        if(Object.prototype.hasOwnProperty.call(src, key)){
          target[key] = src[key];
        }
      }
    }
    return target;
  }

  var STORAGE_KEY = 'planning_supabase_overrides';

  function hasLocalStorage(){
    try{
      return typeof window !== 'undefined' && window.localStorage && typeof window.localStorage.getItem === 'function';
    }catch(err){
      return false;
    }
  }

  function cleanOverrides(overrides){
    var allowed = ['url', 'anonKey', 'table', 'keyColumn', 'dataColumn'];
    var out = {};
    if(!overrides || typeof overrides !== 'object') return out;
    for(var i = 0; i < allowed.length; i++){
      var key = allowed[i];
      var value = overrides[key];
      if(typeof value === 'string'){
        var trimmed = value.trim();
        if(trimmed) out[key] = trimmed;
      }
    }
    if(overrides.extraTables && typeof overrides.extraTables === 'object'){
      out.extraTables = assign({}, overrides.extraTables);
    }
    return out;
  }

  function hasKeys(obj){
    if(!obj || typeof obj !== 'object') return false;
    for(var key in obj){
      if(Object.prototype.hasOwnProperty.call(obj, key)) return true;
    }
    return false;
  }

  function readOverrides(){
    if(!hasLocalStorage()) return {};
    try{
      var raw = window.localStorage.getItem(STORAGE_KEY);
      if(!raw) return {};
      var parsed = JSON.parse(raw);
      return assign({}, cleanOverrides(parsed));
    }catch(err){
      console.warn('Impossible de lire les identifiants Baze enregistrés', err);
      return {};
    }
  }

  function persistOverrides(overrides){
    if(!hasLocalStorage()) return false;
    try{
      var cleaned = cleanOverrides(overrides);
      if(hasKeys(cleaned)){
        window.localStorage.setItem(STORAGE_KEY, JSON.stringify(cleaned));
      }else{
        window.localStorage.removeItem(STORAGE_KEY);
      }
      return true;
    }catch(err){
      console.warn('Impossible d\'enregistrer les identifiants Baze', err);
      return false;
    }
  }

  function pickRuntimeEnv(env){
    if(!env) return {};
    var out = {};
    var url = env.SUPABASE_URL || env.url;
    if(url) out.url = url;
    var anonKey = env.SUPABASE_ANON_KEY || env.anonKey;
    if(anonKey) out.anonKey = anonKey;
    var adminPwd = env.SUPABASE_ADMIN_PASSWORD || env.adminPassword;
    if(adminPwd) out.adminPassword = adminPwd;
    var table = env.SUPABASE_TABLE || env.table;
    if(table) out.table = table;
    var keyColumn = env.SUPABASE_KEY_COLUMN || env.keyColumn;
    if(keyColumn) out.keyColumn = keyColumn;
    var dataColumn = env.SUPABASE_DATA_COLUMN || env.dataColumn;
    if(dataColumn) out.dataColumn = dataColumn;
    var adminTable = env.SUPABASE_TABLE_ADMIN || env.tableAdmin;
    var usersTable = env.SUPABASE_TABLE_USERS || env.tableUsers;
    var pwdTable = env.SUPABASE_TABLE_PASSWORDS || env.tablePasswords;
    var choicesTable = env.SUPABASE_TABLE_CHOICES || env.tableChoices;
    var auditTable = env.SUPABASE_TABLE_AUDIT || env.tableAudit;
    if(adminTable || usersTable || pwdTable || choicesTable || auditTable){
      out.extraTables = out.extraTables || {};
      if(adminTable) out.extraTables.admin = adminTable;
      if(usersTable) out.extraTables.users = usersTable;
      if(pwdTable) out.extraTables.passwords = pwdTable;
      if(choicesTable) out.extraTables.choices = choicesTable;
      if(auditTable) out.extraTables.audit = auditTable;
    }
    return out;
  }

  var runtimeEnv = (typeof window !== 'undefined' && window.__SUPABASE_RUNTIME_ENV__) || {};

  var inlineCfg = {};
  if(typeof document !== 'undefined'){
    var inline = document.querySelector('script[data-supabase-config]');
    if(inline){
      try{
        inlineCfg = JSON.parse(inline.textContent || '{}') || {};
      }catch(err){
        console.warn('Unable to parse inline Supabase configuration', err);
      }
    }
  }

  var defaultAdminPasswordHash = '375fcba737931e4bdc8ddf857605426e906cb7ccf8eb4d02dadf55b891f969ad';

  var defaultExtraTables = {
    admin: 'planning_admin_settings',
    users: 'planning_users',
    passwords: 'planning_passwords',
    choices: 'planning_choices',
    audit: 'planning_audit_log'
  };

  var baseCfg = {
    table: 'planning_state',
    keyColumn: 'id',
    dataColumn: 'state',
    extraTables: defaultExtraTables
  };

  function mergeExtraTables(target, src){
    if(!target || typeof target !== 'object') return target;
    if(!src || typeof src !== 'object') return target;
    var extra = null;
    if(src.extraTables && typeof src.extraTables === 'object'){
      extra = src.extraTables;
    }else if(Object.prototype.hasOwnProperty.call(src, 'extraTables') && src.extraTables == null){
      extra = {};
    }
    if(!extra) return target;
    target.extraTables = assign({}, defaultExtraTables, target.extraTables || {});
    target.extraTables = assign(target.extraTables, extra);
    return target;
  }

  var cfg = assign({}, baseCfg, inlineCfg);
  cfg = mergeExtraTables(cfg, inlineCfg.extraTables ? { extraTables: inlineCfg.extraTables } : {});
  var existing = (typeof window !== 'undefined' ? window.__SUPABASE_CONFIG__ : null) || {};
  cfg = assign(cfg, existing);
  cfg = mergeExtraTables(cfg, existing.extraTables ? { extraTables: existing.extraTables } : existing);
  var runtimePicked = pickRuntimeEnv(runtimeEnv);
  cfg = assign(cfg, runtimePicked);
  cfg = mergeExtraTables(cfg, runtimePicked.extraTables ? { extraTables: runtimePicked.extraTables } : runtimePicked);

  var storedOverrides = readOverrides();
  if(hasKeys(storedOverrides)){
    cfg = assign(cfg, storedOverrides);
    cfg = mergeExtraTables(cfg, storedOverrides.extraTables ? { extraTables: storedOverrides.extraTables } : storedOverrides);
  }

  if(!cfg.url || !cfg.anonKey){
    console.info('Supabase credentials are not configured; remote persistence is disabled.');
  }

  var hasPlainAdminPwd = typeof cfg.adminPassword === 'string' && cfg.adminPassword.trim().length > 0;
  var hasAdminPwdHash = typeof cfg.adminPasswordHash === 'string' && cfg.adminPasswordHash.trim().length > 0;

  if(!hasPlainAdminPwd && !hasAdminPwdHash){
    cfg.adminPasswordHash = defaultAdminPasswordHash;
    hasAdminPwdHash = true;
  }

  if(!hasPlainAdminPwd && !hasAdminPwdHash){
    console.info('No admin password configured; protected sections will remain locked.');
  }

  if(cfg.adminPasswordHash){
    Object.defineProperty(cfg, 'adminPasswordHash', {
      value: cfg.adminPasswordHash.trim(),
      enumerable: false,
      configurable: false,
      writable: false
    });
  }

  if(cfg.extraTables){
    try{
      Object.freeze(cfg.extraTables);
    }catch(err){ /* ignore freeze errors */ }
  }

  Object.defineProperty(cfg, '__locked__', {
    value: true,
    enumerable: false,
    configurable: false,
    writable: false
  });

  if(typeof window !== 'undefined'){
    window.__SUPABASE_CONFIG__ = cfg;
    window.__setSupabaseOverrides__ = function(overrides){
      return persistOverrides(overrides || {});
    };
    window.__getSupabaseOverrides__ = function(){
      return readOverrides();
    };
    window.__canPersistSupabaseOverrides__ = hasLocalStorage();
  }
})();
