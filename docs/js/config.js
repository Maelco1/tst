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

  var defaultAdminPasswordHash = 'e0f9e8b428dac23ec288ddfaae4dea665c3b8e38257e53d3bf94a5620273b15e';

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
  }
})();
