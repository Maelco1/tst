(function(){
  'use strict';

  // Copiez ce fichier en js/config.js puis remplacez les valeurs
  // par celles de votre projet Supabase.
  // ⚠️ Ne versionnez pas vos vraies clés / mots de passe.
  var cfg = window.__SUPABASE_CONFIG__ || {};
  cfg.url = 'https://your-project-ref.supabase.co';
  cfg.anonKey = 'public-anon-key';
  cfg.table = 'planning_state';
  cfg.keyColumn = 'id';
  cfg.dataColumn = 'state';
  cfg.extraTables = {
    admin: 'planning_admin_settings',
    users: 'planning_users',
    passwords: 'planning_passwords',
    choices: 'planning_choices',
    audit: 'planning_audit_log'
  };
  // Idéalement, définissez uniquement le hachage SHA-256 du mot de passe :
  cfg.adminPasswordHash = 'sha256-hex-of-your-password';
  window.__SUPABASE_CONFIG__ = cfg;
})();
