# Planning des gardes

Application front-end monopage destinée à la saisie, à l'attribution et au suivi des gardes médicales.
Elle fonctionne entièrement côté client et persiste désormais l'état applicatif dans une base Supabase,
ce qui autorise un usage multi-utilisateur synchronisé.

## Structure du projet

```
/docs          # contenu statique publié sur GitHub Pages
  css/
  js/
  index.html
```

L'application est servie directement depuis le répertoire `docs`, ce qui permet d'activer facilement
GitHub Pages (source « Docs / » dans les paramètres du dépôt).

## Configuration Supabase

1. Créez un projet Supabase et provisionnez les tables décrites dans `docs/supabase-schema.sql` afin
   de stocker l'état global (`planning_state`) ainsi que les vues dérivées (utilisateurs, mots de
   passe, choix publiés, audit). Le script peut être exécuté tel quel depuis la console SQL de
   Supabase. Il contient également un jeu de données de démarrage qui ajoute un planning par défaut
   (`planning_gardes_state_v080`) avec un compte administrateur (`admin` / `Melatonine`) que vous
   pourrez modifier par la suite.
2. Copiez `docs/js/config.example.js` vers `docs/js/config.js` puis remplissez les valeurs (`url`,
   `anonKey`, `adminPassword`, etc.) avec celles de votre projet. Vous pouvez adapter les noms des
   tables Supabase dans la propriété `extraTables`. Ne versionnez jamais vos secrets dans le dépôt.
3. Activez **Supabase Realtime** sur la table principale (`planning_state`) afin que chaque poste
   reçoive instantanément les modifications effectuées par les autres utilisateurs (section
   « Realtime » des paramètres de la table, cochez `INSERT` et `UPDATE`).
4. Pour déployer sur un autre environnement, vous pouvez :
   - définir des valeurs personnalisées dans `index.html` via le script
     `<script type="application/json" data-supabase-config>...</script>` ;
   - exposer à l'exécution un objet `window.__SUPABASE_RUNTIME_ENV__` contenant les propriétés
     `SUPABASE_URL`, `SUPABASE_ANON_KEY` et `SUPABASE_ADMIN_PASSWORD` (pratique lorsque l'hébergeur
     injecte des variables d'environnement) ;
   - modifier directement `docs/js/config.js` en adaptant l'URL et la clé publique.
   Les différentes sources sont fusionnées automatiquement, `window.__SUPABASE_RUNTIME_ENV__` puis
   `config.js` ayant priorité sur la configuration inline.

Sans configuration Supabase valide, l'application fonctionne mais les données sont perdues à chaque
rechargement puisqu'aucun stockage local n'est utilisé. Sans mot de passe administrateur défini,
les écrans protégés (admin et récapitulatif) restent verrouillés. Lorsque Supabase est configuré,
l'ensemble des paramètres administrateur, des comptes et des choix est envoyé vers les tables
distantes, ce qui permet un fonctionnement 100 % multi-utilisateur.

## Développement local

Aucun outil de build n'est requis : ouvrez `docs/index.html` dans votre navigateur ou servez le dossier
avec un serveur HTTP statique.

```bash
# Exemple avec npx serve
npx serve docs
```

## Déploiement sur GitHub Pages

1. Validez vos modifications et poussez-les sur la branche par défaut.
2. Dans **Settings → Pages**, choisissez **Deploy from a branch**, puis sélectionnez votre branche (par
   exemple `main`) et le dossier **/docs**. C'est ce dossier qui contient `index.html` ; GitHub Pages
   servira automatiquement ce fichier plutôt que `README.md`.
3. Cliquez sur **Save** : un workflow de déploiement est lancé et publie le site statique.
4. Une fois le déploiement terminé, l'application est disponible à l'URL fournie par GitHub Pages.

💡 Si vous voyez encore le contenu du `README.md` sur votre Page, vérifiez que le dossier sélectionné
dans les paramètres est bien `docs/` et que le build précédent est terminé. Vous pouvez aussi forcer un
nouveau déploiement en effectuant un commit vide : `git commit --allow-empty -m "Trigger Pages"` puis
`git push`.

Pensez à pousser le fichier `docs/js/config.js` avec les valeurs Supabase adaptées à votre environnement
(si vous utilisez Supabase en production).

## Licence

Ce projet est fourni « tel quel ». Adaptez-le selon vos besoins et ajoutez une licence si nécessaire.
