# Groupe des Lecteurs NDT

## Déploiement Netlify

Le dossier publié est `public/`. L'API est fournie par la fonction `netlify/functions/api.mjs`; les inscriptions sont enregistrées dans Netlify Blobs.

1. Publier le dépôt sur GitHub et l'importer dans Netlify.
2. Dans **Site configuration → Environment variables**, ajouter :
   - `ADMIN_PHONES` : les numéros autorisés séparés par des virgules, au format ivoirien local de 10 chiffres (ex. `0700000000,0100000000`).
   - `ADMIN_CODE` : un code d'accès unique, long et aléatoire (au moins 20 caractères), à partager uniquement avec les responsables.
   - `SESSION_SECRET` : une chaîne secrète aléatoire d'au moins 32 caractères, différente du code d'accès.
3. Redéployer le site. Netlify Blobs fournit le stockage persistant à la fonction.
4. Vérifier l'inscription de test, la connexion responsable, l'export CSV, puis supprimer l'inscription de test.

Ne jamais mettre les valeurs des variables d'environnement dans les fichiers du dépôt ou dans le code JavaScript public.
Activez l'authentification multifacteur sur le compte Netlify et configurez les protections de trafic/limitation de débit disponibles pour le site. La limite de tentatives de connexion du code s'applique par instance de fonction et ne remplace pas une protection distribuée de la plateforme.

## Tester localement

Installer les dépendances avec `npm install`, puis lancer `npx netlify dev` après avoir renseigné ces variables dans l'environnement local. `npm test` exécute les tests de validation et d'export CSV.