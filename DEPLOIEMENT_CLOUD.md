# Mise en ligne cloud — Espace Maman Rosa

Adresse de l’établissement : Tshingi-Tshingi n°78, Q/Camp Luka, C/Ngaliema. Téléphone : +243 989 697 763.

Cette archive peut être déployée sur un hébergeur acceptant les conteneurs Docker et un disque persistant.

## Déploiement recommandé sur Render

1. Décompresser l’archive et placer son contenu dans un dépôt GitHub privé.
2. Dans Render, choisir **New > Blueprint** et connecter ce dépôt.
3. Render détectera automatiquement `render.yaml`.
4. Saisir les quatre mots de passe secrets demandés.
5. Valider la création du service payant et du disque persistant de 5 Go.
6. Après le déploiement, vérifier l’adresse `/health`, puis connecter le domaine dans **Settings > Custom Domains**.

Le fichier `render.yaml` configure une seule instance Docker, le contrôle de santé et le disque `/persistent`. Ne passez pas à plusieurs instances tant que SQLite est utilisé.

## Conditions indispensables

- un domaine HTTPS ;
- un disque persistant monté sur `/persistent` ;
- une seule instance de l’application, car la base utilisée est SQLite ;
- les quatre variables de mots de passe définies comme secrets ;
- des sauvegardes externes régulières du volume persistant.

## Variables à configurer

Utiliser les noms présents dans `.env.example`. Ne jamais publier le fichier `.env` réel. En hébergement HTTPS, conserver `MAMAN_ROSA_COOKIE_SECURE=1`.

## Déploiement Docker local de contrôle

1. Copier `.env.example` vers `.env`.
2. Remplacer chaque mot de passe.
3. Exécuter `docker compose up -d --build`.
4. Ouvrir `http://localhost:8080`.
5. Vérifier `http://localhost:8080/health`.

Le fichier `compose.yaml` désactive uniquement l’attribut Secure du cookie pour ce contrôle HTTP local. Sur le cloud HTTPS, définir `MAMAN_ROSA_COOKIE_SECURE=1`.

## Paramètres chez l’hébergeur

- commande de construction : construction du `Dockerfile` ;
- port interne : `8080` ;
- contrôle de santé : `/health` ;
- volume : `/persistent` ;
- nombre d’instances : `1` ;
- redémarrage automatique : activé.

## Sauvegarde et restauration

La base est dans `/persistent/data/maman_rosa.db`. Les sauvegardes sont dans `/persistent/backups`. Avant une restauration, arrêter l’instance, copier la sauvegarde choisie vers `/persistent/data/maman_rosa.db`, puis redémarrer.

## Limite de cette livraison

La version est adaptée à un petit établissement et à une instance unique. Pour plusieurs établissements, plusieurs serveurs cloud ou une forte charge, migrer SQLite vers PostgreSQL et remplacer l’enregistrement global de l’état par des tables métier séparées.
