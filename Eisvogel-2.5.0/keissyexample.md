---
title: "Hackazon Website Pentest"
author: 
  - "Keissy Bod"
  - "Milan Pouteau"
date: "October 2024"
titlepage: true,
titlepage-text-color: "FFFFFF"
titlepage-rule-color: "360049"
titlepage-rule-height: 0
titlepage-background: "background.pdf"
---

# SOMMAIRE

1. [Préambule](#préambule)
    1.1 [Présentation des résultats](#présentation-des-résultats)  
    1.2 [Contexte](#contexte)  
    1.3 [Pilotage de la prestation](#pilotage-de-la-prestation)  
    1.4 [Actions de nettoyage recommandées](#actions-de-nettoyage-recommandées)

2. [Synthèse Managériale](#synthèse-managériale)
    2.1 [Synthèse générale](#synthèse-générale)
    2.2 [Synthèse des risques](#synthèse-des-risques)
    2.3 [Synthèse des vulnérabilités et recommandations](#synthèse-des-vulnérabilités-et-recommandations)
    2.4 [Remarques](#remarques)

3. [Synthèse Technique](#synthèse-technique)

4. [Test d'intrusion externe et applicatif](#test-dintrusion-externe-et-applicatif)

    4.1 [Évaluation infrastructure](#évaluation-infrastructure)
        4.1.1 [Réseau](#réseau)
        4.1.2 [Services](#services)

    4.2 [Application web](#application-web)  
        4.2.2 [Évaluation application](#évaluation-application)  
            - Collecte d'informations  
            - Configuration et mécanismes de déploiement  
            - Gestion des identités  
            - Authentification  
            - Autorisations  
            - Gestion des sessions  
            - Validation des entrées utilisateurs  
            - Gestion des erreurs  
            - Cryptographie  
            - Processus métier  
            - Côté client

5. [Annexe](#annexe)  
    5.1 [Présentation de la démarche](#présentation-de-la-démarche)  
    5.2 [Présentation des résultats](#présentation-des-résultats-annexe)
    5.3 [Terminologie des risques](#terminologie-des-risques)


# 1. Préambule

## 1.1 Présentation des résultats
La sécurité globale de l'application web auditée présente plusieurs points d'amélioration notables. L'audit a révélé que certains logiciels utilisés par l'application sont en version dépassée, ce qui expose le système à des vulnérabilités connues. De plus, plusieurs types d'injections, telles que des injections SQL ou des XSS, ont été détectés, indiquant des points d'entrée potentiels pour des attaques exploitant des données malveillantes.

Des problèmes de segmentation ont également été identifiés, avec des configurations de sécurité essentielles qui ne sont pas appliquées, comme l'absence des attributs Secure, HttpOnly, et SameSite sur les cookies de session, augmentant les risques d'attaques liées à la session. Par ailleurs, l'application présente un manque de contrôle d'accès dans certaines parties du système, permettant l'affichage non autorisé de fichiers sensibles, tels que /app/hackazon.apk, ce qui peut conduire à des risques d'exposition de données ou de fonctionnalités non prévues pour le public.

Enfin, l'audit a mis en évidence l'absence de protection CSRF sur certaines parties du site, ce qui pourrait permettre à des attaquants de manipuler des actions au nom des utilisateurs sans leur consentement. Nous recommandons de mettre en place des correctifs pour ces aspects afin d'assurer une meilleure sécurité et de renforcer la protection des données utilisateurs et de l'infrastructure de l'application.



## 1.2 Contexte

Dans le cadre de cette mission, il nous a été demandé de réaliser un test d'intrusion sur l'application web **Hackazon** accessible via l'URL [https://hackazon.trackflaw.com/](https://hackazon.trackflaw.com/). Hackazon est une plateforme de test et d'évaluation de la sécurité, souvent utilisée pour simuler des scénarios d'attaques web afin d'améliorer les pratiques de sécurisation des applications.

Le test d'intrusion avait pour objectif d’identifier les vulnérabilités potentielles de l’application et de fournir des recommandations en matière de sécurité. Ce test s'inscrit dans une démarche d'amélioration continue de la sécurité de l'infrastructure et des applications exposées à des utilisateurs externes.

### Objectifs principaux :
- Identifier et analyser les vulnérabilités présentes sur l’application web Hackazon.
- Évaluer la sécurité de l'infrastructure sous-jacente (serveurs, services réseau).
- Proposer des recommandations pour la remédiation des vulnérabilités détectées.

### Portée du test :
Le test a principalement couvert deux aspects :

1. **L'infrastructure** : Évaluation de la configuration réseau, des services exposés, et des mécanismes de protection en place.

2. **L’application web** : Analyse des points d’entrée de l'application, de la gestion des identités, des sessions, et des mécanismes de validation des entrées utilisateurs.


### Contraintes :
- Le temps alloué pour cette prestation était limité, ce qui a restreint l’analyse exhaustive de tous les points d’entrée possibles.
- Aucun accès aux codes sources de l'application ou aux serveurs hébergeant l'application n'a été fourni. Le test a été réalisé dans une approche « boîte noire », simulant l'attaque d'un utilisateur malveillant sans connaissances internes sur l'application.


## 1.3 Pilotage de la Prestation

Le pilotage de cette mission a suivi une approche structurée afin d'assurer une exécution fluide et alignée sur les attentes du client. Le test d’intrusion a été réalisé en plusieurs phases, chacune encadrée par des points de contact réguliers avec le client pour garantir la transparence et la bonne progression du projet.

### Phases de la mission :
1. **Phase de préparation** :
   - Recueil des besoins du client et définition du périmètre du test.
   - Planification des outils et méthodes à utiliser pour le test d'intrusion.
   - Configuration d’un environnement sécurisé pour l'exécution des tests.

2. **Phase de tests** :
   - Réalisation des tests d’intrusion en suivant une approche **boîte noire**, simulant le comportement d’un attaquant sans accès aux informations internes.
   - Utilisation d’outils automatisés et manuels pour identifier les vulnérabilités potentielles, notamment :
     - Outils de scan de vulnérabilités (ex. **SQLMap**, **Nmap**).
     - Analyse manuelle des points d’entrée utilisateur et des services exposés.

3. **Phase d’analyse** :
   - Analyse approfondie des résultats obtenus durant les tests pour en extraire les vulnérabilités les plus critiques.
   - Classement des vulnérabilités selon leur impact, leur facilité d’exploitation et leur sévérité.

4. **Phase de restitution** :
   - Présentation des résultats sous forme de rapport détaillé, incluant les vulnérabilités détectées et les recommandations associées.
   - Discussion avec le client pour clarifier certains points, notamment les priorités en matière de remédiation.

### Points de contact et communication :

- Un compte-rendu final a été livré sous forme de rapport détaillé, avec une synthèse managériale et une synthèse technique.



## 1.4 Actions de nettoyage recommandées
Suite à cet audit plusieurs action de néttoyage sont à prévoir. 
- C'est d'abord, la suppréssion des différents comptes utilisateurs et leur fichier respectifs  créé soit : pentest1 et pentest2. 
- C'est ensuite la suppréssion des difféntes demande Helpdesk comprenant les id : 29, 28, 27, 26, 25, 24, 23 et 22
- Un nettoyage des commentaire sur la FAQ est aussi à prévoir 
- Une suppréssion des review sur l'article id=81
- La suppression de toutes les commandes faites par les comptes pentest1 et pentest2

# 2. Synthèse Managériale

## 2.1 Synthèse générale

> FIXME: General summary of the findings and their potential impact on the business.

## 2.2 Synthèse des risques

> FIXME: Overview of the risks identified, categorized by severity and potential impact.

## 2.3 Synthèse des vulnérabilités et recommandations

> FIXME: Summary of vulnerabilities found and the recommended actions to mitigate them.

## 2.4 Remarques

> FIXME: Any additional comments or notes for management.

# 3. Synthèse Technique

> FIXME: A detailed technical summary of the findings, highlighting specific vulnerabilities, misconfigurations, and security gaps in the Hackazon web application.

# 4. Test d'intrusion externe et applicatif

## 4.1 Évaluation infrastructure

### 4.1.1 Réseau

> FIXME: Findings from the network evaluation.

### 4.1.2 Services

> FIXME: Evaluation of the services exposed by the infrastructure.

## 4.2 Application web

### 4.2.2 Évaluation application

#### Collecte d'informations


#### Configuration et mécanismes de déploiement

#### <b>Mauvaise configuration du fichier cross-domain.xml (Flash)</b>

L'audit a révélé une mauvaise configuration du fichier cross-domain.xml sur le serveur. Ce fichier permet à des domaines externes de communiquer avec des ressources internes, et une configuration trop permissive peut entraîner des risques de sécurité, notamment des attaques de type Cross-Site Scripting (XSS) ou de vol de données.

| VULN-CROSSDOMAIN | Mauvaise configuration du fichier cross-domain.xml |                               |              |
|------------|--------------------------------------------|-------------------------------|--------------|
| **État**   | **Impact**                                 | **Difficulté d'exploitation** | **Sévérité** |
| Avérée     | Moyen                                     | Modéré                        | 1 / 4        |

Le fichier cross-domain.xml présent sur le serveur autorise des connexions provenant de domaines non sécurisés ou tiers. Cela permet à des applications externes de demander des ressources internes, ce qui pourrait être exploité par un attaquant pour contourner les mécanismes de sécurité habituels et accéder à des données sensibles ou lancer des attaques ciblées contre les utilisateurs de l'application.

![Cross-domain file](Vulns/Manque%20de%20sécurité%20configuration%20flash/cross-domain.png)

La capture d'écran ci-dessus montre un exemple de fichier cross-domain.xml avec des autorisations trop larges permettant des requêtes cross-domain non sécurisées.

| VULN-CROSSDOMAIN | Recommandation : Restreindre les autorisations dans le fichier cross-domain.xml |
| ------- | ----------------------------------------------------------------- |
| **Complexité estimée** : Faible | **Travail/coût estimé** : Faible | **Priorité estimée** : 2 / 4 |
-----------------------------------------------------------------------------
| **Recommandation** : Il est recommandé de sécuriser le fichier cross-domain.xml en appliquant les bonnes pratiques suivantes :
-  1. Limiter les domaines autorisés : Spécifier explicitement les domaines externes de confiance qui peuvent accéder aux ressources, et éviter l'utilisation de l'astérisque (*) qui autorise tous les domaines.
-  2. Restreindre les types de requêtes autorisées : Permettre uniquement les types de requêtes qui sont absolument nécessaires pour les services externes.
-  3. Supprimer ou désactiver le fichier si non utilisé : Si le fichier cross-domain.xml n'est pas requis, il est préférable de le supprimer pour éviter tout risque de sécurité.|


#### <b>Versions dépréciées de logiciels utilisés (PHP, jQuery, Flash, Mysql)</b>

L'audit a identifié que certaines technologies utilisées par l'application sont des versions obsolètes et ne sont plus maintenues. L'utilisation de versions dépréciées expose l'application à des vulnérabilités connues et augmente les risques d'attaques ciblées.

| VULN-IDOR | Non vérification des accès à certaines ressources |                               |              |
|-----------|---------------------------------------------------|-------------------------------|--------------|
| **État**  | **Impact**                                        | **Difficulté d'exploitation** | **Sévérité** |
| Avérée    | Élevé                                             | Modéré                        | 3 / 4        |

Il a été observé que l'application utilise une version ancienne de PHP, une version obsolète de jQuery, ainsi que Flash, qui est officiellement déprécié et ne reçoit plus de mises à jour de sécurité. Ces versions dépréciées contiennent souvent des vulnérabilités connues que les attaquants peuvent exploiter pour compromettre la sécurité de l'application.

![version de flash](Vulns/Version%20déprécié/flash.png)
![version de php](Vulns/Version%20déprécié/php.png)
![version de jquery](Vulns/Version%20déprécié/jquery.png)
![version de mysql](Vulns/Version%20déprécié/mysql.png)


La capture d'écran ci-dessus montre les résultats d'une analyse des versions logicielles, mettant en évidence les composants dépassés utilisés par l'application.

| VULN-OUTDATED-VERSIONS | Recommandation : Mettre à jour vers des versions supportées et sécurisées |
| ------- | ----------------------------------------------------------------- |
| **Complexité estimée** : Modéré | **Travail/coût estimé** : Modéré à Élevé | **Priorité estimée** : 3 / 4 |
-----------------------------------------------------------------------------
| **Recommandation** : Pour assurer la sécurité et la stabilité de l'application, il est recommandé de mettre à jour les composants logiciels concernés. La mise à jour vers une version récente et supportée de PHP, jQuery, et MySQL permettra de bénéficier des dernières améliorations de sécurité, corrigeant les vulnérabilités présentes dans les versions obsolètes. Concernant Flash, étant donné que son support est complètement abandonné, il est préférable de le remplacer par des technologies modernes telles que HTML5 ou JavaScript afin d'éviter toute exposition aux risques liés à son utilisation.|

#### Gestion des identités

#### <b>Accès à des ressources n'appartenant pas à l'utilisateur (IDOR).</b>

Les paramètres et champs utilisateur ont été testé afin de déceler de potentilles vulnérabilités de référence d'objet directe non sécurisée (IDOR)


| VULN-IDOR | Non vérification des accès à certaines ressources |                               |              |
|-----------|---------------------------------------------------|-------------------------------|--------------|
| **État**  | **Impact**                                        | **Difficulté d'exploitation** | **Sévérité** |
| Avérée    | Mineur                                            | Facile                        | 2 / 4        |




l'étude à démontré qu'un problème d'autorisation était présent sur la fonctionnalité d'affichage des commandes utilisateur.

![iDOR commande utilisateur](Vulns/iDOR/screen_order.png)

Sur la capture d'écran si-dessus nous avons pu accèder à la commande d'une personne tierse qui n'appartenait pas à l'utisateur utilisé lors du test. L'attaque est possible en changeant arbitrairement le numéro de commande dans l'url.

Voici la requête vulnérable:

```
GET /account/orders/10000021 HTTP/2
Host: hackazon.trackflaw.com
Cookie: PHPSESSID=XXXXXXXXXXXXXXXXXXXXXXX; visited_products=%2C81%2C102%2C16%2C
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://hackazon.trackflaw.com/account
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
```
Le cookie de session PHPSESSID à été volontairement remplacé par des 'X'. 

###### En suivant cette methodologie d'autre problème d'autorisation on été trouvé 
l'étude à démontré qu'un problème d'autorisation était présent sur la fonctionnalité d'affichage des des ticket du helpdesk.

![iDOR ticket utilisateur](Vulns/iDOR/screen_helpdesk.png)

Sur la capture d'écran si-dessus nous avons pu accèder au ticket d'une personne tierse qui n'appartenait pas à l'utisateur utilisé lors du test. L'attaque est possible en changeant arbitrairement le numéro de ticket dans le body de la requete POST. Dans la requête ci-dessous le numéro à modifier est le dernier soit le 21.

Voici la requête vulnérable:

```
POST /helpdesk/HelpdeskService HTTP/2
Host: hackazon.trackflaw.com
Cookie: visited_products=%2C64%2C72%2C1%2C81%2C; PHPSESSID=XXXXXXXXXXXXXXXXXXXXXX
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0
Accept: */*
Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate, br
Content-Type: text/x-gwt-rpc; charset=utf-8
X-Gwt-Permutation: D9E6FA1B6C016BB53C508E629B022D27
X-Gwt-Module-Base: https://hackazon.trackflaw.com/helpdesk/
Content-Length: 170
Origin: https://hackazon.trackflaw.com
Referer: https://hackazon.trackflaw.com/helpdesk/
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
X-Pwnfox-Color: red
Te: trailers

7|0|5|https://hackazon.trackflaw.com/helpdesk/|5861BBAC393F609060A1E4008EC18E2B|com.ntobjectives.hackazon.helpdesk.client.HelpdeskService|getEnquiryById|I|1|2|3|4|1|5|21|
```
Le cookie de session PHPSESSID à été volontairement remplacé par des 'X'. 

###### Un dernier problème d'autorisation à été trouvé

![iDOR whishlist utilisateur](Vulns/iDOR/screen_whishlist.png)

Sur la capture d'écran si-dessus nous avons pu accèder à la whishlist d'une personne tierse qui n'appartenait pas à l'utisateur utilisé lors du test. L'attaque est possible en changeant arbitrairement le numéro dans le chemin de l'url.

Voici la requête vulnérable:

```
GET /wishlist/view/2 HTTP/2
Host: hackazon.trackflaw.com
Cookie: visited_products=%2C64%2C72%2C1%2C81%2C; PHPSESSID=XXXXXXXXXXXXXXXXXXXXXX
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate, br
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
X-Pwnfox-Color: red
Priority: u=0, i
Te: trailers
```
Le cookie de session PHPSESSID à été volontairement remplacé par des 'X'. 


| VULN-IDOR | Recommandation : Implémenter des contrôles d'accès rigoureux |
| ------- | ----------------------------------------------------------------- |
| **Complexité estimée** : Modéré | **Travail/coût estimé** : Modéré | **Priorité estimée** : 2 / 4 |
-----------------------------------------------------------------------------
| **Recommandation** : Il est recommandé d'implémenter des contrôles d'accès rigoureux : Chaque requête effectuée par un utilisateur doit vérifier si celui-ci est autorisé à accéder aux ressources demandées. Cette vérification doit être appliquée côté serveur, indépendamment des paramètres fournis par l'utilisateur. |

#### Authentification

#### <b>Absence de fonctionnalité de changement de mot de passe</b>

Il a été constaté que l'application ne propose pas de fonctionnalité permettant aux utilisateurs de modifier leur mot de passe. Cette absence représente un problème important en matière de sécurité, car elle empêche les utilisateurs de sécuriser leur compte de manière proactive en cas de suspicion de compromission ou simplement pour renforcer la sécurité de leurs informations d'authentification.

| VULN-NO-PASSWORD-CHANGE | Absence de fonctionnalité de changement de mot de passe |     |              |
|------------|--------------------------------------------|-------------------------------|--------------|
| **État**   | **Impact**                                 | **Difficulté d'exploitation** | **Sévérité** |
| Avérée     | Modéré                                     | Facile                        | 2 / 4        |

L'absence de cette fonctionnalité empêche les utilisateurs de réagir efficacement en cas de perte de sécurité de leur mot de passe. De plus, elle empêche l'application de forcer des changements de mot de passe périodiques ou suite à un incident de sécurité potentiel.


![Interface utilisateur](Vulns/Pas%20de%20fonctionnalité%20de%20changement%20de%20mot%20de%20passe/user%20interface.png)

La capture d'écran ci-dessus montre que l'interface utilisateur ne propose aucun lien ou bouton permettant de changer le mot de passe, ce qui laisse les utilisateurs bloqués avec leur mot de passe initial.

| VULN-NO-PASSWORD-CHANGE | Recommandation : Ajouter une fonctionnalité de changement de mot de passe |
| ------- | ----------------------------------------------------------------- |
| **Complexité estimée** : Modéré | **Travail/coût estimé** : Modéré | **Priorité estimée** : 2 / 4 |
-----------------------------------------------------------------------------
| **Recommandation** : Il est recommandé d'ajouter une fonctionnalité de changement de mot de passe pour les utilisateurs. Cette fonctionnalité doit inclure les éléments suivants :
-  1. Option accessible dans le profil utilisateur : Un lien ou un bouton permettant aux utilisateurs de modifier leur mot de passe directement depuis leur espace personnel. 
-  2. Demande de mot de passe actuel avant le changement : Afin de confirmer l'identité de l'utilisateur et de prévenir les abus, l'application doit demander le mot de passe actuel avant de permettre un changement.
- 3. Un jeton csrf afin de protéger le rejeu de requête et éviter de future vulnérabilité |

#### Autorisations

####  <b> Création d'un jeton API ouvert à tous les utilisateurs </b>

Un manque d'autorisation à été trouvé dans la demande d'un jeton api. 

| VULN-TOKEN | Droit de demande de jeton api trop laxiste |                               |              |
|------------|--------------------------------------------|-------------------------------|--------------|
| **État**   | **Impact**                                 | **Difficulté d'exploitation** | **Sévérité** |
| Avérée     | Mineur                                     | Facile                        | 1 / 4        |

Aucune vérification du niveau de droit n'est fait lors de la demande d'un token api.

![Demande token API](Vulns/demande_token/screen.png)

Sur la capture d'écran si-dessus nous avons pu demander un token api en fournissant nos informations de connexion utilisateur basique. 

| VULN-TOKEN | Recommandation : Implémenter un contrôle d'accès basé sur le rôle  |
| ------- | ----------------------------------------------------------------- |
| **Complexité estimée** : Faible | **Travail/coût estimé** : Faible | **Priorité estimée** : 1 / 4 |
-----------------------------------------------------------------------------
| **Recommandation** : Il est recommandé d'implémenter des contrôles d'accès rigoureux : Chaque requête effectuée par un utilisateur doit vérifier si celui-ci est autorisé à accéder aux ressources demandées. Cette vérification doit être appliquée côté serveur, indépendamment des paramètres fournis par l'utilisateur. |
-----------------------------------------------------------------------------|


#### Gestion des sessions

> FIXME: Review of session management mechanisms (e.g., session cookies, timeout policies).

#### Validation des entrées utilisateurs

##### Open Redirect
##### VULN-XX : VULNERABILITY TITLE

| **État**     | **Impact** | **Difficulté d'exploitation** | **Sévérité** |
|--------------|------------|------------------------------|--------------|
| **Avérée**   | **Majeur** | **Facile**                    | **4 / 4**    |



| VULN-02 | Vulnérabilité : Application vulnérable à une redirection ouverte |
| ------- | --------------------------------------------------------------- |
| **Avérée** | **Impact** : Modéré | **Difficulté d'exploitation** : Facile | **Sévérité** : 3 / 4 |
| **Description** : L’application permet de rediriger l’utilisateur vers un site externe après l’achat d’un item si l’utilisateur n’est pas connecté. Ce comportement peut être exploité pour rediriger les utilisateurs vers des sites malveillants, en manipulant le paramètre `return_url`. |
| **Requête** :  GET /user/login?return_url=https://google.com HTTP/2 |

```
GET /user/login?return_url=https://google.com HTTP/2
	Host: hackazon.trackflaw.com
	Cookie: PHPSESSID=883e17745fa4e1c535218812b0ee20ee; visited_products=%2C81%2C102%2C16%2C
	User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0
	Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
	Accept-Language: en-US,en;q=0.5
	Accept-Encoding: gzip, deflate, br
	Upgrade-Insecure-Requests: 1
	Sec-Fetch-Dest: document
	Sec-Fetch-Mode: navigate
	Sec-Fetch-Site: none
	Sec-Fetch-User: ?1
	X-Pwnfox-Color: red
	Priority: u=0, i
	Te: trailers


```

---

### Remediation Table

```markdown
| VULN-02 | Recommandation : Filtrer et valider les paramètres de redirection |
| ------- | ----------------------------------------------------------------- |
| **Complexité estimée** : Faible | **Travail/coût estimé** : Faible | **Priorité estimée** : 3 / 4 |
| **Recommandation** : Il est recommandé de valider strictement les URL de redirection pour s’assurer qu’elles pointent uniquement vers des destinations légitimes ou internes à l’application. Il est possible d’implémenter une liste blanche des domaines autorisés afin d’éviter les redirections non sécurisées vers des sites externes. |
```


#### Gestion des erreurs

> FIXME: Review of how the application handles errors (e.g., verbose error messages).

#### Cryptographie

**Mauvaise configuration SSL**

\begin{table}[htbp]
\centering
\renewcommand{\arraystretch}{1.5} % Augmente l'espacement entre les lignes
\begin{tabular}{|>{\centering\arraybackslash}p{4cm}|>{\centering\arraybackslash}p{4cm}|>{\centering\arraybackslash}p{4cm}|>{\centering\arraybackslash}p{3cm}|}
\hline
\multicolumn{4}{|>{\columncolor{red}\centering\arraybackslash}p{16.30cm}|}{\textcolor{white}{\textbf{VULN-SSL : Mauvaise configuration SSL}}} \\ \hline
\rowcolor{gray!30}
\textbf{\textcolor{black}{État}} & \textbf{Impact} & \textbf{Difficulté d'exploitation} & \textbf{Sévérité} \\ \hline
\textbf{Avérée} & \textbf{Moyen} & \textbf{Modéré} & \textbf{2 / 4} \\
\hline
\end{tabular}
\end{table}

Lors de l'audit, des problèmes de configuration SSL ont été identifiés, affectant la sécurité des communications entre les utilisateurs et le serveur, augmentant ainsi le risque d'attaques de type "Man-in-the-Middle" (MITM). L'absence de HSTS et l'utilisation de suites de chiffrement faibles sont deux points critiques qui compromettent la sécurité des connexions.

---

![Manque HSTS](Vulns/Mauvaise%20configuration%20ssl/hsts.png)

![Suites de chiffrement faibles](Vulns/Mauvaise%20configuration%20ssl/faible%20cipher%20authorisé.png)

Les captures d'écran ci-dessus montrent les résultats d'un scan SSL, révélant l'absence de HSTS et la prise en charge de suites de chiffrement obsolètes.

---

**Remediation**

\begin{table}[htbp]
\centering
\renewcommand{\arraystretch}{1.5} % Augmente l'espacement entre les lignes
\begin{tabular}{|>{\centering\arraybackslash}p{5cm}|>{\centering\arraybackslash}p{5cm}|>{\centering\arraybackslash}p{5cm}|}
\hline
\multicolumn{3}{|>{\columncolor{cyan}\centering\arraybackslash}p{16.30cm}|}{\textcolor{white}{\textbf{VULN-SSL : Recommandation pour sécuriser la configuration SSL}}} \\ \hline
\textbf{Complexité estimée : Faible} & \textbf{Travail/coût estimé : Faible} & \textbf{Priorité estimée : 2 / 4} \\
\hline
\multicolumn{3}{|p{16.30cm}|}{
    Il est recommandé de renforcer la configuration SSL en appliquant les actions suivantes :
    1. Activer HSTS : Permet de forcer les navigateurs à utiliser des connexions HTTPS uniquement, même si une tentative est faite en HTTP. Cela protège contre les attaques de redirection et de downgrade.
    2. Désactiver les suites de chiffrement faibles : Les protocoles et ciphers obsolètes (par exemple, TLS 1.0, TLS 1.1, et des ciphers RC4) doivent être désactivés pour empêcher les attaques exploitant ces algorithmes faibles.
    3. Configurer une liste de ciphers robustes et modernes : Utiliser uniquement des ciphers modernes et recommandés tels que AES-GCM avec TLS 1.2 ou supérieur.
} \\
\hline
\end{tabular}
\end{table}



#### Processus métier

> FIXME: Assessment of business logic flaws.

#### Côté client

> FIXME: Client-side vulnerabilities (e.g., JavaScript security, DOM-based XSS).

# 5. Annexe

## 5.1 Présentation de la démarche

La démarche adoptée pour ce test d’intrusion s’inscrit dans une méthodologie de sécurité éprouvée, basée sur les bonnes pratiques en matière de tests de pénétration. Ce test a été réalisé en suivant une approche **boîte noire**, simulant un attaquant sans connaissance préalable des infrastructures internes de l’application Hackazon.

Le test s’est déroulé en plusieurs étapes, chaque phase étant conçue pour identifier et exploiter les vulnérabilités potentielles dans l’infrastructure et l'application web.

### Méthodologie suivie :

1. **Collecte d’informations** (*Reconnaissance*) :
   - L’objectif de cette première phase est d’acquérir le maximum d’informations sur l’infrastructure et l’application ciblée. Des techniques de reconnaissance passive et active ont été employées pour découvrir les technologies utilisées, les points d’entrée potentiels, ainsi que les services exposés.
   - Outils utilisés : **Nmap**, **Whois**, **Google Dorking**, et divers outils de reconnaissance open-source.

2. **Analyse des vulnérabilités** (*Scanning*) :
   - Cette phase consiste à identifier les vulnérabilités potentielles sur les services exposés et les points d’entrée de l’application web. Un audit approfondi a été réalisé pour détecter des failles telles que les injections SQL, les failles XSS, les mauvaises configurations de serveur, ou encore la gestion incorrecte des sessions.
   - Outils utilisés : **Burp Suite**, **OWASP ZAP**, **SQLMap**.

3. **Exploitation des vulnérabilités** (*Exploitation*) :
   - Lors de cette étape, les vulnérabilités détectées sont exploitées afin de démontrer leur impact réel. Cela inclut l’extraction de données sensibles, la compromission de comptes utilisateurs, ou encore le contournement des mécanismes de sécurité.
   - Des preuves de concept (PoC) ont été fournies pour les vulnérabilités les plus critiques afin de montrer leur faisabilité.

4. **Post-exploitation et recommandations** :
   - Une fois les vulnérabilités exploitées, une analyse plus approfondie est réalisée pour déterminer l’étendue des dommages potentiels. Cette phase permet également de formuler des recommandations précises sur les correctifs à apporter pour chaque vulnérabilité identifiée.
   - Outils utilisés : **SQLMap** pour la récupération des bases de données, **Burp Suite** pour l’analyse des réponses serveur.

### Limites et contraintes :

- Le test a été réalisé dans des conditions de temps limitées, ce qui a restreint l'exploration exhaustive de toutes les fonctionnalités de l’application.
- L’approche **boîte noire** ne permet pas d’explorer certaines vulnérabilités internes ou logicielles, qui auraient pu être visibles avec un accès direct au code source ou aux environnements de développement.


## 5.2 Présentation des résultats

> FIXME: Additional detailed results, if necessary.

## 5.3 Terminologie des risques

> FIXME: Glossary of risk-related terms used in the report.
