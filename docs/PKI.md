
## PKI.md

# Création d'une PKI Privée avec OpenSSL sous Linux 🛠️

Ce guide détaille la mise en place d'une Infrastructure à Clé Publique (PKI) privée en utilisant l'outil **OpenSSL** sous un environnement Linux. Il couvre la création d'une Autorité de Certification (CA), d'un certificat serveur avec **Subject Alternative Name (SAN)**, et d'un certificat client pour l'**Authentification Mutuelle TLS**.

-----

## 1\. Préparation de l'Environnement

Nous allons créer une structure de dossiers pour organiser les clés et certificats de manière sécurisée.

```bash
mkdir -p private_pki
cd private_pki
mkdir ca server client
```

| Dossier | Contenu |
| :--- | :--- |
| `ca` | Clé privée (`ca.key`) et certificat racine (`ca.crt`) de la CA. |
| `server` | Clé, CSR et certificat pour le serveur. |
| `client` | Clé, CSR et certificat pour le client. |

-----

## 2\. Création de l'Autorité de Certification (CA) Racine

La CA est la racine de confiance de votre PKI.

### 2.1. Génération de la Clé Privée de la CA

Génère une clé RSA de 2048 bits chiffrée avec AES-256. Vous devrez définir une **phrase secrète** (*passphrase*) pour sécuriser cette clé.

```bash
openssl genrsa -aes256 -out ca/ca.key 2048
```

### 2.2. Création du Certificat Racine Auto-Signé

Crée le certificat racine (`ca.crt`), valide 10 ans, à partir de la clé.

```bash
openssl req -x509 -new -nodes -key ca/ca.key -sha256 -days 3650 -out ca/ca.crt -subj "/CN=Ma Racine PKI Privee/O=Mon Organisation/C=FR"
```

-----

## 3\. Création du Certificat Serveur

Ce certificat est destiné à l'authentification du serveur (ex: serveur web, API).

### 3.1. Génération de la Clé Privée Serveur et du CSR

```bash
# Génération de la clé privée
openssl genrsa -out server/server.key 2048

# Création de la Requête de Signature (CSR)
openssl req -new -key server/server.key -out server/server.csr -subj "/CN=mon.serveur.interne/O=Mon Organisation/C=FR"
```

### 3.2. Création du Fichier de Configuration Serveur (`server.ext`)

Créez le fichier `server/server.ext` pour inclure les extensions cruciales : `serverAuth` (usage) et les **SAN** (Subject Alternative Name).

```ini
# server/server.ext
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
DNS.2 = *.domain.x
```

### 3.3. Signature du Certificat Serveur par la CA

Signe le CSR avec la clé de la CA, en appliquant les extensions du fichier `server.ext`.

```bash
openssl x509 -req -in server/server.csr \
    -CA ca/ca.crt \
    -CAkey ca/ca.key \
    -CAcreateserial \
    -out server/server.crt \
    -days 365 \
    -sha256 \
    -extfile server/server.ext
```

-----

## 4\. Création du Certificat Client (Authentification Mutuelle)

Ce certificat sera utilisé par un client pour s'authentifier auprès du serveur lors d'une session TLS mutuelle.

### 4.1. Génération de la Clé Privée Client et du CSR

```bash
# Génération de la clé privée
openssl genrsa -out client/client.key 2048

# Création de la Requête de Signature (CSR)
openssl req -new -key client/client.key -out client/client.csr -subj "/CN=utilisateur.vpn.01/O=Mon Organisation/C=FR"
```

### 4.2. Création du Fichier de Configuration Client (`client.ext`)

Créez le fichier `client/client.ext` pour spécifier l'usage pour l'**Authentification Client** (`clientAuth`).

```ini
# client/client.ext
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
```

### 4.3. Signature du Certificat Client par la CA

Signe le CSR client avec la clé de la CA.

```bash
openssl x509 -req -in client/client.csr \
    -CA ca/ca.crt \
    -CAkey ca/ca.key \
    -CAcreateserial \
    -out client/client.crt \
    -days 365 \
    -sha256 \
    -extfile client/client.ext
```

-----

## 5\. Vérification et Déploiement

### 5.1. Vérification des Extensions

Confirmez que les extensions d'usage ont été correctement appliquées :

```bash
# Vérifier l'usage serveur (doit contenir 'Server Authentication')
echo "--- Certificat Serveur ---"
openssl x509 -in server/server.crt -text -noout | grep -A 3 "X509v3 Extended Key Usage"
openssl x509 -in server/server.crt -text -noout | grep -A 4 "Subject Alternative Name"

# Vérifier l'usage client (doit contenir 'Client Authentication')
echo "--- Certificat Client ---"
openssl x509 -in client/client.crt -text -noout | grep -A 3 "X509v3 Extended Key Usage"
```

### 5.2. Étapes de Déploiement

1. **Serveur :** Configurez votre service (ex: Nginx, Apache) pour utiliser `server/server.crt` et `server/server.key`.
2. **Confiance Racine :** Distribuez le certificat **`ca/ca.crt`** à tous les clients/systèmes qui doivent faire confiance à vos certificats privés. Installez-le dans leur magasin de confiance.
3. **Authentification Mutuelle :** Pour l'authentification mutuelle, le client utilise **`client/client.crt`** et **`client/client.key`**. Le serveur doit être configuré pour *demander* un certificat client signé par cette CA.
