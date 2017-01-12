---
title: API Reference

language_tabs:
  - python
  - json

toc_footers:
  - <a href='#'>Sign Up for a Developer Key</a>

includes:
  - errors

search: true
---
# User

## Inscription, connexion et authentification

### Connexion

Ce point d'accès permet de connecter un utilisateur.

```python
def login(credentials):

	user = None

	def auth_user(credentials):
		if credentials:
			credentials = str(b64decode(credentials), 'utf-8').split(':')
			if len(credentials) == 2:
				name, passw = credentials[0], encode_hex(scrypt.hash(credentials[1], "du gros sel s'il vous plait")).decode('utf-8')
				if (name is not None) and (passw is not None):
					user = users.find_one({"name": name, "password": passw}, users.user_info)
					return user
		return None

	def auth_user_social(credentials):
		print(credentials)
		if credentials["provider"] == "facebook":
			return users.find_one({"social.facebook.id" : credentials["socialId"]})
		if credentials["provider"] == "github":
			return users.find_one({"social.github.id" : credentials["socialId"]})
		if credentials["provider"] == "coinbase" :
			return users.find_one({"social.coinbase.id" : credentials["socialId"]})
		if credentials["provider"] == "linkedin":
			return users.find_one({"social.linkedin.id" : credentials["socialId"]})
		if credentials["provider"] == "twitter":
			return users.find_one({"social.twitter.id" : credentials["socialId"]})
		if credentials["provider"] == "google":
			return users.find_one({"social.google.id" : credentials["socialId"]})



	if request.headers.get('authentification') is not None and request.headers.get('authentification') in session:
		return {
			"data": "already logged in",
			"status": 403
		}

	if "socialId" not in credentials:
		print(credentials)
		user = auth_user(credentials.get('id'))
	else:
		user = auth_user_social(credentials)

	if user is not None:
		token = str(jwt.encode({"_id": str(user.get("_id")), "timestamp": time.strftime("%a%d%b%Y%H%M%S")}, secret_key, algorithm='HS256'), 'utf-8')
		session[token] = user
		return {"data": {
					"token": token,
					"user": deserialize_user(user)
				},
				"status": 200}

	else:
		return {"data": "User does not exists of false password",
				"status": 401}
```

```json
{
    "data":
    {
        "token": "<token>",
        "user":
        {
            "_id" : "586873da9a112c005018081b",
            "address" : "3 rue toto",
            "birthday" : "06/12/1990",
            "city" : "Paris",
            "email" : "toto@api.com",
            "eth" :
                {
                    "mainKey" : null,
                    "keys" : {}
                },
            "firstname" : "toto",
            "gender" : "Male",
            "lastname" : "tata",
            "name" : "tototata",
            "password" : "06739ff96e0da"
        }
    },
    "status": 200
}
```

**Requête HTTP**

`POST /login`

**Paramètres de requête**

Paramètre | Description
--------- | -----------
username  | Nom de connexion de l'utilisateur.
password  | Mot de passe de l'utilisateur.

### Déconnexion
Ce point d'accès déconnecte un utilisateur.
<aside class="warning">Ce point d'accès nécessite d'être authentifié.</aside>

```python
def logout(user):
	token = request.headers.get('authentification')
	del session[token]
	return {"success": True}
```

```json
{
    "succes": true
}
```

**Requête HTTP**

`GET /logout`

### Inscription
Ce point d'accès permet d'inscrire un nouvel utilisateur.

```python
def sign_up(newUser):

	def wrong_signup_request(newUser):
		required_fields = ["name", "password", "email"]
		for field in required_fields:
			if newUser.get(field) is None:
				return {"status": 403,
						"error": "missing required field"}
		return None

	def user_exists(newUser):
		if users.find({"email": newUser.get('email')}).count() > 0:
			return {"data": "user already exists",
					"status": 403}
		return False

	def social_user_exists(newUser):
		if 'facebook' in newUser["social"]:
			if users.find({"social.facebook.id" : newUser["social"]["facebook"]["id"]}).count() > 0:
				return {"data": "user already exists", "status": 403}
		if 'github' in newUser["social"]:
			if users.find({"social.github.id" : newUser["social"]["github"]["id"]}).count() > 0:
				return {"data": "user already exists", "status": 403}
		if 'coinbase' in newUser["social"]:
			if users.find({"social.coinbase.id" : newUser["social"]["coinbase"]["id"]}).count() > 0:
				return {"data": "user already exists", "status": 403}
		if 'linkedin' in newUser["social"]:
			if users.find({"social.linkedin.id" : newUser["social"]["linkedin"]["id"]}).count() > 0:
				return {"data": "user already exists", "status": 403}
		if 'twitter' in newUser["social"]:
			if users.find({"social.twitter.id" : newUser["social"]["twitter"]["id"]}).count() > 0:
				return {"data": "user already exists", "status": 403}
		if 'google' in newUser["social"]:
			if users.find({"social.facebook.id" : newUser["social"]["google"]["id"]}).count() > 0:
				return {"data": "user already exists", "status": 403}


	if 'social' not in newUser:
		failure = wrong_signup_request(newUser) or user_exists(newUser)
		if failure:
			return failure

		unencryptedPassword = newUser.get('password')
		newUser["password"] = encode_hex(scrypt.hash(newUser.get('password'), "du gros sel s'il vous plait")).decode('utf-8')

		user = UserDocument(newUser)
		user.save()
		user.populate_key()
		return login({"id": b64encode(bytearray(newUser.get('name'), 'utf-8') + b':' + bytearray(unencryptedPassword, 'utf-8'))})

	else:
		failure = social_user_exists(newUser)
		if failure:
			return failure
		user = UserDocument(newUser)
		user.save()
		user.populate_key()
		user.generatePersonalDataFromSocial()
		return {"data": newUser, "status": 200}
```

```json
{
    "data":
    {
        "token": "<token>",
        "user":
        {
            "_id" : "586873da9a112c005018081b",
            "address" : "3 rue toto",
            "birthday" : "06/12/1990",
            "city" : "Paris",
            "email" : "toto@api.com",
            "eth" :
                {
                    "mainKey" : null,
                    "keys" : {}
                },
            "firstname" : "toto",
            "gender" : "Male",
            "lastname" : "tata",
            "name" : "tototata",
            "password" : "06739ff96e0da"
        }
    },
    "status": 200
}
```

**Requête HTTP**

`POST /newUser`

**Paramètres de requête**

Paramètre | Default | Description
----------|---------|------------
name | Pas de valeur par défaut | Nom de connexion de l'utilisateur.
email | Pas de valeur par défaut | Adresse e-mail de l'utilisateur..
password | Pas de valeur par défaut | Mot de passe de l'utilisateur.
eth | false | Si l'utilisateur souhaite une clé ethereum ou non.
firstname | "" | Prénom de l'utilisateur.
lastname | "" | Nom de famille de l'utilisateur.
birthday | "" | Date de naissance de l'utilisateur.
gender | "" | Sexe de l'utilisateur.
address | "" | Adresse de l'utilisateur.
city | "" | Ville de l'utilisateur.

### Vérification du token d'authentification
Ce point d'accès permet de vérifier que l'utilisateur est bien authentifié.

```python
def check_token_validity(token):
	return {"data": {"user": session.get(token)},
			"status": 200}
```

```json
{
    "data" :
    {
        "user" :
        {
            "_id" : "586873da9a112c005018081b",
            "address" : "3 rue toto",
            "birthday" : "06/12/1990",
            "city" : "Paris",
            "email" : "toto@api.com",
            "eth" :
                {
                    "mainKey" : null,
                    "keys" : {}
                },
            "firstname" : "toto",
            "gender" : "Male",
            "lastname" : "tata",
            "name" : "tototata",
            "password" : "06739ff96e0da"
        }
    },
	"status": 200
}
```

**Requête HTTP**

`GET /checkTokenValidity/<token>`

**Paramètres d'URL**

Paramètre | Description
----------|------------
token | Token d'authentification à vérifier.

### Suppression
Ce point d'accès supprime un utilisateur.
<aside class="warning">Ce point d'accès nécessite d'être authentifié.</aside>
> Cette méthode ne fait rien pour le moment.

## Information management

### Mise à jour des informations utilisateur
<aside class="notice">Ce point d'accès met à jour les informations de l'utilisateur. Il est utilisé uniquement pour informations sociales pour le moment.</aside>
<aside class="warning">Ce point d'accès nécessite d'être authentifié.</aside>

```python
def update(user, newData):
	def recurse_update(user, newData):
		for key, value in newData.items():
			if isinstance(value, collections.Mapping):
				r = recurse_update(user.get(key, {}), value)
				user[key] = r
			else:
				user[key] = newData[key]
		return user

	user = recurse_update(user, newData)
	user.save_partial()
	user.generatePersonalDataFromSocial()
	return {"data": user,
		"status": 200}
```

```json
{
    "data" :
    {
        "user" :
        {
            "_id" : "586873da9a112c005018081b",
            "address" : "3 rue toto",
            "birthday" : "06/12/1990",
            "city" : "Paris",
            "email" : "toto@api.com",
            "eth" :
                {
                    "mainKey" : null,
                    "keys" : {}
                },
            "firstname" : "toto",
            "gender" : "Male",
            "lastname" : "tata",
            "name" : "tototata",
            "password" : "06739ff96e0da"
        }
    },
	"status": 200
}
```

**Requête HTTP**

`POST /updateUser`

### Mise à jour des informations utilisateur
<aside class="notice">Ce point d'accès met à jour les informations de l'utilisateur. Il est utilisé uniquement pour les informations affichées dans le profil de l'utilisateur.</aside>
<aside class="warning">Ce point d'accès nécessite d'être authentifié.</aside>

```python
def updateUserField(user, newData):
	def field_exist(data):
		if users.find({"_id": ObjectId(data["_id"])}).count() <= 0:
			return {"data": "Cannot find the user and with the corresponding data. Please logout, login and try again",
				"status": 401}
		return False

	error = field_exist(newData)
	if error:
		return error

	user[newData["name"]] = newData["new"];
	user.save_partial()
	return {"data": user,
		"status": 200}
```

```json
{
    "data" :
    {
        "user" :
        {
            "_id" : "586873da9a112c005018081b",
            "address" : "3 rue toto",
            "birthday" : "06/12/1990",
            "city" : "Paris",
            "email" : "toto@api.com",
            "eth" :
                {
                    "mainKey" : null,
                    "keys" : {}
                },
            "firstname" : "toto",
            "gender" : "Male",
            "lastname" : "tata",
            "name" : "tototata",
            "password" : "06739ff96e0da"
        }
    },
	"status": 200
}
```

**Requête HTTP**

`POST /updateSingleUserField`

**Paramètres de requête**

Paramètre | Description
----------|------------
id | ID de l'utilisateur a modifier.
new | Nouvelle valeur du champ.
old | Ancienne valeur.
name | Nom du champ à modifier.

### Recherche d'un utilisateur
Ce point d'accès permet de trouver un utilisateur.

```python
def findUser(data):
	user = users.find_one({"name": data["name"]})
	return {"data": user,
		"status": 200}
```

```json
{
    "data" :
    {
        "user" :
        {
            "_id" : "586873da9a112c005018081b",
            "address" : "3 rue toto",
            "birthday" : "06/12/1990",
            "city" : "Paris",
            "email" : "toto@api.com",
            "eth" :
                {
                    "mainKey" : null,
                    "keys" : {}
                },
            "firstname" : "toto",
            "gender" : "Male",
            "lastname" : "tata",
            "name" : "tototata",
            "password" : "06739ff96e0da"
        }
    },
	"status": 200
}
```

**Requête HTTP**

`POST /findUser`

**Paramètres de la requête**

Paramètres | Description
-----------|------------
name | Nom de l'utilisateur à rechercher.

## Key management

### Génère une clef liée au compte

 ```python
def gen_linked_key(user, password):

  def gen_key_remote(password):
    hashPassword = scrypt.hash(password, "je trouve que les carottes ne sont pas assez salées")
    hashPassword = encode_hex(hashPassword).decode('utf-8')
    dirContent = listdir(keyDirectory)
    key = eth_cli.personal_newAccount(hashPassword)
    keyFile = list(set(listdir(keyDirectory)) - set(dirContent))[0]
    return {"address": key, "file": keyFile}

  newKey = gen_key_remote(password)
  user.add_key(newKey.get('address'), local=False, balance=0, file=newKey.get('file'))
  return {
    "data": newKey.get('address'),
    "status": 200
  }
```

 ```json
"0xa98786136a8d89525b1c1618f601e649116da8c6"
 ```

**Requête HTTP**

`POST /genLinkedKey`

**Paramètres de la requête**

Paramètres | Description
-----------|------------
Aucun | /

### Génération de clef locale

 ```python
def key_was_generated(user, address):
  address = normalize_address(address, hexa=True)
  user.add_key(address, local=True, balance=fromWei(eth_cli.eth_getBalance(address)))
  return {
    "data": "OK",
    "status": 200
  }
 ```

 ```json
 "OK"
 ```

**Requête HTTP**

`GET /keyWasGenerated/<address>`

**Paramètres de l'URL**

Paramètres | Description
-----------|------------
address | adresse de la nouvelle clef

### Importer une clef existante

 ```python
def import_new_key(user, sourceKey):

  def is_ethereum_key(keyFile):
    required_entries = set(["address", "crypto", "id", "version"])
    if not required_entries.issubset(set(keyFile.keys())):
      raise KeyFormatError

  def key_already_exists(address, userExistingAddresses):
    if normalize_address(address, hexa=True) in userExistingAddresses.keys():
      raise KeyExistsError

  def import_key_remote(keyId, sourceKey):
    keyFilename = "UTC--" + strftime("%Y-%m-%dT%H-%M-%S") + "." + str(clock())[2:] + "Z--" + keyId
    with open(path.join(keyDirectory, keyFilename), 'w') as f:
      f.write(sourceKey)
    return keyFilename

  status = 200
  sourceKey = sourceKey.read().decode('utf-8')

  try:
    key = json.loads(sourceKey)
    is_ethereum_key(key)
    key_already_exists(key.get('address'), user.get('eth').get('keys'))
    keyFilename = import_key_remote(key.get('id'), sourceKey)
    key["address"] = normalize_address(key.get('address'), hexa=True)
    data = { "address" : key.get('address') }
    user.add_key(key.get('address'), local=False, balance=fromWei(eth_cli.eth_getBalance(key.get('address'))), file=keyFilename)
  except (json.JSONDecodeError, KeyFormatError):
    data = "key format not recognized"
    status = 400
  except (KeyExistsError):
    data = "trying to import an existing key"
    status = 400

  return {
    "data": data,
    "status": status
  }
```

 ```json
 {
  "address": "0xa98786136a8d89525b1c1618f601e649116da8c6"
}
 ```

**Requête HTTP**

`POST /importNewKey`

**Paramètres de la requête**

Paramètres | Description
-----------|------------
key | fichier contenant la clef existante

### Exporter une clef

 ```python
def export_key(user, address, delete=False):
  exportedKey = user.get_key(address)

  if exportedKey and delete and exportedKey.get('local') is True:
    user.remove_key(address, local=True)
    return {
      "data": None,
      "status": 200
    }

  elif exportedKey is not None:
    for keyFile in listdir(keyDirectory):
      if exportedKey.get('file') == keyFile:
        with open(path.join(keyDirectory, keyFile), 'r') as f:
          data = json.load(f)
          if delete is True:
            user.remove_key(address, local=False)
            remove(f.name)
          return {
            "data": data,
            "status": 200
          }

  return {
    "data": "Key does not exists",
    "status": 400
  }
```

 ```json
{
  "address": "7f607df82ec1107cfd31431aefc03041dd239316",
  "crypto": {
    "cipher": "aes-128-ctr",
    "cipherparams": {
      "iv": "e0aeff559a53241f7f57cd5accea9330"
    },
    "ciphertext": "208d1ada7c79aa2be36252705420145955869089489aaf9387713e117c9c4f66",
    "kdf": "pbkdf2",
    "kdfparams": {
      "c": 10240,
      "dklen": 32,
      "prf": "hmac-sha256",
      "salt": "d55d2e80e22fb8a716453d7d8d3300d8fe28d7bdc732b9a327cc026ca92dd6f0"
    },
    "mac": "3eba1319a5a719812651bcf4e1f7389265dd45c10bd05b378b5f0d24a6b88ccd"
  },
  "id": "8b2899cc-1cda-d6ad-e24a-4aa519783a99",
  "meta": "{}",
  "name": "8b2899cc-1cda-d6ad-e24a-4aa519783a99",
  "version": 3
}

 ```
 }

**Requête HTTP**

`GET /exportKey/<address>`

**Paramètres de l'URL**

Paramètres | Description
-----------|------------
address | adresse de la clef à exporter

### Supprimer une clef

 ```python
def export_key(user, address, delete=False):
  exportedKey = user.get_key(address)

  if exportedKey and delete and exportedKey.get('local') is True:
    user.remove_key(address, local=True)
    return {
      "data": None,
      "status": 200
    }

  elif exportedKey is not None:
    for keyFile in listdir(keyDirectory):
      if exportedKey.get('file') == keyFile:
        with open(path.join(keyDirectory, keyFile), 'r') as f:
          data = json.load(f)
          if delete is True:
            user.remove_key(address, local=False)
            remove(f.name)
          return {
            "data": data,
            "status": 200
          }

  return {
    "data": "Key does not exists",
    "status": 400
  }
```

 ```json
 {
  "address": "a98786136a8d89525b1c1618f601e649116da8c6",
  "crypto": {
    "cipher": "aes-128-ctr",
    "cipherparams": {
      "iv": "6e6c4af40b62f5ad613d9dcc3bb23897"
    },
    "ciphertext": "d546ac8273e5f6962b658d8c2a7fea6939022704dc78d1244491ac473b8b7f52",
    "kdf": "pbkdf2",
    "kdfparams": {
      "c": 10240,
      "dklen": 32,
      "prf": "hmac-sha256",
      "salt": "38daeb21f66984bfeb93a43f3507126ad362e9fc7c7ff3ddc6876a7f8bf4561e"
    },
    "mac": "4041bc2f35464d6ab1a2d8e7e8d9f79aff4c1c93e5c5e721076fedb029b2b9af"
  },
  "id": "9a463bfd-4e09-1f60-ad13-c1857f4eba45",
  "meta": "{}",
  "name": "9a463bfd-4e09-1f60-ad13-c1857f4eba45",
  "version": 3
}
 ```

**Requête HTTP**

`GET /exportDeleteKey/<address>`

**Paramètres de l'URL**

Paramètres | Description
-----------|------------
address | adresse de la clef à supprimer

## Wallet management

### Get la balance totale d'un utilisateur

 ```python
 ```

 ```json
 ```

**Requête HTTP**

`GET /getAllBalances>`

**Paramètres de l'URL**

Paramètres | Description
-----------|------------
aucun | /

### Get la balance d'une addresse

 ```python
 ```

 ```json
 ```

**Requête HTTP**

`GET /getBalance/<address>`

**Paramètres de l'URL**

Paramètres | Description
-----------|------------
address | adresse de la balance souhaitée

### Get l'historique des transactions

 ```python
 ```

 ```json
 ```

**Requête HTTP**

`GET /getTxHistory/<address>`

**Paramètres de l'URL**

Paramètres | Description
-----------|------------
address | adresse du comptes pour lequel on veut l'historique des transactions

# Organisation

# Project
