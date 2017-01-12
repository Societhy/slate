---
title: API Reference

language_tabs:
  - python
  - json

toc_footers:
  - <a href='https://github.com/tripit/slate'>Documentation Powered by Slate</a>

includes:
  - errors

search: true
---
# Inscription, connexion et authentification

## Connexion

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

### Requête HTTP
`POST /login`

### Paramètres de requête
Paramètre | Description
--------- | -----------
username  | Nom de connexion de l'utilisateur.
password  | Mot de passe de l'utilisateur.

## Déconnexion
Ce point d'accès déconnecte un utilisateur.

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

### Requête HTTP
`GET /logout`

## Inscription
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

### Requête HTTP
`POST /newUser`

### Paramètres de requête
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

## Vérification du token d'authentification
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

### Requête HTTP
`GET /checkTokenValidity/<token>`

### Paramètres d'URL
Paramètre | Description
----------|------------
token | Token d'authentification à vérifier.

## Suppression
Ce point d'accès supprime un utilisateur.
> Cette méthode ne fait rien pour le moment.

# Information management

## Mise à jour des informations utilisateur
<aside class="notice">Ce point d'accès met à jour les informations de l'utilisateur. Il est utilisé uniquement pour informations sociales pour le moment.</aside>

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

### Requête HTTP
`POST /updateUser`

## Mise à jour des informations utilisateur
<aside class="notice">Ce point d'accès met à jour les informations de l'utilisateur. Il est utilisé uniquement pour les informations affichées dans le profil de l'utilisateur.</aside>

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

### Requête HTTP
`POST /updateSingleUserField`

### Paramètres de requête
Paramètre | Description
----------|------------
id | ID de l'utilisateur a modifier.
new | Nouvelle valeur du champ.
old | Ancienne valeur.
name | Nom du champ à modifier.

## Recherche d'un utilisateur
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

### Requête HTTP
`POST /findUser`

### Paramètres de requête
Paramètres | Description
-----------|------------
name | Nom de l'utilisateur à rechercher.

# Key management

# Wallet management
