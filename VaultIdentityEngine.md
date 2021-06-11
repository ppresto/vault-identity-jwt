# Vault PoV - Identity Engine

## Authenticate your services with Vault and JWTs

You may want your services to be able to talk to each other in an authenticated manner, and even perform some authorization. This is not easy to do and you might have scratched your head a bunch about how to do it. This lab is going to show you how to do something like this using hashicorp’s Vault. At the end of this lab you’ll be able to issue and validate authorization tokens to make sure your services communicate in an authenticated and secure manner.

## What are JWTs ?

JWT, or JSON Web Tokens, are tokens that are signed by a central authority that encapsulate authorization information. This [website](https://jwt.io/#debugger) can help debug/decode your tokens.

A JWT consists of 3 parts separated by dots "`.`".

* Header
* Payload
* Signature

A JWT looks like this:
`xxx.yyy.zzz`

* The "**header**" gives you info about:
    * the algorithm used,
    * the key id used to sign the token and so on.
* The "**payload**" is the actual encoded auth data that you care about
* The "**signature**" is used to validate the token.

## Setup

### Start Vault Enterprise (if one does not exist)


```bash
docker stop vault
docker rm vault
docker run --rm -itd \
    --name vault \
    -p 8200:8200 \
    -e 'VAULT_DEV_ROOT_TOKEN_ID=root' \
    -e "VAULT_ADDR=http://127.0.0.1:8200" \
    hashicorp/vault-enterprise
```

Save the unseal key(s) and root token.


```bash
UNSEAL_1=$(docker logs vault | grep "Unseal Key" | awk '{print $NF}')
VAULT_TOKEN_ROOT=$(docker logs vault | grep "Root Token" | awk '{print $NF}')
echo Unseal Key: $UNSEAL_1
echo Root Token: $VAULT_TOKEN_ROOT
```

### Set environment variables

Change address and token as appropriate.


```bash
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="root"
export VAULT_SKIP_VERIFY=true
#VAULT_TLS_SERVER_NAME=
```

Set fancy colors for standard output.


```bash
export RED="\e[0;31m"
export YELLOW="\e[0;33m"
export BLDYELLOW="\e[1;33m"
export GREEN="\e[0;32m"
export CYAN="\e[0;36m"
export BLUE="\e[0;34m"
export WHITE="\e[0;37m"
export BLDWHITE="\e[1;37m"
export NC="\e[0m"
```


```bash
# vault login root
# vault version
```

### Make sure vault is initialized and unsealed


```bash
vault status
```

### (optional) Create admin/dev namespace


```bash
printf "${GREEN}# Create dev namespace${NC}\n"
vault namespace create admin

printf "${GREEN}# Create admin/dev namespace${NC}\n"
export VAULT_NAMESPACE=admin
vault namespace create dev

printf "${GREEN}# Manage namespace admin/dev${NC}\n"
export VAULT_NAMESPACE=admin/dev
```

**NOTE:** The rest of this deployment will be in the `admin/dev` namespace.

## Enable the userpass auth method


```bash
vault auth enable userpass || true
vault auth list
```

## Write the Ops Team and App Team KV policies (NEEDS EDITING)

We will need to create a policy (`ops-team` and `app-team`) to allow the account (that we will create right after) to perform some basic operations on Vault.


```bash
printf "${GREEN}Create policy file for ops.${NC}\n"
vault policy write ops-team - <<EOF
path "identity/oidc/token/*" {
  capabilities = ["list", "read", "create", "update"]
}

path "identity/oidc/introspect" {
  capabilities = ["list", "read", "create", "update"]
}

path "identity/oidc/key/*" {
  capabilities = ["list", "read", "create", "update"]
}
EOF

echo
printf "${GREEN}Create policy file for app team.${NC}\n"
vault policy write app-team - <<EOF
path "identity/oidc/token/*" {
#   capabilities = ["list", "read", "create", "update"]
  capabilities = ["read"]

}

path "identity/oidc/introspect" {
#   capabilities = ["list", "read", "create", "update"]
  capabilities = ["read", "update"]
}
EOF
```

You should lock down your policies. This policy is over-permissive.

### Confirm policies


```bash
printf "${GREEN}Read ops-team policy.\n${NC}"
vault policy read ops-team
echo
printf "${GREEN}Read app-team policy.\n${NC}"
vault policy read app-team
```

## Create Userpass users


```bash
printf "${GREEN}Create ops user.\n${NC}"
vault write auth/userpass/users/ops-1 password=ops-1 policies=ops-team
printf "${GREEN}Create app user.\n${NC}"
vault write auth/userpass/users/app-1 password=app-1 policies=app-team
```

## Create the OIDC issuer - Write the configuration for the Identity Tokens Backend

Configure the Identity Tokens Backend for OIDC-compliant identity tokens issued by Vault.


```bash
vault write identity/oidc/config issuer="${VAULT_ADDR}"
```

`issuer` will be used to populate the `issuer` field of your tokens. If `issuer` is not set, Vault's `api_addr` will be used.

Read the configuration for Identity Tokens Backend to confirm your settings.


```bash
vault read -format=json identity/oidc/config | jq -r .data
```

## Create Vault roles

Create two `role`'s in Vault, which will map to the apps you want to authenticate against. In this example we will assume that our app is called `role-001` and `role-002`.

**NOTE**: ID tokens are **generated** against a role and **signed** against a named key.

### Create template for generating JWT tokens.

Define claims and scopes in `token_template.json`: https://www.vaultproject.io/docs/secrets/identity#token-contents-and-templates


```bash
mkdir -p config/vault
printf "${GREEN}#--> Create the template to use for generating tokens.${NC}\n"
cat <<"EOF" > config/vault/token_template.json
{
    "entity_id": {{identity.entity.id}},
    "entity_name": {{identity.entity.name}},
    "groups": {{identity.entity.groups.names}},
    "metadata": {{identity.entity.metadata}}
}
EOF
cat config/vault/token_template.json
```


```bash
vault write identity/oidc/role/role-ops \
    key="named-key-ops-1" ttl="12h" \
    template=@config/vault/token_template.json
vault write identity/oidc/role/role-app \
    key="named-key-app-1" ttl="12h" \
    template=@config/vault/token_template.json
```

* `template` - The template string to use for generating tokens. This may be in string-ified JSON or base64 format.
* `ttl` - TTL of the tokens generated against the role. Can be specified as a number of seconds or as a time string like "30m" or "6h".

### Read the Roles


```bash
printf "${GREEN}Read role - role-ops.\n${NC}"
vault read identity/oidc/role/role-ops
echo
printf "${GREEN}Read role - role-app.\n${NC}"
vault read identity/oidc/role/role-app
```

### Get the Role IDs


```bash
ROLE_1_CLIENT_ID=$(vault read -format=json identity/oidc/role/role-ops | jq -r .data.client_id)
ROLE_2_CLIENT_ID=$(vault read -format=json identity/oidc/role/role-app | jq -r .data.client_id)
```


```bash
#optional
echo $ROLE_1_CLIENT_ID
echo $ROLE_2_CLIENT_ID
```

## Create named keys

Create two [named keys](https://www.vaultproject.io/api/secret/identity/tokens.html#create-a-named-key). The associated role uses the key to sign tokens. `allowed_client_ids` define the roles allowed to use the keys.


```bash
vault write identity/oidc/key/named-key-ops-1 \
    rotation_period="10m" verification_ttl="30m" allowed_client_ids=$ROLE_1_CLIENT_ID

vault write identity/oidc/key/named-key-app-1 \
    rotation_period="10m" verification_ttl="30m" allowed_client_ids=$ROLE_2_CLIENT_ID
```

Now we have keys that will sign our tokens.

**NOTE**: In a production environment you will need to have a key per environment (dev/staging/prod and so on) and will need to individually allow client ID (which we talk about later) to be signed by your key.

### Read the named keys

Query a named key and returns its configurations.


```bash
printf "${GREEN}Query named-key-ops-1.${NC}\n"
vault read identity/oidc/key/named-key-ops-1
echo
printf "${GREEN}Query named-key-app-1.${NC}\n"
vault read identity/oidc/key/named-key-app-1
```

### List All Named Keys

List all named keys.


```bash
vault list identity/oidc/key
```

## (optional) AppRole - SKIP FOR NOW - NOT READY YET

### Create the AppRole

An [AppRole](https://www.vaultproject.io/docs/auth/approle.html) is a Vault authentication backend. You can see it as something similar to a username/password authentication, but intended for services instead of actual human users.

Enable the approle authentication backend:


```bash
vault auth enable approle
```

Create the actual `approle`, it will be called `demo-approle`:


```bash
vault write auth/approle/role/demo-approle role_name=demo-approle policies=readonly
vault write auth/approle/role/ops-1 role_name=ops-1 policies=ops-team
vault write auth/approle/role/app-1 role_name=app-1 policies=app-team
```

Then you will need to get two pieces of information, the `roleid` and the `secretid` for the approle. These are the equivalent of the username and the password to authenticate yourself.


```bash
ops_secret_id=$(vault write -force -format=json auth/approle/role/ops-1/secret-id | jq -r .data.secret_id)
ops_role_id=$(vault read -format=json auth/approle/role/ops-1/role-id | jq -r .data.role_id)
echo $ops_role_id $ops_secret_id

app_secret_id=$(vault write -force -format=json auth/approle/role/app-1/secret-id | jq -r .data.secret_id)
app_role_id=$(vault read -format=json auth/approle/role/app-1/role-id | jq -r .data.role_id)
echo $app_role_id $app_secret_id
```

Sample Output

`ca9f0470-8d1f-4464-2635-25f02b9407d7 f91a7c31-dc06-2b24-20fd-e9f5867c32a8`

Your values will be different.

### Create the entity and map it to the AppRole

Now that we have created the approle, we need to map it to an internal Vault `entity`, you need to do that because several entities can be mapped to various authentication backends, like `userpass` or if you use something like Google or what not. So first, create the `entity` and save it for later:


```bash
ops_entity_id=$(vault write -format=json identity/entity name=ops | jq .data.id -r)
echo $ops_entity_id
app_entity_id=$(vault write -format=json identity/entity name=app | jq .data.id -r)
echo $app_entity_id
```

NOTE: Running this command twice will not work. There is not output after the first time.

You should see something like this:

`c957656f-0872-766c-3517-83b787672f84`

#### Entity Alias

Now you finally need to create an `entity alias` to make the link between the `entity` and the `approle` authentication backend (that is tedious I know but bear with me i swear it is worth it). Retrieve the `accessor`, which is the internal Vault reference to your approle authentication backend:


```bash
accessor=$(vault auth list -format=json | grep 'auth_approle' | tr -d " " | tr -d , | cut -d ":" -f 2 | tr -d \")
echo $accessor
vault auth list -format=json | grep 'auth_approle' | tr -d " " | tr -d ,
```

Sample Output:

`auth_approle_91098819`

Then, create the alias:


```bash
vault write identity/entity-alias name=ops-1 canonical_id=$ops_entity_id mount_accessor=$accessor
vault write identity/entity-alias name=app-1 canonical_id=$app_entity_id mount_accessor=$accessor
```

Sample Output

```
Key             Value
---             -----
canonical_id    c957656f-0872-766c-3517-83b787672f84
id              a2d067d6-229b-6580-d714-35a01ba62864
```

Everything is setup now.

### Log in as the AppRole


```bash
# ops-1_token=$(vault write -format=json auth/approle/login role_id=$role_id secret_id=$secret_id | jq -r .auth.client_token)
# export VAULT_TOKEN=$ops-1_token
ops_1_token=$(vault write -format=json auth/approle/login role_id=$ops_role_id secret_id=$ops_secret_id | jq -r ".auth.client_token")
export VAULT_TOKEN=$ops_1_token
echo $ops_1_token
```

You are now logged into Vault as your approle! Check it by running:


```bash
vault token lookup
```

Sample output

```
Key                 Value
---                 -----
accessor            Tc6riT70kLnepiW3CC0rEkBj
creation_time       1579287446
creation_ttl        768h
display_name        approle
entity_id           f1be740b-8b4f-4369-a019-bc6ef3f8e963
expire_time         2020-02-18T18:57:26.707866969Z
explicit_max_ttl    0s
id                  s.ohsNR1DIo6sVr8gG8hsRsk1Y
issue_time          2020-01-17T18:57:26.707866723Z
meta                map[role_name:demo-approle]
num_uses            0
orphan              true
path                auth/approle/login
policies            [default readonly]
renewable           true
ttl                 767h58m57s
type                service
```

## Sign in as the Ops user


```bash
printf "${YELLOW}Sign in as ops user and set VAULT_TOKEN.${NC}\n"
token=$(vault login -format=json -method=userpass username=ops-1 password=ops-1 | jq -r .auth.client_token)
export VAULT_TOKEN=$token
echo $VAULT_TOKEN
```

You are now logged into Vault as the `ops` user!

Confirm your policies and namespace:


```bash
vault token lookup
```

## Generate a signed (OIDC) token

Generate a signed ID (OIDC) token. `role-001` is the name of the role against which to generate a signed ID token


```bash
#vault read identity/oidc/token/role-001
printf "${GREEN}Set client id and token.${NC}\n"
TOKEN_DATA=$(vault read -format=json identity/oidc/token/role-ops)
echo $TOKEN_DATA | jq -r .data
CLIENT_ID=$(echo $TOKEN_DATA | jq -r .data.client_id)
ID_TOKEN=$(echo $TOKEN_DATA | jq -r .data.token)
```

You can now use this token to identify to a service !

## Sign in as the App user


```bash
export VAULT_TOKEN=$(vault login -format=json -method=userpass username=app-1 password=app-1 \
| jq -r .auth.client_token)

printf "${YELLOW}DEBUG - View VAULT_TOKEN.${NC}\n"
echo $VAULT_TOKEN
```

You are now logged into Vault as the `app` user!

Confirm your policies and namespace:


```bash
vault token lookup
```

## Get the key id from the JWT

Let’s unpack the token a bit using the [debugger](https://jwt.io/#debugger) or `jwt` cli tool.

### optional - install jwt cli tool


```bash
#optional
# brew tap mike-engel/jwt-cli                    
# brew install jwt-cli
```

### jwt decode


```bash
echo $TOKEN_DATA | jq -r .data.token | jwt decode -
```

The "**header**" specifies the signature algorithm (`alg`) used and the key id (`kid`) used to sign the token. We will look at this `kid` value in the Well Known keys section.

```
Token header
------------(B
{
  "alg": "RS256",
  "kid": "64d94750-6ccc-cf98-e26a-455d57f42b14"
}
```

The "**body**" of the token reads the following:

```
Token claims
------------(B
{
  "aud": "gp6ydLvnWZuxPGXYQt673q5XmX",
  "entity_id": "dcde86df-8c01-1dfb-2289-70e63e2c72a6",
  "entity_name": "entity_bbe2033e",
  "exp": 1622889270,
  "iat": 1622846070,
  "iss": "http://localhost:8200/v1/identity/oidc",
  "namespace": "root",
  "sub": "dcde86df-8c01-1dfb-2289-70e63e2c72a6"
}
```

Here you have a bunch of information about the identity of the token bearer:

* `exp` is the expiration time of the token
* `iat` is the issuance time
* `iss` is the issuer
* `aud` is the intended audience of the token, namely the `demo` OIDC role you created above
* `sub` is the `subject` of the token, namely the identity of the bearer. **NOTE**: This is the same UUID as the one referenced in the `entity_id` field of the `vault token lookup` command.

**NOTE: You can now identify who’s token you are looking at!**

You can also add more custom fields, such as group membership and other arbitrary things. More info on that [here](https://www.vaultproject.io/docs/secrets/identity/index.html#token-contents-and-templates).

## Verify the token

Now you need to be able to verify the tokens.

You need to be able to verify the signature of the token to establish that the token:

* Comes from whom it says it comes from
* Is signed by a key owned by whom it says it comes from

Vault exposes an unauthenticated endpoint that allows you to retrieve the public part of the signing keys used for the tokens, which you can access the following way


```bash
printf "${GREEN}Create verify.json payload for introspection/validation${NC}\n"
cat <<EOF > config/vault/verify.json
{
    "token": "${ID_TOKEN}"
}
EOF
cat config/vault/verify.json
```

The ID_TOKEN was set previously when we created the token. 


```bash
printf "${GREEN}Verify the authenticity and active state of the signed ID token.${NC}\n"
curl \
    --header "X-Vault-Token: $VAULT_TOKEN" \
    --header "X-Vault-Namespace: admin/dev" \
    --request POST \
    --data @config/vault/verify.json \
    http://127.0.0.1:8200/v1/identity/oidc/introspect
```

You should see

``{"active":true}``

### Show the Well Known config

Read the Well Known config to retrieve a set of claims about the identity tokens' configuration. This response is a compliant OpenID Provider configuration response.


```bash
curl -s \
    --header "X-Vault-Namespace: admin/dev" \
    --request GET \
    http://127.0.0.1:8200/v1/identity/oidc/.well-known/openid-configuration | jq -r .
```

### Show the Well Known keys

This is the public portion of the named keys. Clients can use this to validate the authenticity of an identity token


```bash
curl -s \
    --header "X-Vault-Namespace: admin/dev" \
    --request GET \
    http://127.0.0.1:8200/v1/identity/oidc/.well-known/keys | jq -r .keys
```

If you pay attention and fluently speak UUID, you will notice that `962cbe97-f3ca-15c3-042d-61e431c194e0` is the `kid` present in the header of the token we have previously issued.

This way you can verify that the signature is valid. Note that Vault implements the [openID discovery protocol](https://swagger.io/docs/specification/authentication/openid-connect-discovery/) which can give you access to even more information.

## Rotate a Named Key

Rotate a named key.

Negative Testing


```bash
printf "${RED}This should fail.${NC}\n"
# export VAULT_TOKEN=root
#vault write -f -format=json identity/oidc/key/role-002/rotate
vault write -f -format=json identity/oidc/key/named-key-app-1/rotate
```


```bash
printf "${YELLOW}Sign in as ops user and set VAULT_TOKEN.${NC}\n"
token=$(vault login -format=json -method=userpass username=ops-1 password=ops-1 | jq -r .auth.client_token)
export VAULT_TOKEN=$token
```

Positive Testing


```bash
printf "${YELLOW}Show current Well Known Keys - Before Rotation.${NC}\n"
well_known_keys=$(curl -s -H "X-Vault-Namespace: admin/dev" -X GET \
    http://127.0.0.1:8200/v1/identity/oidc/.well-known/keys | jq -r .keys[].kid)
echo "$well_known_keys"
printf "${YELLOW}Number of keys:${NC} $(echo $well_known_keys | wc -w)"
```


```bash
printf "${GREEN}This should now work.${NC}\n"
# export VAULT_TOKEN=root
#vault write -f -format=json identity/oidc/key/role-002/rotate
vault write -f -format=json identity/oidc/key/named-key-app-1/rotate
```


```bash
printf "${YELLOW}Show current Well Known Keys - After Rotation.${NC}\n"
well_known_keys=$(curl -s -H "X-Vault-Namespace: admin/dev" -X GET \
    http://127.0.0.1:8200/v1/identity/oidc/.well-known/keys | jq -r .keys[].kid)
echo "$well_known_keys"
printf "${YELLOW}Number of keys:${NC} $(echo $well_known_keys | wc -w)"
```

There should be one more key than above.

NOTE: The reason you see multiple keys is due to the auto-rotation. We set a rotation period of 10 minutes and a verification_ttl of 30 minutes. After 30 minutes, you will see at least 3 keys for each named key.

## Delete a Named Key


```bash
# Delete an identity key
VAULT_TOKEN=root vault delete identity/oidc/key/named-key-app-1
```


```bash
# Delete an identity role and then the key.
VAULT_TOKEN=root vault delete identity/oidc/role/role-app
VAULT_TOKEN=root vault delete identity/oidc/key/named-key-app-1
```

You have completed this lab. Please proceed to Cleanup if necessary.

## Cleanup

### Delete admin/dev namespace


```bash
export VAULT_TOKEN=root
VAULT_NAMESPACE=admin vault namespace delete dev
```

### Shutdown Docker


```bash
docker stop vault

# Remove the container - not needed since --rm was used
# docker rm vault
```

## END
