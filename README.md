# KTHB LDAP
API mot LDAP

##

###


#### Dependencies

Node 16.13.2

##### Installation

1.  Skapa folder på server med namnet på repot: "/local/docker/ldap-api"
2.  Skapa och anpassa docker-compose.yml i foldern
```
version: '3.6'

services:
  ldap-api:
    container_name: ldap-api
    image: ghcr.io/kth-biblioteket/ldap-api:${REPO_TYPE}
    restart: always
    env_file:
      - ./ldap-api.env
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.ldap-api.rule=Host(`${DOMAIN_NAME}`) && PathPrefix(`${PATHPREFIX}`)"
      - "traefik.http.routers.ldap-api.middlewares=ldap-api-stripprefix"
      - "traefik.http.middlewares.ldap-api-stripprefix.stripprefix.prefixes=${PATHPREFIX}"
      - "traefik.http.routers.ldap-api.entrypoints=websecure"
      - "traefik.http.routers.ldap-api.tls=true"
      - "traefik.http.routers.ldap-api.tls.certresolver=myresolver"
    networks:
      - "apps-net"

networks:
  apps-net:
    external: true
```
3.  Skapa och anpassa .env(för composefilen) i foldern
```
PATHPREFIX=/ldap
DOMAIN_NAME=api-ref.lib.kth.se
REPO_TYPE=ref
```
4.  Skapa och anpassa ldap-api.env (för applikationen) i foldern
```
ENVIRONMENT=production
PORT=3002
SECRET=kthb%Q2
APIKEYREAD=xxxxxxxxxxxxxxxxxxxxxxxxx
LDAP_USER=xxxxxxxxxx
LDAP_PASSWORD="xxxxxxxxxx"
LDAP_HOST=ldaps://ug.kth.se
LDAP_BASEDN=dc=ug,dc=kth,dc=se
SIZE_LIMIT=5000
LDAPAPIKEY=xxxxxxxxxxxxxxxx
ORCIDAPIKEY=xxxxxxxxxxxxxxxx
LETAANSTALLDAAPIKEY=xxxxxxxxxxxxxxxx
SCOPUSAPIKEY=xxxxxxxxxxxxxxxx
WOSAPIKEY=xxxxxxxxxxxxxxxx
MEILIPUBLIC=xxxxxxxxxxxxxxxx
```
5. Skapa deploy_ref.yml i github actions
6. Skapa deploy_prod.yml i github actions
7. Github Actions bygger en dockerimage i github packages
8. Starta applikationen med docker compose up -d --build i "local/docker/ldap-api"

