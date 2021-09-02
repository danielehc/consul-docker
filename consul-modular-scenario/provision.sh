#! /bin/bash
# set -x

## TODO: Check Docker capabilities
## Before functions so nothing gets created

# ++-----------------+
# || Functions       |
# ++-----------------+

## Prints a line on stdout prepended with date and time
log() {
  echo -e "\033[1m["$(date +"%Y-%d-%d %H:%M:%S")"] - ${@}\033[0m"
}

## Logs for a container. Prints a log for the container passed as argument.
## If no command is passed as argument, it prints the startup command for the
## container. It always prints on the provision log file if the variable is defined.
## If the LOG_LEVEL is set to COMMAND printa also on stdout.
## Usage:
##      $0 [-h|-f] <container_name> [<command_to_print>]
log_container_command() {

  local _head="\n"
  local _foot="\n"

  local OPTIND o

  while getopts ":hfb" o; do
    case "${o}" in
        h)
            _foot=""
            ;;
        f)
            _head=""
            ;;
        b)
            _head=""
            _foot=""
            ;;
        ?)
            break
            ;;
    esac
  done
  shift $((OPTIND-1))
  local CONTAINER_NAME=$1

  local COMMAND

  if [ "$#" -ne 1 ]; then
    shift
    COMMAND=$@ 
  else
    COMMAND=""
    
    for j in `docker inspect ${CONTAINER_NAME} | jq -r '.[].Args | .[] '`; do 
      
      COMMAND="${COMMAND}""$j "
      
      if [[ "$j" =~ "entrypoint.sh" ]] ; then
        COMMAND=""
      fi
    done

  fi 
  if [ ! -z "${PROVISION_LOG_FILE}" ]; then
    echo -en "${_head}[ ${CONTAINER_NAME} ]\t${COMMAND}\n${_foot}" >> ${PROVISION_LOG_FILE}  
  fi

  if [ "$LOG_LEVEL" == "COM" ]; then
    echo -en "${_head}[ ${CONTAINER_NAME} ]\t${COMMAND}\n${_foot}"  1>&2;
  fi
}

## Compatibility for Katacoda - creates a file to signal provision ended
finish() {
  touch /provision_complete
  log "Complete!  Move on to the next step."
}

## Prints a header on stdout
header() {

  echo -e " \033[1m\033[32m"

  echo ""
  echo "++----------- " 
  echo "||   ${@} "
  echo "++------      " 

  echo -e "\033[0m"
}

## Prints environment variables to be used to configure local machine
## for communicating with the server directly
print_vars() {

  if [ ! -z $1 ] ; then
  
    if [ -f "${ASSETS}secrets/$1_env.conf" ]; then

      cat ${ASSETS}secrets/$1_env.conf

    elif [ "$1" == "consul" ]; then

      echo "export CONSUL_HTTP_ADDR=https://${SERVER_IP}:443"
      echo "export CONSUL_HTTP_ADDR=https://localhost:1443"
      echo "export CONSUL_HTTP_TOKEN=${CONSUL_HTTP_TOKEN}"
      echo "export CONSUL_HTTP_SSL=true"
      echo "export CONSUL_CACERT=./assets/secrets/consul-agent-ca.pem"
      ## This is a boolean value (default true) to specify 
      # SSL certificate verification; setting this value to 
      # false is not recommended for production use. 
      # Example for development purposes:
      # echo "export CONSUL_HTTP_SSL_VERIFY=false"
      echo "export CONSUL_TLS_SERVER_NAME=server.${DATACENTER}.${DOMAIN}"
  
    elif [ "$1" == "vault" ]; then

      echo "export VAULT_ADDR=http://${VAULT_IP}:8200"
      echo "export VAULT_TOKEN=${VAULT_TOKEN}"

    elif [ "$1" == "curl" ]; then

      echo "export CONSUL_SERVER_IP=${SERVER_IP}"
      echo "export CONSUL_DC=${DATACENTER}"
      echo "export CONSUL_DOMAIN=${DOMAIN}"
      echo "export CONSUL_SERVER_FQDM=server.${CONSUL_DC}.${CONSUL_DOMAIN}"

    fi



  else
    
    if [ -f "${ASSETS}secrets/consul_env.conf" ]; then

      cat ${ASSETS}secrets/consul_env.conf
    fi

    if [ -f "${ASSETS}secrets/vault_env.conf" ]; then

      cat ${ASSETS}secrets/vault_env.conf

    fi
  fi
}

## Prints environment variables to be used to configure local machine
## for communicating with the local Consul agent
print_vars_local () {
  echo "export CONSUL_HTTP_ADDR=http://localhost:8500"
  echo "export CONSUL_HTTP_TOKEN=${CONSUL_HTTP_TOKEN}"
}

## Cleans environment by removing containers and volumes
clean_env() {

  if [[ $(docker ps -aq --filter label=tag=${DK_TAG}) ]]; then
    docker rm -f $(docker ps -aq --filter label=tag=${DK_TAG})
  fi

  if [[ $(docker volume ls -q --filter label=tag=${DK_TAG}) ]]; then
    docker volume rm $(docker volume ls -q --filter label=tag=${DK_TAG})
  fi

  if [[ $(docker network ls -q --filter label=tag=${DK_TAG}) ]]; then
    docker network rm $( docker network ls -q --filter label=tag=${DK_TAG})
  fi

  ## Remove certificates 
  rm -rf ${ASSETS}secrets

  ## Remove data 
  rm -rf ${ASSETS}data

  ## Remove logs
  rm -rf ${LOGS}/*
  
  ## Unset variables
  unset CONSUL_HTTP_ADDR
  unset CONSUL_HTTP_TOKEN
  unset CONSUL_HTTP_SSL
  unset CONSUL_CACERT
  unset CONSUL_CLIENT_CERT
  unset CONSUL_CLIENT_KEY
}

## Prints for each container the ports used
## and the process listening on those ports.
show_ports() {
  for i in `docker container ls --filter label=tag=${DK_TAG} --format "{{.Names}}"`; do 
    
    local CONT_IP=`docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $i`
    
    echo "======================="; 
    echo -e "$i - ${CONT_IP}"; 
    echo "======================="; 
    
    # docker exec $i netstat -natp | grep LISTEN; 
    docker exec $i netstat -natp 2> /dev/null | grep LISTEN | awk '{print $7"\t: "$4}' | sed 's/[0-9]*\///g' | sort ; 
    
    echo ""
  done
}

show_ips () {
  for i in `docker container ls --filter label=tag=${DK_TAG} --format "{{.Names}}"`; do 

    local CONT_IP=`docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $i`  

    echo -e "${CONT_IP}\t- $i"; 

  done
}

## Executes a command on the container passed as argument
## Usage:
##   op_exec <container name> <consul_ip:consul:port> <token> <command>
## Ecample:
##   op_exec operator ${SERVER_IP}:443 ${CONSUL_HTTP_TOKEN} "consul members"
op_exec() {

  local CONTAINER_NAME=$1
  local CONSUL_SERVER_AND_PORT=$2
  local CONSUL_TOKEN=$3
  local CONSUL_COMMAND=$4

  log_container_command -h ${CONTAINER_NAME} "export CONSUL_HTTP_ADDR=https://${CONSUL_SERVER_AND_PORT}"
  log_container_command -b ${CONTAINER_NAME} "export CONSUL_HTTP_TOKEN=${CONSUL_TOKEN}"
  log_container_command -f ${CONTAINER_NAME} ${CONSUL_COMMAND}

  docker exec \
    -w /assets \
    --env CONSUL_HTTP_ADDR=https://${CONSUL_SERVER_AND_PORT} \
    --env CONSUL_HTTP_TOKEN=${CONSUL_TOKEN} \
    --env CONSUL_HTTP_SSL=true \
    --env CONSUL_HTTP_SSL_VERIFY=false \
    ${CONTAINER_NAME} bash -c "${CONSUL_COMMAND}"

}

vault_exec() {

  local CONTAINER_NAME=$1
  local VAULT_SERVER_AND_PORT=$2
  local V_TOKEN=$3
  local VAULT_COMMAND="${@:4}"

  log_container_command -h ${CONTAINER_NAME} "export VAULT_ADDR=${VAULT_SERVER_AND_PORT}"
  log_container_command -b ${CONTAINER_NAME} "export VAULT_TOKEN=${V_TOKEN}"
  log_container_command -f ${CONTAINER_NAME} ${VAULT_COMMAND}

  docker exec \
    -w /assets \
    --env VAULT_ADDR=${VAULT_SERVER_AND_PORT} \
    --env VAULT_TOKEN=${V_TOKEN} \
    ${CONTAINER_NAME} sh -c "${VAULT_COMMAND}"

}

envoy_exec() {

  local CONTAINER_NAME=$1
  local C_TOKEN=$2
  local COMMAND="${@:3}"

  log_container_command -h ${CONTAINER_NAME} "export CONSUL_HTTP_ADDR=127.0.0.1:8500"
  log_container_command -b ${CONTAINER_NAME} "export CONSUL_GRPC_ADDR=127.0.0.1:8502"
  log_container_command -b ${CONTAINER_NAME} "export CONSUL_HTTP_TOKEN=${CONSUL_AGENT_TOKEN}"
  log_container_command -f ${CONTAINER_NAME} ${COMMAND}

  ## Start api sidecar
  docker exec \
    --env CONSUL_HTTP_ADDR='127.0.0.1:8500' \
    --env CONSUL_GRPC_ADDR='127.0.0.1:8502' \
    --env CONSUL_HTTP_TOKEN="${C_TOKEN}" \
    ${CONTAINER_NAME} sh -c "$COMMAND"

}

cont_exec() {

  local CONTAINER_NAME=$1
  local C_TOKEN=$2
  local COMMAND="${@:3}"

  log_container_command -h ${CONTAINER_NAME} "export CONSUL_HTTP_ADDR=http://127.0.0.1:8500"
  log_container_command -b ${CONTAINER_NAME} "export CONSUL_HTTP_TOKEN=${CONSUL_AGENT_TOKEN}"
  log_container_command -f ${CONTAINER_NAME} ${COMMAND}

  ## Start api sidecar
  docker exec \
    --env CONSUL_HTTP_ADDR='http://127.0.0.1:8500' \
    --env CONSUL_HTTP_TOKEN="${C_TOKEN}" \
    ${CONTAINER_NAME} sh -c "$COMMAND"

}

spin_service() {
  echo pippo
}

# ++-----------------+
# || Variables       |
# ++-----------------+

# --- CONSUL ---

## Number of servers to spin up (3 or 5 recommended for production environment)
SERVER_NUMBER=3

## Define datacenter and domain for the sandbox Consul DC
DATACENTER="dc1"
DOMAIN="consul"

# --- DOCKER IMAGE ---

## For the sandbox I used a Docker container to simulate a VM-like scenario
## The Docker image was built starting from envoyproxy/envoy-alpine to easily
## provide the Envoy proxy and Consul binary was added alongside with a go
## application (/usr/local/bin/fake-service) that will be used to simulate a
## three-tier application scenario.
IMAGE_NAME=danielehc/consul-learn-image

CONSUL_VERSION=${CONSUL_VERSION:="1.10.1"}
ENVOY_VERSION=${ENVOY_VERSION:="1.18.3"}
IMAGE_TAG=v${CONSUL_VERSION}-v${ENVOY_VERSION}

VAULT_VERSION="latest"

## Defines vault running mode
## It can be one between DEV and PROD
VAULT_MODE=${VAULT_MODE:="PROD"}

# --- VAULT INTEGRATION ---

## If true uses Vault to generate Consul TLS certificates
VAULT_TLS="true"

## If true uses Vault as Consul Connect CA
VAULT_CONNECT_CA="true"

# --- ENVIRONMENT ---

## Docker tag for resources
DK_TAG="learn"

## Paths for the environment
ASSETS="./assets/"  ## Configuration and secrets
LOGS="./logs/"      ## Logs for the Consul agents and services
BIN="./bin/"        ## Binary for local tools
PROVISION_LOG_FILE="${LOGS}provision.log"

# ++-----------------+
# || Begin           |
# ++-----------------+

## Check Parameters
if   [ "$1" == "clean" ]; then

  clean_env
  exit 0

elif [ "$1" == "ports" ]; then

  show_ports
  exit 0

elif [ "$1" == "ips" ]; then

  show_ips
  exit 0

elif [ "$1" == "env" ]; then

  print_vars
  exit 0

elif [ "$1" == "commands" ]; then

  LOG_LEVEL="COM"

elif [ "$1" == "help" ] || [ "$1" == "-h" ]; then

  header "Consul DC in Docker provision script"

  echo -e "Usage:\n"
  echo -e "  `basename $0` \t\t- Deploys a Consul datacenter in Docker"
  echo -e "  `basename $0` clean \t\t- Cleans the environment and removes all resources"
  echo -e "  `basename $0` ports \t\t- Shows ports used by all containers"
  echo -e "  `basename $0` env \t\t- Prints environment variables to setup terminal"
  echo -e "  `basename $0` help|-h \t- Prints this text"

  exit 0

fi

########## ------------------------------------------------
header     "PREREQUISITES CHECK"
###### -----------------------------------------------

log "Cleaning Environment"
clean_env

mkdir -p ${ASSETS}secrets
mkdir -p ${ASSETS}data
mkdir -p ${LOGS}

touch ${PROVISION_LOG_FILE}

log "Pulling Docker Images"
docker pull ${IMAGE_NAME}:${IMAGE_TAG} > /dev/null
docker pull vault:${VAULT_VERSION} > /dev/null

########## ------------------------------------------------
header     "GENERATE NETWORKS"
###### -----------------------------------------------

docker network create primary   --subnet=172.19.0.0/24 --label tag=${DK_TAG}
# docker network create secondary --subnet=172.19.2.0/24 --label tag=${DK_TAG}
# docker network create public    --subnet=172.19.0.0/24 --label tag=${DK_TAG}

########## ------------------------------------------------
header     "VAULT - Starting Vault server"
###### -----------------------------------------------

if [[ ${VAULT_MODE} == "DEV" ]]; then

  log "Starting HashiCorp Vault in Dev Mode..."

  ## Starting Vault in DEV mode, not recommended for PROD
  docker run \
    -d \
    -v ${PWD}/assets:/assets \
    --net primary \
    -p 8200:8200 \
    --name=vault \
    --hostname=vault \
    --label tag=${DK_TAG} \
    --label dc=${DATACENTER} \
    --cap-add=IPC_LOCK \
    -e 'VAULT_DEV_ROOT_TOKEN_ID=password'  \
    vault:${VAULT_VERSION}

  log_container_command vault

  ## Retrieve newly created server IP
  VAULT_IP=`docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' vault`

  VAULT_ADDR='http://127.0.0.1:8200'
  VAULT_TOKEN="password"

elif [[ ${VAULT_MODE} == "PROD" ]]; then

  log "Starting HashiCorp Vault in Prod Mode..."

  # TODO: For now Vault is insecure and single node. Better deploy might be needed.

  docker run \
    -d \
    -v ${PWD}/assets:/assets \
    --net primary \
    -p 8200:8200 \
    --name=vault \
    --hostname=vault \
    --label tag=${DK_TAG} \
    --label dc=${DATACENTER} \
    --cap-add=IPC_LOCK \
    vault:${VAULT_VERSION} \
    server -log-level=debug -config=/assets/vault-server-config.hcl > ./logs/vault.log 2>&1
  
  log_container_command vault

  sleep 1

  ## Retrieve newly created server IP
  VAULT_IP=`docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' vault`

  VAULT_ADDR='http://127.0.0.1:8200'
  
  ## Initialize Vault server
  log "Initializing Vault"
  vault_exec vault $VAULT_ADDR "" "vault operator init -key-shares=1 -key-threshold=1 -format=json" > assets/secrets/vault-init.json

  VAULT_UNSEAL_KEY=`cat assets/secrets/vault-init.json | jq -r '.unseal_keys_b64[0]'`
  VAULT_TOKEN=`cat assets/secrets/vault-init.json | jq -r '.root_token'`

  ## Unseal Vault server
  log "Unsealing Vault"

  vault_exec vault $VAULT_ADDR "" "vault operator unseal ${VAULT_UNSEAL_KEY}" > assets/secrets/vault-unseal.log

else

  log "Not starting Vault"

  ## If true uses Vault to generate Consul TLS certificates
  VAULT_TLS="false"

  ## If true uses Vault as Consul Connect CA
  VAULT_CONNECT_CA="false"

fi

########## ------------------------------------------------
header     "GENERATE DYNAMIC CONFIGURATION"
###### -----------------------------------------------

log "Starting Operator container"

docker run \
  -d \
  -v ${PWD}/assets:/assets \
  --net primary \
  --user $(id -u):$(id -g) \
  --name=operator \
  --hostname=operator \
  --label tag=${DK_TAG} \
  ${IMAGE_NAME}:${IMAGE_TAG} "" > /dev/null 2>&1

log "Generating Consul TLS certificates and gossip key"

echo "Generate gossip encryption key"

docker exec \
  -w /assets/secrets \
  operator bash -c \
    'echo encrypt = \"$(consul keygen)\" > agent-gossip-encryption.hcl;'

echo "Generate server certificates and config files"

if [ "${VAULT_TLS}" == "true" ] ; then

  echo "Using Vault as CA"

  log "Configure root CA"

  ## Enable and tune pki secrets engine
  vault_exec vault $VAULT_ADDR $VAULT_TOKEN "vault secrets enable pki"

  vault_exec vault $VAULT_ADDR $VAULT_TOKEN "vault secrets tune -max-lease-ttl=87600h pki"

  # Generate the root CA
  vault_exec vault $VAULT_ADDR $VAULT_TOKEN \
    "vault write -field=certificate \
      pki/root/generate/internal \
      common_name=${DATACENTER}.${DOMAIN} \
      ttl=87600h" > ${ASSETS}secrets/vault_root_CA_cert.crt

  # Configure CA and CRL URLs
  vault_exec vault $VAULT_ADDR $VAULT_TOKEN \
    'vault write pki/config/urls \
      issuing_certificates="http://127.0.0.1:8200/v1/pki/ca" \
      crl_distribution_points="http://127.0.0.1:8200/v1/pki/crl"'

  log "Configure intermediate CA"

  vault_exec vault $VAULT_ADDR $VAULT_TOKEN \
    'vault secrets enable -path=pki_int pki'

  vault_exec vault $VAULT_ADDR $VAULT_TOKEN \
    "vault secrets tune -max-lease-ttl=43800h pki_int"

  # Request an intermediate certificate signing request (CSR)
  vault_exec vault $VAULT_ADDR $VAULT_TOKEN \
    "vault write -format=json \
      pki_int/intermediate/generate/internal \
      common_name=\"${DATACENTER}.${DOMAIN}_intermediate_authority\"" \
      | jq -r '.data.csr' > ${ASSETS}secrets/pki_intermediate.csr

  # Sign the CSR and import the certificate into Vault
  vault_exec vault $VAULT_ADDR $VAULT_TOKEN \
    "vault write -format=json pki/root/sign-intermediate \
      csr=@./secrets/pki_intermediate.csr \
      format=pem_bundle ttl=43800h" | jq -r '.data.certificate' > ${ASSETS}secrets/intermediate.cert.pem

  vault_exec vault $VAULT_ADDR $VAULT_TOKEN \
    'vault write pki_int/intermediate/set-signed \
      certificate=@./secrets/intermediate.cert.pem'

  log "Create Vault role for Consul DC"

  vault_exec vault $VAULT_ADDR $VAULT_TOKEN \
  "vault write pki_int/roles/${DOMAIN}-${DATACENTER} \
      allowed_domains=${DATACENTER}.${DOMAIN} \
      allow_subdomains=true \
      generate_lease=true \
      max_ttl=720h"

  for ((i = 1 ; i <= ${SERVER_NUMBER} ; i++)); do

    ## Create certificates
    vault_exec vault $VAULT_ADDR $VAULT_TOKEN \
      "vault write -format=json \
        pki_int/issue/${DOMAIN}-${DATACENTER} \
        common_name=server.${DATACENTER}.${DOMAIN} \
        ttl=24h" | jq -j '.data.certificate, "\u0000", .data.private_key, "\u0000", .data.issuing_ca, "\u0000"' \
        | { IFS= read -r -d '' cert && printf '%s\n' "$cert" > ./assets/secrets/server.${i}.${DATACENTER}.${DOMAIN}.crt;
            IFS= read -r -d '' key && printf '%s\n' "$key" > ./assets/secrets/server.${i}.${DATACENTER}.${DOMAIN}.key;
            IFS= read -r -d '' ca && printf '%s\n' "$ca" > ./assets/secrets/consul-agent-ca.pem; }

    ## Create configuration files
    tee ${ASSETS}secrets/agent-${DATACENTER}-server-$i-tls.hcl > /dev/null << EOF
ca_file   = "/assets/secrets/consul-agent-ca.pem"
cert_file = "assets/secrets/server.${i}.${DATACENTER}.${DOMAIN}.crt"
key_file  = "/assets/secrets/server.${i}.${DATACENTER}.${DOMAIN}.key"
EOF

  done

fi

## If the CA certificate does not exist at this point means that one is needed.
## Used to fallback to Consul embedded CA for connect.
## TODO: This is a hacky escape I should make modules and conditions.
# rm -rf "./assets/secrets/consul-agent-ca.pem"

if [ ! -f "./assets/secrets/consul-agent-ca.pem" ]; then

  echo "Using Consul CA for certificates"

  echo "Generate CA root certificate"

  docker exec \
    -w /assets/secrets \
    operator bash -c \
      "consul tls ca create consul-agent-ca.pem -domain=${DOMAIN} > /dev/null 2>&1;"
      
      # > /dev/null 2>&1;" 

  echo Generate certificate for servers;
  
  docker exec \
    -w /assets/secrets \
    operator bash -c \
      "for ((i = 0 ; i <= ${SERVER_NUMBER} ; i++)); do \
        consul tls cert create -server -ca=consul-agent-ca.pem -key=consul-agent-ca-key.pem -domain=${DOMAIN} -dc=${DATACENTER} > /dev/null 2>&1; \
      done" 

# > /dev/null 2>&1; \

  for ((i = 1 ; i <= ${SERVER_NUMBER} ; i++)); do
    tee ${ASSETS}secrets/agent-${DATACENTER}-server-$i-tls.hcl > /dev/null << EOF
ca_file   = "/assets/secrets/consul-agent-ca.pem"
cert_file = "/assets/secrets/${DATACENTER}-server-${DOMAIN}-${i}.pem"
key_file  = "/assets/secrets/${DATACENTER}-server-${DOMAIN}-${i}-key.pem"
EOF
done

fi

log "Configure CA for service mesh"

if [ "${VAULT_CONNECT_CA}" == "true" ] ; then

  echo "Using Vault as Connect CA"

  tee ${ASSETS}secrets/agent-server-connect-ca.hcl > /dev/null << EOF
## Service mesh CA configuration
connect {
  ca_provider = "vault"
  ca_config {
      address = "http://${VAULT_IP}:8200"
      token = "${VAULT_TOKEN}"
      root_pki_path = "connect-root"
      intermediate_pki_path = "connect-intermediate"
      leaf_cert_ttl = "1h"
      rotation_period = "1h"
      intermediate_cert_ttl = "3h"
      private_key_type = "rsa"
      private_key_bits = 2048
  }
}
EOF

else

  echo "Using Consul Connect CA"

  tee ${ASSETS}secrets/agent-server-connect-ca.hcl > /dev/null << EOF
## Service mesh CA configuration
connect {
  ca_provider = "consul"
  ca_config {
      leaf_cert_ttl = "1h"
      rotation_period = "1h"
      intermediate_cert_ttl = "3h"
  }
}
EOF

# ==> Intermediate Cert TTL must be greater or equal than 3h

fi

########## ------------------------------------------------
header     "CONSUL - Starting Primary Datacenter"
###### -----------------------------------------------

## These vartiables will store the IPs for the servers while they get generated.
## Will be used as a parameter for other nodes to join the datacenter.
RETRY_JOIN=""
RETRY_JOIN_WAN=""

for i in $(seq 1 ${SERVER_NUMBER}); do 

  log "Starting Consul server $i"
  docker run \
    -d \
    -v ${PWD}/assets:/assets \
    -v ${PWD}/logs:/logs \
    --net primary \
    -p ${i}443:443 \
    --name=server-$i \
    --hostname=server-$i \
    --label tag=${DK_TAG} \
    --label dc=${DATACENTER} \
    --dns=127.0.0.1 \
    --dns-search=consul \
    --user=1000:1000 \
    ${IMAGE_NAME}:${IMAGE_TAG} \
    consul agent -server -ui \
      -datacenter=${DATACENTER} \
      -domain=${DOMAIN} \
      -node=server-$i \
      -client=127.0.0.1 \
      -bootstrap-expect=${SERVER_NUMBER} \
      -retry-join=${RETRY_JOIN} \
      -log-file="/logs/consul-server-$i" \
      -config-file=/assets/agent-server-connect.hcl \
      -config-file=/assets/secrets/agent-server-connect-ca.hcl \
      -config-file=/assets/agent-server-secure.hcl \
      -config-file=/assets/secrets/agent-${DATACENTER}-server-$i-tls.hcl \
      -config-file=/assets/secrets/agent-gossip-encryption.hcl > ${LOGS}/docker-server-$i.log 2>&1
  
  ## Logs container command if PROVISION_LOG is enabled
  log_container_command "server-$i"

  ## Retrieve newly created server IP
  SERVER_IP=`docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' server-$i`

  ## Generate the retry-join string
  if [ -z "${RETRY_JOIN}" ]; then 
    RETRY_JOIN=${SERVER_IP};
    RETRY_JOIN_WAN=${SERVER_IP}; 
  else 
    RETRY_JOIN="${RETRY_JOIN} -retry-join=${SERVER_IP}";
    RETRY_JOIN_WAN="${RETRY_JOIN_WAN} -retry-join-wan=${SERVER_IP}";
  fi
done

########## ------------------------------------------------
header     "CONSUL - ACL configuration"
###### -----------------------------------------------

log "ACL Bootstrap"

## Tries to bootstrap the ACL system until it succeds
op_exec operator ${SERVER_IP}:443 "" \
  "while ! consul acl bootstrap > ./secrets/acl-bootstrap.conf 2> /dev/null; do echo 'ACL system not ready. Retrying...'; sleep 5; done"

## Exports the Bootstrap Token
export CONSUL_HTTP_TOKEN=`cat ${ASSETS}/secrets/acl-bootstrap.conf | grep SecretID | awk '{print $2}'`

# TODO - Best Practice - Create a new token based on global-management policy

log "Create ACL Policies"

## DNS Policy for default tokens
op_exec operator ${SERVER_IP}:443 ${CONSUL_HTTP_TOKEN} \
  "consul acl policy create -name 'acl-policy-dns' -description 'Policy for DNS endpoints' -rules @acl-policy-dns.hcl  > /dev/null 2>&1"

## Policy for server nodes
op_exec operator ${SERVER_IP}:443 ${CONSUL_HTTP_TOKEN} \
  "consul acl policy create -name 'acl-policy-server-node' -description 'Policy for Server nodes' -rules @acl-policy-server-node.hcl  > /dev/null 2>&1"

log "Create ACL Tokens"

op_exec operator ${SERVER_IP}:443 ${CONSUL_HTTP_TOKEN} \
  "consul acl token create -description 'DNS - Default token' -policy-name acl-policy-dns > ./secrets/acl-dns-token.conf 2> /dev/null"

DNS_TOK=`cat ${ASSETS}secrets/acl-dns-token.conf | grep SecretID | awk '{print $2}'` 

## Create one agent token per server
for i in `seq 1 ${SERVER_NUMBER}`; do

  IP_ADDR=`docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' server-$i`

  op_exec operator ${SERVER_IP}:443 ${CONSUL_HTTP_TOKEN} \
    "consul acl token create -description \"server-$i agent token\" -policy-name acl-policy-server-node > ./secrets/acl-server-$i-token.conf 2> /dev/null"

  TOK=`cat ${ASSETS}secrets/acl-server-$i-token.conf | grep SecretID | awk '{print $2}'`

  op_exec operator ${IP_ADDR}:443 ${CONSUL_HTTP_TOKEN} \
    "consul acl set-agent-token agent ${TOK}"

  op_exec operator ${IP_ADDR}:443 ${CONSUL_HTTP_TOKEN} \
    "consul acl set-agent-token default ${DNS_TOK}"

done

########## ------------------------------------------------
header     "CONSUL - Service Mesh configuration"
###### -----------------------------------------------

log "Apply Configuration Entries"

## Envoy Proxy Defaults
op_exec operator ${SERVER_IP}:443 ${CONSUL_HTTP_TOKEN} \
  "consul config write config-proxy-defaults.hcl"

op_exec operator ${SERVER_IP}:443 ${CONSUL_HTTP_TOKEN} \
  "consul config write config-service-api.hcl"

op_exec operator ${SERVER_IP}:443 ${CONSUL_HTTP_TOKEN} \
  "consul config write config-service-web.hcl"

## Intention web > api
op_exec operator ${SERVER_IP}:443 ${CONSUL_HTTP_TOKEN} \
  "consul config write config-intentions-api.hcl"


########## ------------------------------------------------
header     "CONSUL - Starting Client Agents"
###### -----------------------------------------------

## TODO: Generate different token for client nodes
## Create policy for service nodes

## Policy for service nodes
# op_exec operator ${SERVER_IP}:443 ${CONSUL_HTTP_TOKEN} \
#   "consul acl policy create -name 'acl-policy-service-node' -description 'Policy for client nodes named service-*' -rules @acl-policy-service-node.hcl  > /dev/null 2>&1"

## Policy for service
# op_exec operator ${SERVER_IP}:443 ${CONSUL_HTTP_TOKEN} \
#   "consul acl policy create -name 'acl-policy-service' -description 'Policy to register services' -rules @acl-policy-service.hcl  > /dev/null 2>&1"

# log "Create client ACL Tokens"

# op_exec operator ${SERVER_IP}:443 ${CONSUL_HTTP_TOKEN} \
#   "consul acl token create -description 'Client - Default token' -policy-name acl-policy-service-node -policy-name acl-policy-service > ./secrets/acl-clients-agent-token.conf 2> /dev/null"

# CLIENT_TOK=`cat ${ASSETS}secrets/acl-clients-agent-token.conf | grep SecretID | awk '{print $2}'` 

CONSUL_AGENT_TOKEN=${CONSUL_HTTP_TOKEN}

tee ${ASSETS}secrets/agent-client-tokens.hcl > /dev/null << EOF
acl {
  tokens {
    agent  = "${CONSUL_AGENT_TOKEN}"
    default  = "${DNS_TOK}"
  }
}
EOF

## API
docker run \
  -d \
  -v ${PWD}/assets:/assets \
  -v ${PWD}/logs:/logs \
  --net primary \
  --name=api \
  --hostname=api \
  --label tag=${DK_TAG} \
  --dns=127.0.0.1 \
  --dns-search=consul \
  --user=1000:1000 \
  ${IMAGE_NAME}:${IMAGE_TAG} \
  consul agent \
    -datacenter=${DATACENTER} \
    -domain=${DOMAIN} \
    -node=service-1 \
    -retry-join=${RETRY_JOIN} \
    -log-file="/logs/consul-client-api" \
    -config-file=/assets/agent-client-connect.hcl \
    -config-file=/assets/agent-client-secure.hcl \
    -config-file=/assets/secrets/agent-gossip-encryption.hcl \
    -config-file=/assets/secrets/agent-client-tokens.hcl > ${LOGS}/docker-client-api.log 2>&1

## Logs container command if PROVISION_LOG is enabled
log_container_command api

## FRONTEND
docker run \
  -d \
  -v ${PWD}/assets:/assets \
  -v ${PWD}/logs:/logs \
  --net primary \
  -p 9002:9002 \
  --name=web \
  --hostname=web \
  --label tag=${DK_TAG} \
  --dns=127.0.0.1 \
  --dns-search=consul \
  --user=1000:1000 \
  ${IMAGE_NAME}:${IMAGE_TAG} \
  consul agent \
    -datacenter=${DATACENTER} \
    -domain=${DOMAIN} \
    -node=service-2 \
    -retry-join=${RETRY_JOIN} \
    -log-file="/logs/consul-client-web" \
    -config-file=/assets/agent-client-connect.hcl \
    -config-file=/assets/agent-client-secure.hcl \
    -config-file=/assets/secrets/agent-gossip-encryption.hcl \
    -config-file=/assets/secrets/agent-client-tokens.hcl > ${LOGS}/docker-client-web.log 2>&1

## Logs container command if PROVISION_LOG is enabled
log_container_command web

########## ------------------------------------------------
header     "CONSUL - Adding services to the service mesh"
###### -----------------------------------------------

## Start API
cont_exec api ${CONSUL_HTTP_TOKEN} \
  "LISTEN_ADDR=127.0.0.1:9003 NAME=api fake-service > /logs/service-api.log 2>&1 &"
## Start WEB
cont_exec web ${CONSUL_HTTP_TOKEN} \
  "LISTEN_ADDR=0.0.0.0:9002 NAME=web UPSTREAM_URIS=\"http://localhost:5000\" fake-service > /logs/service-web.log 2>&1 &"

cont_exec api ${CONSUL_HTTP_TOKEN} \
  "consul services register /assets/svc-api.hcl"

cont_exec web ${CONSUL_HTTP_TOKEN} \
  "consul services register /assets/svc-web.hcl"

log "Start Envoy sidecar proxies"

## Once the services are registered in Consul and the upstream dependencies are
## specified 
envoy_exec api ${CONSUL_AGENT_TOKEN} \
  "consul connect envoy -sidecar-for api-1 -admin-bind 0.0.0.0:19001 -- -l debug > /logs/sidecar-proxy-api.log 2>&1 &"  

## Start web sidecar
envoy_exec web ${CONSUL_AGENT_TOKEN} \
  "consul connect envoy -sidecar-for web -admin-bind 0.0.0.0:19001 -- -l debug > /logs/sidecar-proxy-web.log 2>&1 &"  


########## ------------------------------------------------
header     "CONSUL - Configure your local environment"
###### -----------------------------------------------

# ++-----------------+
# || Output          |
# ++-----------------+

print_vars consul | tee ${ASSETS}secrets/consul_env.conf
print_vars vault  | tee ${ASSETS}secrets/vault_env.conf
# print_vars curl  | tee ${ASSETS}secrets/curl_env.conf

## Only for katacoda, completes the provision
# finish