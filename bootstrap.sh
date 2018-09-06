#!/bin/bash
export LC_ALL=C
#
function -h {
  cat <<USAGE
   USAGE: Generates Traefik config
   -v / --verbose  debugging output
USAGE
}; function --help { -h ;}

function msg { out "$*" >&1 ;}
function out { printf '%s\n' "$*" ;}
function err { local x=$? ; msg "$*" ; return $(( $x == 0 ? 1 : $x )) ;}

function main {
  local verbose=false
  while [[ $# -gt 0 ]]
  do
    case "$1" in                                      # Munging globals, beware
      -v|--verbose)         verbose=true; shift 1 ;;
      *)                    err 'Argument error. Please see help: -h' ;;
    esac
  done
  if [[ $verbose == true ]]; then
    set -ex
  fi
  generate_config
  if [ -f traefik_linux-amd64 ]; then
    chmod +x traefik_linux-amd64
  fi
}

function generate_config {
  TRAEFIK_DCOS_CLUSTER_NAME=${TRAEFIK_DCOS_CLUSTER_NAME:-"dcos"}
  TRAEFIK_CONSUL_DOMAIN=${TRAEFIK_CONSUL_DOMAIN:-"service.dev.localdomain"}
  TRAEFIK_HTTP_COMPRESSION=${TRAEFIK_HTTP_COMPRESSION:-"true"}
  TRAEFIK_HTTPS_COMPRESSION=${TRAEFIK_HTTPS_COMPRESSION:-"true"}
  TRAEFIK_HTTP_ADDRESS=${TRAEFIK_HTTP_ADDRESS:-""}
  TRAEFIK_HTTP_PORT=${TRAEFIK_HTTP_PORT:-"80"}
  TRAEFIK_HTTPS_ENABLE=${TRAEFIK_HTTPS_ENABLE:-"false"}
  TRAEFIK_HTTPS_ADDRESS=${TRAEFIK_HTTP_ADDRESS:-""}
  TRAEFIK_HTTPS_PORT=${TRAEFIK_HTTPS_PORT:-"443"}
  TRAEFIK_HTTPS_REDIRECT_ENABLE=${TRAEFIK_HTTPS_REDIRECT_ENABLE:-"false"}
  TRAEFIK_API_ENABLE=${TRAEFIK_API_ENABLE:-"true"}
  TRAEFIK_API_PORT=${TRAEFIK_API_PORT:-"8080"}
  TRAEFIK_DEBUG=${TRAEFIK_DEBUG:="false"}
  TRAEFIK_INSECURE_SKIP=${TRAEFIK_INSECURE_SKIP:="false"}
  TRAEFIK_LOG_LEVEL=${TRAEFIK_LOG_LEVEL:-"INFO"}
  TRAEFIK_STATISTICS_RECENT_ERRORS=${TRAEFIK_STATISTICS_RECENT_ERRORS:-10}
  TRAEFIK_API_AUTH_METHOD=${TRAEFIK_API_AUTH_METHOD:-"basic"}
  TRAEFIK_API_AUTH_USERS=${TRAEFIK_API_AUTH_USERS:-""}
  TRAEFIK_PING_PORT=${TRAEFIK_PING_PORT:-"8081"}
  TRAEFIK_SSL_PATH=${TRAEFIK_SSL_PATH:-"$(pwd)/certs"}
  TRAEFIK_ACME_ENABLE=${TRAEFIK_ACME_ENABLE:-"false"}
  TRAEFIK_ACME_EMAIL=${TRAEFIK_ACME_EMAIL:-"test@traefik.io"}
  TRAEFIK_ACME_STORAGE=${TRAEFIK_ACME_STORAGE:-"$(pwd)/acme/acme.json"}
  TRAEFIK_ACME_ONHOSTRULE=${TRAEFIK_ACME_ONHOSTRULE:-"false"}
  TRAEFIK_ACME_CASERVER=${TRAEFIK_ACME_CASERVER:-"https://acme-v01.api.letsencrypt.org/directory"}
  TRAEFIK_ACME_DCOS_DOMAIN=$TRAEFIK_DCOS_CLUSTER_NAME.$TRAEFIK_CONSUL_DOMAIN
  TRAEFIK_ACME_DNS_PROVIDER=${TRAEFIK_ACME_DNS_PROVIDER:-"-"}
  TRAEFIK_ACME_DNS_DELAY=${TRAEFIK_ACME_DNS_DELAY:-"0"}
  TRAEFIK_K8S_ENABLE=${TRAEFIK_K8S_ENABLE:-"false"}
  TRAEFIK_K8S_OPTS=${TRAEFIK_K8S_OPTS:-""}
  TRAEFIK_PROMETHEUS_ENABLE=${TRAEFIK_PROMETHEUS_ENABLE:-"false"}
  TRAEFIK_PROMETHEUS_OPTS=${TRAEFIK_PROMETHEUS_OPTS:-""}
  TRAEFIK_PROMETHEUS_ENTRYPOINT=${TRAEFIK_PROMETHEUS_ENTRYPOINT:-"traefik"}
  TRAEFIK_PROMETHEUS_BUCKETS=${TRAEFIK_PROMETHEUS_BUCKETS:-"[0.1,0.3,1.2,5.0]"}
  TRAEFIK_RANCHER_ENABLE=${TRAEFIK_RANCHER_ENABLE:-"false"}
  TRAEFIK_RANCHER_REFRESH=${TRAEFIK_RANCHER_REFRESH:-15}
  TRAEFIK_RANCHER_MODE=${TRAEFIK_RANCHER_MODE:-"api"}
  TRAEFIK_RANCHER_DOMAIN=${TRAEFIK_RANCHER_DOMAIN:-"rancher.internal"}
  TRAEFIK_RANCHER_EXPOSE=${TRAEFIK_RANCHER_EXPOSE:-"false"}
  TRAEFIK_RANCHER_HEALTHCHECK=${TRAEFIK_RANCHER_HEALTHCHECK:-"true"}
  TRAEFIK_RANCHER_INTERVALPOLL=${TRAEFIK_RANCHER_INTERVALPOLL:-"false"}
  TRAEFIK_RANCHER_OPTS=${TRAEFIK_RANCHER_OPTS:-""}
  TRAEFIK_RANCHER_PREFIX=${TRAEFIK_RANCHER_PREFIX:-"/2017-11-11"}
  TRAEFIK_FILE_NAME=${TRAEFIK_FILE_NAME:-"rules.toml"}
  TRAEFIK_FILE_WATCH=${TRAEFIK_FILE_WATCH:="true"}
  CATTLE_URL=${CATTLE_URL:-""}
  CATTLE_ACCESS_KEY=${CATTLE_ACCESS_KEY:-""}
  CATTLE_SECRET_KEY=${CATTLE_SECRET_KEY:-""}
  TRAEFIK_MARATHON_ENABLE=${TRAEFIK_MARATHON_ENABLE:-"true"}
  TRAEFIK_MARATHON_ENDPOINT=${TRAEFIK_MARATHON_ENDPOINT:-"http://marathon.mesos:8080"}
  TRAEFIK_MARATHON_WATCH=${TRAEFIK_MARATHON_WATCH:-"true"}
  TRAEFIK_MARATHON_LB_COMPATIBILITY=${TRAEFIK_MARATHON_LB_COMPATIBILITY:-"false"}
  TRAEFIK_MARATHON_DOMAIN=$TRAEFIK_DCOS_CLUSTER_NAME.$TRAEFIK_CONSUL_DOMAIN
  TRAEFIK_MARATHON_OPTS=${TRAEFIK_MARATHON_OPTS:-""}
  TRAEFIK_MARATHON_EXPOSE=${TRAEFIK_MARATHON_EXPOSE:-"true"}
  TRAEFIK_MARATHON_GROUPS_AS_SUBDOMAINS=${TRAEFIK_MARATHON_GROUPS_AS_SUBDOMAINS:-"false"}
  TRAEFIK_MARATHON_DIALER_TIMEOUT=${TRAEFIK_MARATHON_DIALER_TIMEOUT:-"60s"}
  TRAEFIK_MARATHON_KEEP_ALIVE=${TRAEFIK_MARATHON_KEEP_ALIVE:-"10s"}
  TRAEFIK_MARATHON_FORCE_TASK_HOSTNAME=${TRAEFIK_MARATHON_FORCE_TASK_HOSTNAME:-"false"}
  TRAEFIK_MARATHON_RESPECT_READINESS_CHECKS=${TRAEFIK_MARATHON_RESPECT_READINESS_CHECKS:-"false"}

TRAEFIK_ENTRYPOINTS_HTTP="\
  [entryPoints.http]
  address = \"${TRAEFIK_HTTP_ADDRESS}:${TRAEFIK_HTTP_PORT}\"
  compress = ${TRAEFIK_HTTP_COMPRESSION}
"

if [ "X${TRAEFIK_HTTPS_ENABLE}" == "Xtrue" ]; then
  TRAEFIK_ENTRYPOINTS_HTTPS="\
  [entryPoints.https]
  address = \"${TRAEFIK_HTTPS_ADDRESS}:${TRAEFIK_HTTPS_PORT}\"
  compress = ${TRAEFIK_HTTPS_COMPRESSION}
    [entryPoints.https.tls]
"

  if [ -d "${TRAEFIK_SSL_PATH}" ]; then
    filelist=`ls -1 ${TRAEFIK_SSL_PATH}/*.key | rev | cut -d"." -f2- | rev`
    RC=`echo $?`

    if [ $RC -eq 0 ]; then
      for i in $filelist; do
        if [ -f "$i.crt" ]; then
          TRAEFIK_ENTRYPOINTS_HTTPS=$TRAEFIK_ENTRYPOINTS_HTTPS"
      [[entryPoints.https.tls.certificates]]
      certFile = \"${i}.crt\"
      keyFile = \"${i}.key\"
"
        fi
      done
    fi
  fi

  if [ "X${TRAEFIK_HTTPS_REDIRECT_ENABLE}" == "Xtrue" ]; then
    TRAEFIK_ENTRYPOINTS_HTTP=$TRAEFIK_ENTRYPOINTS_HTTP"\
    [entryPoints.http.redirect]
       entryPoint = \"https\"
"
  fi

  TRAEFIK_ENTRYPOINTS_OPTS=${TRAEFIK_ENTRYPOINTS_HTTP}${TRAEFIK_ENTRYPOINTS_HTTPS}
  TRAEFIK_ENTRYPOINTS='"http", "https"'
else
  TRAEFIK_ENTRYPOINTS_OPTS=${TRAEFIK_ENTRYPOINTS_HTTP}
  TRAEFIK_ENTRYPOINTS='"http"'
fi

if [ "X${TRAEFIK_API_ENABLE}" == "Xtrue" ]; then
  TRAEFIK_ENTRYPOINTS_API="\
  [entryPoints.traefik]
  address = \":${TRAEFIK_API_PORT}\"
"
    if [ "${TRAEFIK_API_AUTH_USERS}" != "" ]; then
      echo ${TRAEFIK_API_AUTH_USERS} > "$(pwd)/.htpasswd"
      TRAEFIK_ENTRYPOINTS_API=$TRAEFIK_ENTRYPOINTS_API"\
    [entryPoints.traefik.auth]
      [entryPoints.traefik.auth.${TRAEFIK_API_AUTH_METHOD}]
      usersFile = \"$(pwd)/.htpasswd\"
"
    fi
  TRAEFIK_ENTRYPOINTS_OPTS=${TRAEFIK_ENTRYPOINTS_OPTS}${TRAEFIK_ENTRYPOINTS_API}
fi

TRAEFIK_ENTRYPOINTS_PING="\
  [entryPoints.ping]
  address = \":${TRAEFIK_PING_PORT}\"
"
TRAEFIK_ENTRYPOINTS_OPTS=${TRAEFIK_ENTRYPOINTS_OPTS}${TRAEFIK_ENTRYPOINTS_PING}

if [ "X${TRAEFIK_K8S_ENABLE}" == "Xtrue" ]; then
    TRAEFIK_K8S_OPTS="[kubernetes]"
fi

if [ "X${TRAEFIK_HTTPS_ENABLE}" == "Xtrue" ] && [ "X${TRAEFIK_ACME_ENABLE}" == "Xtrue" ]; then
  TRAEFIK_ACME_CFG="\

[acme]
email = \"${TRAEFIK_ACME_EMAIL}\"
storage = \"${TRAEFIK_ACME_STORAGE}\"
onHostRule = ${TRAEFIK_ACME_ONHOSTRULE}
caServer = \"${TRAEFIK_ACME_CASERVER}\"
entryPoint = \"https\"
  [acme.dnsChallenge]
    provider = \"${TRAEFIK_ACME_DNS_PROVIDER}\"
    delayBeforeCheck = ${TRAEFIK_ACME_DNS_DELAY}
  [[acme.domains]]
    main = \"*.${TRAEFIK_ACME_DCOS_DOMAIN}\"
"
fi

if [ "X${TRAEFIK_RANCHER_ENABLE}" == "Xtrue" ]; then
    TRAEFIK_RANCHER_OPTS="\
[rancher]
domain = \"${TRAEFIK_RANCHER_DOMAIN}\"
Watch = true
RefreshSeconds = ${TRAEFIK_RANCHER_REFRESH}
ExposedByDefault = ${TRAEFIK_RANCHER_EXPOSE}
EnableServiceHealthFilter = ${TRAEFIK_RANCHER_HEALTHCHECK}
"
    if [ "${TRAEFIK_RANCHER_MODE}" == "api" ]; then
        TRAEFIK_RANCHER_OPTS=${TRAEFIK_RANCHER_OPTS}"
[rancher.api]
Endpoint = \"${CATTLE_URL}\"
AccessKey = \"${CATTLE_ACCESS_KEY}\"
SecretKey = \"${CATTLE_SECRET_KEY}\"
"
    elif [ "${TRAEFIK_RANCHER_MODE}" == "metadata" ]; then
        TRAEFIK_RANCHER_OPTS=${TRAEFIK_RANCHER_OPTS}"
[rancher.metadata]
IntervalPoll = ${TRAEFIK_RANCHER_INTERVALPOLL}
Prefix = \"${TRAEFIK_RANCHER_PREFIX}\"
"
    fi
fi

if [ "X${TRAEFIK_API_ENABLE}" == "Xtrue" ]; then
    TRAEFIK_API_CFG="\

[api]
entryPoint = \"traefik\"
dashboard = true
debug = ${TRAEFIK_DEBUG}
  [api.statistics]
  recentErrors = ${TRAEFIK_STATISTICS_RECENT_ERRORS}
"
fi

TRAEFIK_PING_CFG="\

[ping]
entryPoint = \"ping\"
"

# Metrics definition
if [ "X${TRAEFIK_PROMETHEUS_ENABLE}" == "Xtrue" ]; then
    TRAEFIK_PROMETHEUS_OPTS="\
[metrics]
  [metrics.prometheus]
  entryPoint = \"${TRAEFIK_PROMETHEUS_ENTRYPOINT}\"
  # Buckets for latency metrics
  #
  # Optional
  # Default: [0.1, 0.3, 1.2, 5]
  #
  buckets=${TRAEFIK_PROMETHEUS_BUCKETS}
"
fi

if [ -f "${TRAEFIK_FILE_NAME}" ]; then
    TRAEFIK_FILE_OPTS="\

[file]
filename = \"${TRAEFIK_FILE_NAME}\"
watch = ${TRAEFIK_FILE_WATCH}
"
fi

if [ "X${TRAEFIK_MARATHON_ENABLE}" == "Xtrue" ]; then
    TRAEFIK_MARATHON_OPTS="\

[marathon]
# Marathon server endpoint.
# You can also specify multiple endpoint for Marathon:
# endpoint = \"http://10.241.1.71:8080,10.241.1.72:8080,10.241.1.73:8080\"
#
endpoint = \"${TRAEFIK_MARATHON_ENDPOINT}\"
watch = ${TRAEFIK_MARATHON_WATCH}

# Default domain used.
# Can be overridden by setting the \"traefik.domain\" label on an application.
#
# Required
#
domain = \"${TRAEFIK_MARATHON_DOMAIN}\"

# Expose Marathon apps by default in Traefik.
#
# Optional
# Default: true
#
exposedByDefault = ${TRAEFIK_MARATHON_EXPOSE}

# Convert Marathon groups to subdomains.
# Default behavior: /foo/bar/myapp => foo-bar-myapp.{defaultDomain}
# with groupsAsSubDomains enabled: /foo/bar/myapp => myapp.bar.foo.{defaultDomain}
#
# Optional
# Default: false
#
groupsAsSubDomains = ${TRAEFIK_MARATHON_GROUPS_AS_SUBDOMAINS}

# Enable compatibility with marathon-lb labels.
#
# Optional
# Default: false
#
marathonLBCompatibility = ${TRAEFIK_MARATHON_LB_COMPATIBILITY}

# Enable Marathon basic authentication.
#
# Optional
#
#    [marathon.basic]
#    httpBasicAuthUser = \"foo\"
#    httpBasicPassword = \"bar\"

# TLS client configuration. https://golang.org/pkg/crypto/tls/#Config
#
# Optional
#
#    [marathon.TLS]
#    CA = \"/etc/ssl/ca.crt\"
#    Cert = \"/etc/ssl/marathon.cert\"
#    Key = \"/etc/ssl/marathon.key\"
#    InsecureSkipVerify = true

# DCOSToken for DCOS environment.
# This will override the Authorization header.
#
# Optional
#
# dcosToken = \"xxxxxx\"

# Override DialerTimeout.
# Amount of time to allow the Marathon provider to wait to open a TCP connection
# to a Marathon master.
# Can be provided in a format supported by [time.ParseDuration](https://golang.org/pkg/time/#ParseDuration) or as raw
# values (digits).
# If no units are provided, the value is parsed assuming seconds.
#
# Optional
# Default: \"60s\"
#
dialerTimeout = \"${TRAEFIK_MARATHON_DIALER_TIMEOUT}\"

# Set the TCP Keep Alive interval for the Marathon HTTP Client.
# Can be provided in a format supported by [time.ParseDuration](https://golang.org/pkg/time/#ParseDuration) or as raw
# values (digits).
# If no units are provided, the value is parsed assuming seconds.
#
# Optional
# Default: \"10s\"
#
keepAlive = \"${TRAEFIK_MARATHON_KEEP_ALIVE}\"

# By default, a task's IP address (as returned by the Marathon API) is used as
# backend server if an IP-per-task configuration can be found; otherwise, the
# name of the host running the task is used.
# The latter behavior can be enforced by enabling this switch.
#
# Optional
# Default: false
#
forceTaskHostname = ${TRAEFIK_MARATHON_FORCE_TASK_HOSTNAME}

# Applications may define readiness checks which are probed by Marathon during
# deployments periodically and the results exposed via the API.
# Enabling the following parameter causes Traefik to filter out tasks
# whose readiness checks have not succeeded.
# Note that the checks are only valid at deployment times.
# See the Marathon guide for details.
#
# Optional
# Default: false
#
respectReadinessChecks = ${TRAEFIK_MARATHON_RESPECT_READINESS_CHECKS}
"
fi

local opts=""
  if [ ! -z "${TRAEFIK_ENTRYPOINTS_OPTS}" ]; then
    opts+="${TRAEFIK_ENTRYPOINTS_OPTS}"
  fi
  if [ ! -z "${TRAEFIK_API_CFG}" ]; then
    opts+="${TRAEFIK_API_CFG}"
  fi
  if [ ! -z "${TRAEFIK_PING_CFG}" ]; then
    opts+="${TRAEFIK_PING_CFG}"
  fi
  if [ ! -z "${TRAEFIK_PROMETHEUS_OPTS}" ]; then
    opts+="${TRAEFIK_PROMETHEUS_OPTS}"
  fi
  if [ ! -z "${TRAEFIK_RANCHER_OPTS}" ]; then
    opts+="${TRAEFIK_RANCHER_OPTS}"
  fi
  if [ ! -z "${TRAEFIK_FILE_OPTS}" ]; then
    opts+="${TRAEFIK_FILE_OPTS}"
  fi
  if [ ! -z "${TRAEFIK_ACME_CFG}" ]; then
    opts+="${TRAEFIK_ACME_CFG}"
  fi
  if [ ! -z "${TRAEFIK_K8S_OPTS}" ]; then
    opts+="${TRAEFIK_K8S_OPTS}"
  fi
  if [ ! -z "${TRAEFIK_MARATHON_OPTS}" ]; then
    opts+="${TRAEFIK_MARATHON_OPTS}"
  fi


cat << EOF > ./traefik.toml
# traefik.toml
logLevel = "${TRAEFIK_LOG_LEVEL}"
InsecureSkipVerify = ${TRAEFIK_INSECURE_SKIP}
defaultEntryPoints = [${TRAEFIK_ENTRYPOINTS}]

[entryPoints]
${opts}
EOF
}


if [[ ${1:-} ]] && declare -F | cut -d' ' -f3 | fgrep -qx -- "${1:-}"
then
  case "$1" in
    -h|--help) : ;;
    *) ;;
  esac
  "$@"
else
  main "$@"
fi
