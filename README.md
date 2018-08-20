# dcos-traefik

[Traefik](https://traefik.io) package for DC/OS.

## Supported ENV variables

 * `TRAEFIK_DCOS_CLUSTER_NAME` Default `dcos`
 * `TRAEFIK_CONSUL_DOMAIN` Default `service.dev.localdomain`
 * `TRAEFIK_HTTP_COMPRESSION` Default `true`
 * `TRAEFIK_HTTPS_COMPRESSION` Default `true`
 * `TRAEFIK_HTTP_ADDRESS`
 * `TRAEFIK_HTTP_PORT` Default `80`
 * `TRAEFIK_HTTPS_ENABLE` Default `false`
 * `TRAEFIK_HTTPS_ADDRESS`
 * `TRAEFIK_HTTPS_PORT` Default `443`
 * `TRAEFIK_HTTPS_REDIRECT_ENABLE` Default `false`
 * `TRAEFIK_API_ENABLE` Default `true`
 * `TRAEFIK_API_PORT` Default `8080`
 * `TRAEFIK_DEBUG` Default `false`
 * `TRAEFIK_INSECURE_SKIP` Default `false`
 * `TRAEFIK_LOG_LEVEL` Default `INFO`
 * `TRAEFIK_STATISTICS_RECENT_ERRORS` Default `10`
 * `TRAEFIK_API_AUTH_METHOD` Default `basic`
 * `TRAEFIK_API_AUTH_USERS`
 * `TRAEFIK_PING_PORT` Default `8081`
 * `TRAEFIK_SSL_PATH` Default `$(pwd)/certs`
 * `TRAEFIK_ACME_ENABLE` Certificates from Let's Encrypt. Default `false`
 * `TRAEFIK_ACME_EMAIL` Default `test@traefik.io`
 * `TRAEFIK_ACME_STORAGE` Default `$(pwd)/acme/acme.json`
 * `TRAEFIK_ACME_ONHOSTRULE` Default `false`
 * `TRAEFIK_ACME_CASERVER` Default `https://acme-v01.api.letsencrypt.org/directory`
 * `TRAEFIK_ACME_DNS_PROVIDER` Default `-`
 * `TRAEFIK_K8S_ENABLE` Default `false`
 * `TRAEFIK_K8S_OPTS`
 * `TRAEFIK_PROMETHEUS_ENABLE` Default `false`
 * `TRAEFIK_PROMETHEUS_OPTS`
 * `TRAEFIK_PROMETHEUS_ENTRYPOINT` Default `traefik`
 * `TRAEFIK_PROMETHEUS_BUCKETS` Default `[0.1,0.3,1.2,5.0]`
 * `TRAEFIK_RANCHER_ENABLE` Default `false`
 * `TRAEFIK_RANCHER_REFRESH` Default `15`
 * `TRAEFIK_RANCHER_MODE` Default `api`
 * `TRAEFIK_RANCHER_DOMAIN` Default `rancher.internal`
 * `TRAEFIK_RANCHER_EXPOSED` Default `false`
 * `TRAEFIK_RANCHER_HEALTHCHECK` Default `true`
 * `TRAEFIK_RANCHER_INTERVALPOLL` Default `false`
 * `TRAEFIK_RANCHER_OPTS`
 * `TRAEFIK_RANCHER_PREFIX` Default `/2017-11-11`
 * `TRAEFIK_FILE_NAME` Default `rules.toml`
 * `TRAEFIK_FILE_WATCH` Default `true`
 * `CATTLE_URL`
 * `CATTLE_ACCESS_KEY`
 * `CATTLE_SECRET_KEY`
 * `TRAEFIK_MARATHON_ENABLE` Default `true`
 * `TRAEFIK_MARATHON_ENDPOINT` `http://marathon.mesos:8080`
 * `TRAEFIK_MARATHON_WATCH` Default `true`
 * `TRAEFIK_MARATHON_LB_COMPATIBILITY` Default `false`
 * `TRAEFIK_MARATHON_DOMAIN` Default `dcos.service.dev.localdomain`
 * `TRAEFIK_MARATHON_OPTS`
 * `TRAEFIK_MARATHON_EXPOSE` Default `true`
 * `TRAEFIK_MARATHON_GROUPS_AS_SUBDOMAINS` Default `false`
 * `TRAEFIK_MARATHON_DIALER_TIMEOUT` Default `60s`
 * `TRAEFIK_MARATHON_KEEP_ALIVE` Default `10s`
 * `TRAEFIK_MARATHON_FORCE_TASK_HOSTNAME` Default `false`
 * `TRAEFIK_MARATHON_RESPECT_READINESS_CHECKS` Default `false`
