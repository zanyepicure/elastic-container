#!/bin/bash -eu
set -o pipefail

ipvar="0.0.0.0"

# These should be set in the .env file
declare LinuxDR
declare WindowsDR
declare MacOSDR

declare COMPOSE

# Ignore following warning
# shellcheck disable=SC1091
. .env

HEADERS=(
  -H "kbn-version: ${STACK_VERSION}"
  -H "kbn-xsrf: kibana"
  -H 'Content-Type: application/json'
)

passphrase_reset() {
  if grep -Fq "changeme" .env; then
    echo "Sorry, looks like you haven't updated the passphrase from the default"
    echo "Please update the changeme passphrases in the .env file."
    exit 1
  else
    echo "Passphrase has been reset. Proceeding."
  fi
}

# Create the script usage menu
usage() {
  cat <<EOF | sed -e 's/^  //'
  usage: ./elastic-container.sh [-v] (stage|start|stop|restart|status|help)
  actions:
    stage     downloads all necessary images to local storage
    export    packages images for export to an offline host
    import    load containers while offline from previous export
    start     creates a container network and starts containers
    stop      stops running containers without removing them
    destroy   stops and removes the containers, the network, and volumes created
    restart   restarts all the stack containers
    status    check the status of the stack containers
    clear     clear all documents in logs and metrics indexes
    help      print this message
  flags:
    -v        enable verbose output
EOF
}

# Create a function to enable the Detection Engine and load prebuilt rules in Kibana
configure_kbn() {
  MAXTRIES=15
  i=${MAXTRIES}

  while [ $i -gt 0 ]; do
    STATUS=$(curl -I -k --silent "${LOCAL_KBN_URL}" | head -n 1 | cut -d ' ' -f2)
    echo
    echo "Attempting to enable the Detection Engine and install prebuilt Detection Rules."

    if [ "${STATUS}" == "302" ]; then
      echo
      echo "Kibana is up. Proceeding."
      echo
      output=$(curl -k --silent "${HEADERS[@]}" --user "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" -XPOST "${LOCAL_KBN_URL}/api/detection_engine/index")
      [[ ${output} =~ '"acknowledged":true' ]] || (
        echo
        echo "Detection Engine setup failed :-("
        exit 1
      )

      echo "Detection engine enabled. Installing prepackaged rules."
      curl -k --silent "${HEADERS[@]}" --user "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" -XPUT "${LOCAL_KBN_URL}/api/detection_engine/rules/prepackaged" 1>&2

      echo
      echo "Prepackaged rules installed!"
      echo
      if [[ "${LinuxDR}" -eq 0 && "${WindowsDR}" -eq 0 && "${MacOSDR}" -eq 0 ]]; then
        echo "No detection rules enabled in the .env file, skipping detection rules enablement."
        echo
        break
      else
        echo "Enabling detection rules"
        if [ "${LinuxDR}" -eq 1 ]; then

          curl -k --silent "${HEADERS[@]}" --user "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" -X POST "${LOCAL_KBN_URL}/api/detection_engine/rules/_bulk_action" -d'
            {
              "query": "alert.attributes.tags: (\"Linux\" OR \"OS: Linux\")",
              "action": "enable"
            }
            ' 1>&2
          echo
          echo "Successfully enabled Linux detection rules"
        fi
        if [ "${WindowsDR}" -eq 1 ]; then

          curl -k --silent "${HEADERS[@]}" --user "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" -X POST "${LOCAL_KBN_URL}/api/detection_engine/rules/_bulk_action" -d'
            {
              "query": "alert.attributes.tags: (\"Windows\" OR \"OS: Windows\")",
              "action": "enable"
            }
            ' 1>&2
          echo
          echo "Successfully enabled Windows detection rules"
        fi
        if [ "${MacOSDR}" -eq 1 ]; then

          curl -k --silent "${HEADERS[@]}" --user "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" -X POST "${LOCAL_KBN_URL}/api/detection_engine/rules/_bulk_action" -d'
            {
              "query": "alert.attributes.tags: (\"macOS\" OR \"OS: macOS\")",
              "action": "enable"
            }
            ' 1>&2
          echo
          echo "Successfully enabled MacOS detection rules"
        fi
      fi
      echo
      break
    else
      echo
      echo "Kibana still loading. Trying again in 40 seconds"
    fi

    sleep 40
    i=$((i - 1))
  done
  [ $i -eq 0 ] && echo "Exceeded MAXTRIES (${MAXTRIES}) to setup detection engine." && exit 1
  return 0
}

get_host_ip() {
  os=$(uname -s)
  if [ "${os}" == "Linux" ]; then
    ipvar=$(hostname -I | awk '{ print $1}')
  elif [ "${os}" == "Darwin" ]; then
    ipvar=$(ifconfig en0 | awk '$1 == "inet" {print $2}')
  fi
}

set_fleet_values() {
  # Get the current Fleet settings
  CURRENT_SETTINGS=$(curl -k -s -u "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" -X GET "${LOCAL_KBN_URL}/api/fleet/agents/setup" -H "Content-Type: application/json")

  # Check if Fleet is already set up
  if echo "$CURRENT_SETTINGS" | grep -q '"isInitialized": true'; then
    echo "Fleet settings are already configured."
    return
  fi

  echo "Fleet is not initialized, setting up Fleet..."
  
  fingerprint=$(${COMPOSE} exec -w /usr/share/elasticsearch/config/certs/ca elasticsearch cat ca.crt | openssl x509 -noout -fingerprint -sha256 | cut -d "=" -f 2 | tr -d :)
  printf '{"fleet_server_hosts": ["%s"]}' "https://${ipvar}:${FLEET_PORT}" | curl -k --silent --user "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" -XPUT "${HEADERS[@]}" "${LOCAL_KBN_URL}/api/fleet/settings" -d @- | jq
  printf '{"hosts": ["%s"]}' "https://${ipvar}:9200" | curl -k --silent --user "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" -XPUT "${HEADERS[@]}" "${LOCAL_KBN_URL}/api/fleet/outputs/fleet-default-output" -d @- | jq
  printf '{"ca_trusted_fingerprint": "%s"}' "${fingerprint}" | curl -k --silent --user "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" -XPUT "${HEADERS[@]}" "${LOCAL_KBN_URL}/api/fleet/outputs/fleet-default-output" -d @- | jq
  printf '{"config_yaml": "%s"}' "ssl.verification_mode: certificate" | curl -k --silent --user "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" -XPUT "${HEADERS[@]}" "${LOCAL_KBN_URL}/api/fleet/outputs/fleet-default-output" -d @- | jq
  policy_id=$(printf '{"name": "%s", "description": "%s", "namespace": "%s", "monitoring_enabled": ["logs","metrics"], "inactivity_timeout": 1209600}' "Endpoint Policy" "" "default" | curl -k --silent --user "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" -XPOST "${HEADERS[@]}" "${LOCAL_KBN_URL}/api/fleet/agent_policies?sys_monitoring=true" -d @- | jq -r '.item.id')
  pkg_version=$(curl -k --user "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" -XGET "${HEADERS[@]}" "${LOCAL_KBN_URL}/api/fleet/epm/packages/endpoint" -d : | jq -r '.item.version')
  printf "{\"name\": \"%s\", \"description\": \"%s\", \"namespace\": \"%s\", \"policy_id\": \"%s\", \"enabled\": %s, \"inputs\": [{\"enabled\": true, \"streams\": [], \"type\": \"ENDPOINT_INTEGRATION_CONFIG\", \"config\": {\"_config\": {\"value\": {\"type\": \"endpoint\", \"endpointConfig\": {\"preset\": \"EDRComplete\"}}}}}], \"package\": {\"name\": \"endpoint\", \"title\": \"Elastic Defend\", \"version\": \"${pkg_version}\"}}" "Elastic Defend" "" "default" "${policy_id}" "true" | curl -k --silent --user "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" -XPOST "${HEADERS[@]}" "${LOCAL_KBN_URL}/api/fleet/package_policies" -d @- | jq
}

clear_documents() {
  if (($(curl -k --silent "${HEADERS[@]}" --user "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" -X DELETE "https://${ipvar}:9200/_data_stream/logs-*" | grep -c "true") > 0)); then
    printf "Successfully cleared logs data stream"
  else
    printf "Failed to clear logs data stream"
  fi
  echo
  if (($(curl -k --silent "${HEADERS[@]}" --user "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" -X DELETE "https://${ipvar}:9200/_data_stream/metrics-*" | grep -c "true") > 0)); then
    printf "Successfully cleared metrics data stream"
  else
    printf "Failed to clear metrics data stream"
  fi
  echo
}

# Logic to enable the verbose output if needed
OPTIND=1 # Reset in case getopts has been used previously in the shell.

verbose=0

while getopts "v" opt; do
  case "$opt" in
  v)
    verbose=1
    ;;
  *) ;;
  esac
done

shift $((OPTIND - 1))

[ "${1:-}" = "--" ] && shift

ACTION="${*:-help}"

if [ $verbose -eq 1 ]; then
  exec 3<>/dev/stderr
else
  exec 3<>/dev/null
fi

if docker compose >/dev/null; then
  COMPOSE="docker compose"
elif command -v docker-compose >/dev/null; then
  COMPOSE="docker-compose"
else
  echo "elastic-container requires docker compose!"
  exit 2
fi

case "${ACTION}" in

"stage")
  # Collect the Elastic, Kibana, and Elastic-Agent Docker images
  docker pull "docker.elastic.co/elasticsearch/elasticsearch:${STACK_VERSION}"
  docker pull "docker.elastic.co/kibana/kibana:${STACK_VERSION}"
  docker pull "docker.elastic.co/beats/elastic-agent:${STACK_VERSION}"
  if [ "${AIRGAPPED}" == "true" ]; then
    docker pull "docker.elastic.co/package-registry/distribution:${STACK_VERSION}"
    docker pull httpd
  fi
  docker pull "docker.elastic.co/beats/metricbeat:${STACK_VERSION}"
  docker pull "docker.elastic.co/beats/filebeat:${STACK_VERSION}"
  docker pull "docker.elastic.co/logstash/logstash:${STACK_VERSION}"
  ;;

"export")
  # Check why AIRGAPPED=false if exporting images
  if [ "${AIRGAPPED}" == "false" ]; then
    echo "Exporting without setting AIRGAPPED=true in .env will cause an incomplete export for offline use."
    read -r -p "Do you want to continue eitherway? [y/N]" response
    if ! [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    exit 1
    fi
  fi
  # Collect the Elastic, Kibana, and Elastic-Agent Docker images
  docker pull "docker.elastic.co/elasticsearch/elasticsearch:${STACK_VERSION}"
  docker pull "docker.elastic.co/kibana/kibana:${STACK_VERSION}"
  docker pull "docker.elastic.co/beats/elastic-agent:${STACK_VERSION}"
  if [ "${AIRGAPPED}" == "true" ]; then
    docker pull "docker.elastic.co/package-registry/distribution:${STACK_VERSION}"
    docker pull httpd
  fi
  docker pull "docker.elastic.co/beats/metricbeat:${STACK_VERSION}"
  docker pull "docker.elastic.co/beats/filebeat:${STACK_VERSION}"
  docker pull "docker.elastic.co/logstash/logstash:${STACK_VERSION}"
  # Package container images for export to offline system
  if [ ! -d "${EXPORT_DIR}" ]; then
    mkdir -p ${EXPORT_DIR}
  fi
  if ! test -f ${EXPORT_DIR}/elasticsearch_${STACK_VERSION}.tar.gz; then
    echo "Compressing Elasticsearch image..."
    docker save "docker.elastic.co/elasticsearch/elasticsearch:${STACK_VERSION}" | gzip > ${EXPORT_DIR}/elasticsearch_${STACK_VERSION}.tar.gz
  else
    echo "elasticsearch_${STACK_VERSION}.tar.gz already exists. Skipping."
  fi
  if ! test -f ${EXPORT_DIR}/kibana_${STACK_VERSION}.tar.gz; then
    echo "Compressing Kibana image..."
    docker save "docker.elastic.co/kibana/kibana:${STACK_VERSION}" | gzip > ${EXPORT_DIR}/kibana_${STACK_VERSION}.tar.gz
  else
    echo "kibana_${STACK_VERSION}.tar.gz already exists. Skipping."
  fi
  if ! test -f ${EXPORT_DIR}/elastic-agent_${STACK_VERSION}.tar.gz; then
    echo "Compressing Elastic Agent image..."
    docker save "docker.elastic.co/beats/elastic-agent:${STACK_VERSION}" | gzip > ${EXPORT_DIR}/elastic-agent_${STACK_VERSION}.tar.gz
  else
    echo "elastic-agent_${STACK_VERSION}.tar.gz already exists. Skipping."
  fi
  if ! test -f ${EXPORT_DIR}/epr_${STACK_VERSION}.tar.gz; then
    echo "Compressing Elastic Package Registry image..."
    docker save "docker.elastic.co/package-registry/distribution:${STACK_VERSION}" | gzip > ${EXPORT_DIR}/epr_${STACK_VERSION}.tar.gz
  else
    echo "epr_${STACK_VERSION}.tar.gz already exists. Skipping."
  fi
  if ! test -f ${EXPORT_DIR}/metricbeat_${STACK_VERSION}.tar.gz; then
    echo "Compressing Metricbeat image..."
    docker save "docker.elastic.co/beats/metricbeat:${STACK_VERSION}" | gzip > ${EXPORT_DIR}/metricbeat_${STACK_VERSION}.tar.gz
  else
    echo "metricbeat_${STACK_VERSION}.tar.gz already exists. Skipping."
  fi
  if ! test -f ${EXPORT_DIR}/filebeat_${STACK_VERSION}.tar.gz; then
    echo "Compressing Filebeat image..."
    docker save "docker.elastic.co/beats/filebeat:${STACK_VERSION}" | gzip > ${EXPORT_DIR}/filebeat_${STACK_VERSION}.tar.gz
  else
    echo "filebeat_${STACK_VERSION}.tar.gz already exists. Skipping."
  fi
  if ! test -f ${EXPORT_DIR}/logstash_${STACK_VERSION}.tar.gz; then
    echo "Compressing Logstash image..."
    docker save "docker.elastic.co/logstash/logstash:${STACK_VERSION}" | gzip > ${EXPORT_DIR}/logstash_${STACK_VERSION}.tar.gz
  else
    echo "logstash_${STACK_VERSION}.tar.gz already exists. Skipping."
  fi
  # Download Elastic Endpoint Artifacts
  if [ ! -d "${EXPORT_DIR}/endpoint_artifacts" ]; then
    mkdir -p ${EXPORT_DIR}/endpoint_artifacts
  fi
  # wget -P ${EXPORT_DIR}/endpoint_artifacts/downloads/endpoint/manifest https://artifacts.security.elastic.co/downloads/endpoint/manifest/artifacts-$STACK_VERSION.zip && sudo zcat -q ${EXPORT_DIR}/endpoint_artifacts/downloads/endpoint/manifest/artifacts-$STACK_VERSION.zip | sudo jq -r '.artifacts | to_entries[] | .value.relative_url' | sudo xargs -I@ curl "https://artifacts.security.elastic.co@" --create-dirs -o ".@"
  # Created directory for selected binaries from Elastic Artifact Registry
  if [ ! -d "${EXPORT_DIR}/binary_artifacts" ]; then
    mkdir -p ${EXPORT_DIR}/binary_artifacts
  fi
  # Download binaries - script from https://www.elastic.co/guide/en/elastic-stack/current/air-gapped-install.html
  set -o nounset -o errexit -o pipefail

  ARTIFACT_DOWNLOADS_BASE_URL=https://artifacts.elastic.co/downloads

  DOWNLOAD_BASE_DIR=${EXPORT_DIR}/binary_artifacts

  COMMON_PACKAGE_PREFIXES="apm-server/apm-server beats/auditbeat/auditbeat beats/elastic-agent/elastic-agent beats/filebeat/filebeat beats/heartbeat/heartbeat beats/metricbeat/metricbeat beats/osquerybeat/osquerybeat beats/packetbeat/packetbeat endpoint-dev/endpoint-security fleet-server/fleet-server"

  WIN_ONLY_PACKAGE_PREFIXES="beats/winlogbeat/winlogbeat"

  # RPM_PACKAGES="beats/elastic-agent/elastic-agent"
  DEB_PACKAGES="beats/elastic-agent/elastic-agent"

  function download_packages() {
    local url_suffix="$1"
    local package_prefixes="$2"

    local _url_suffixes="$url_suffix ${url_suffix}.sha512 ${url_suffix}.asc"
    local _pkg_dir=""
    local _dl_url=""

    for _download_prefix in $package_prefixes; do
      for _pkg_url_suffix in $_url_suffixes; do
            _pkg_dir=$(dirname ${DOWNLOAD_BASE_DIR}/${_download_prefix})
            _dl_url="${ARTIFACT_DOWNLOADS_BASE_URL}/${_download_prefix}-${_pkg_url_suffix}"
            (mkdir -p $_pkg_dir && cd $_pkg_dir && curl -O "$_dl_url")
      done
    done
  }

  # and we download
  for _os in linux windows; do
    case "$_os" in
      linux)
        PKG_URL_SUFFIX="${STACK_VERSION}-${_os}-x86_64.tar.gz"
        ;;
      windows)
        PKG_URL_SUFFIX="${STACK_VERSION}-${_os}-x86_64.zip"
        ;;
      *)
        echo "[ERROR] Something happened"
        exit 1
        ;;
    esac

    download_packages "$PKG_URL_SUFFIX" "$COMMON_PACKAGE_PREFIXES"

    if [[ "$_os" = "windows" ]]; then
      download_packages "$PKG_URL_SUFFIX" "$WIN_ONLY_PACKAGE_PREFIXES"
    fi

    if [[ "$_os" = "linux" ]]; then
      # download_packages "${STACK_VERSION}-x86_64.rpm" "$RPM_PACKAGES"
      download_packages "${STACK_VERSION}-amd64.deb" "$DEB_PACKAGES"
    fi
  done
;;

"import")
  # Check why directory to import from exists
  if [ ! -d "${EXPORT_DIR}" ]; then
    echo "The directory ${EXPORT_DIR} does not exist, confirm container images are in the correct location to be imported."
    exit 1
  fi
  if [ -f ${EXPORT_DIR}/elasticsearch_${STACK_VERSION}.tar.gz ]; then
    echo "Loading Elasticsearch..."
    docker load < ${EXPORT_DIR}/elasticsearch_${STACK_VERSION}.tar.gz
  else
    echo "${EXPORT_DIR}/elasticsearch_${STACK_VERSION}.tar.gz does not exist. Skipping import."
  fi
  if [ -f ${EXPORT_DIR}/kibana_${STACK_VERSION}.tar.gz ]; then
    echo "Loading Kibana..."
    docker load < ${EXPORT_DIR}/kibana_${STACK_VERSION}.tar.gz
  else
    echo "${EXPORT_DIR}/kibana_${STACK_VERSION}.tar.gz does not exist. Skipping import."
  fi
  if [ -f ${EXPORT_DIR}/elastic-agent_${STACK_VERSION}.tar.gz ]; then
    echo "Loading Elastic Agent..."
    docker load < ${EXPORT_DIR}/elastic-agent_${STACK_VERSION}.tar.gz
  else
    echo "${EXPORT_DIR}/elastic-agent_${STACK_VERSION}.tar.gz does not exist. Skipping import."
  fi
  if [ -f ${EXPORT_DIR}/epr_${STACK_VERSION}.tar.gz ]; then
    echo "Loading Elastic Package Repository..."
    docker load < ${EXPORT_DIR}/epr_${STACK_VERSION}.tar.gz
  else
    echo "${EXPORT_DIR}/epr_${STACK_VERSION}.tar.gz does not exist. Skipping import."
  fi
  if [ -f ${EXPORT_DIR}/metricbeat_${STACK_VERSION}.tar.gz ]; then
    echo "Loading Metricbeat..."
    docker load < ${EXPORT_DIR}/metricbeat_${STACK_VERSION}.tar.gz
  else
    echo "${EXPORT_DIR}/metricbeat_${STACK_VERSION}.tar.gz does not exist. Skipping import."
  fi
  if [ -f ${EXPORT_DIR}/filebeat_${STACK_VERSION}.tar.gz ]; then
    echo "Loading Filebeat..."
    docker load < ${EXPORT_DIR}/fiebeat_${STACK_VERSION}.tar.gz
  else
    echo "${EXPORT_DIR}/filebeat_${STACK_VERSION}.tar.gz does not exist. Skipping import."
  fi
  if [ -f ${EXPORT_DIR}/logstash_${STACK_VERSION}.tar.gz ]; then
    echo "Loading Logstash..."
    docker load < ${EXPORT_DIR}/logstash_${STACK_VERSION}.tar.gz
  else
    echo "${EXPORT_DIR}/logstash_${STACK_VERSION}.tar.gz does not exist. Skipping import."
  fi
  ;;

"start")
  passphrase_reset

  get_host_ip

  echo "Starting Elastic Stack network and containers."

  if [ "${AIRGAPPED}" == "true" ]; then
    ${COMPOSE} -f docker-compose-airgapped.yml up -d --no-deps 
  else
    ${COMPOSE} -f docker-compose.yml up -d --no-deps 
  fi

  configure_kbn 1>&2 2>&3

  echo "Waiting 40 seconds for Fleet Server setup."
  echo

  sleep 40

  echo "Populating Fleet Settings."
  set_fleet_values > /dev/null 2>&1
  echo

  echo "READY SET GO!"
  echo
  echo "Browse to https://${ipvar}:${KIBANA_PORT}"
  echo "Username: ${ELASTIC_USERNAME}"
  echo "Passphrase: ${ELASTIC_PASSWORD}"
  echo
  ;;

"stop")
  echo "Stopping running containers."

  if [ "${AIRGAPPED}" == "true" ]; then
    ${COMPOSE} -f docker-compose-airgapped.yml stop
  else
    ${COMPOSE} -f docker-compose.yml stop
  fi
  ;;

"destroy")
  echo "#####"
  echo "Stopping and removing the containers, network, and volumes created."
  echo "#####"
  if [ "${AIRGAPPED}" == "true" ]; then
    ${COMPOSE} -f docker-compose-airgapped.yml down -v
  else
    ${COMPOSE} -f docker-compose.yml down -v
  fi
  ;;

"restart")
  echo "#####"
  echo "Restarting all Elastic Stack components."
  echo "#####"
  if [ "${AIRGAPPED}" == "true" ]; then
    ${COMPOSE} restart elasticsearch kibana fleet-server epr metricbeat filebeat logstash
  else
    ${COMPOSE} restart elasticsearch kibana fleet-server metricbeat filebeat logstash
  fi
  ;;

"status")
  ${COMPOSE} ps | grep -v setup
  ;;

"clear")
  clear_documents
  ;;

"help")
  usage
  ;;

*)
  echo -e "Proper syntax not used. See the usage\n"
  usage
  ;;
esac

# Close FD 3
exec 3>&-
