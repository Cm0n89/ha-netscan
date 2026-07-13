#!/usr/bin/with-contenv bashio

bashio::log.info "NetScan starting..."

SCAN_INTERVAL=$(bashio::config 'scan_interval' '5')
NETWORK=$(bashio::config 'network' '')
SCAN_METHOD=$(bashio::config 'scan_method' 'auto')

INGRESS_PORT=8099
if bashio::var.has_value "$(bashio::addon.ingress_port 2>/dev/null)"; then
    INGRESS_PORT=$(bashio::addon.ingress_port)
fi

# /data inside container = addon data folder on host
DATA_DIR="/data"
mkdir -p "${DATA_DIR}"

bashio::log.info "Port         : ${INGRESS_PORT}"
bashio::log.info "Data dir     : ${DATA_DIR}"
bashio::log.info "Scan interval: ${SCAN_INTERVAL} min"
bashio::log.info "Network      : ${NETWORK:-auto-detect}"
bashio::log.info "Method       : ${SCAN_METHOD}"

# Log where files will be written
bashio::log.info "Results file : ${DATA_DIR}/scan_results.json"
bashio::log.info "Comments file: ${DATA_DIR}/comments.json"

OFFLINE_THRESHOLD=$(bashio::config 'offline_threshold' '5')
export NETSCAN_SCAN_INTERVAL="${SCAN_INTERVAL}"
export NETSCAN_NETWORK="${NETWORK}"
export NETSCAN_METHOD="${SCAN_METHOD}"
export NETSCAN_DATA_DIR="${DATA_DIR}"
export NETSCAN_PORT="${INGRESS_PORT}"
export NETSCAN_OFFLINE_THRESHOLD="${OFFLINE_THRESHOLD}"
export NETSCAN_VERSION="$(bashio::addon.version)"

bashio::log.info "Starting Python server..."
exec python3 /usr/bin/netscan/server.py
