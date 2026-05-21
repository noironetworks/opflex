#!/bin/sh

set -e
set -x

PREFIX=/usr/local
VARDIR=${PREFIX}/var
LOG_DIR=${VARDIR}/log
OPFLEXAGENT=${PREFIX}/bin/opflex_agent
OPFLEXAGENT_CONF_PATH=/usr/local/etc/opflex-agent-ovs
OPFLEXAGENT_REBOOT_CONFD=${VARDIR}/lib/opflex-agent-ovs/reboot-conf.d
OPFLEXAGENT_DISABLED_CONF=${OPFLEXAGENT_CONF_PATH}/opflex-agent.conf
OPFLEXAGENT_BASE_CONF=${OPFLEXAGENT_CONF_PATH}/base-conf.d
OPFLEXAGENT_CONFD=${OPFLEXAGENT_CONF_PATH}/conf.d
EXTRA_ARGS=""
export LD_LIBRARY_PATH=/usr/local/lib64:$LD_LIBRARY_PATH

if [ -w ${PREFIX} ]; then
    # Setup folders to hold metadata
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/endpoints
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/services
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/ids
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/mcast
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/snats
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/reboot-conf.d
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/droplog
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/faults
    mkdir -p ${VARDIR}/lib/opflex-agent-ovs/startup
fi

if [ -d ${OPFLEXAGENT_CONF_PATH} ]; then
    cat <<EOF > ${OPFLEXAGENT_DISABLED_CONF}
{
    "opflex": {
        "name": "disabled",
        "domain": "disabled",
        "ssl": {
            "mode": "$SSL_MODE",
            "ca-store": "/etc/ssl/certs/"
        }
    }
}
EOF
fi

if [ -n "$OPFLEXAGENT_DROPLOG_FILE" ]; then
    DROP_LOG_FILE_PATH="$LOG_DIR/$OPFLEXAGENT_DROPLOG_FILE"
    touch "$DROP_LOG_FILE_PATH"
    EXTRA_ARGS="--drop_log=$DROP_LOG_FILE_PATH"

    # Background drop log rotation to prevent unbounded file growth.
    DROPLOG_MAXSIZE_MB=${OPFLEXAGENT_DROPLOG_MAXSIZE:-50}
    DROPLOG_ROTATE_COUNT=${OPFLEXAGENT_DROPLOG_ROTATE:-5}
    LOGROTATE_CONF="/tmp/droplog-logrotate.conf"
    LOGROTATE_STATE="/tmp/droplog-logrotate.state"
    cat > "${LOGROTATE_CONF}" <<LREOF
${DROP_LOG_FILE_PATH} {
    size ${DROPLOG_MAXSIZE_MB}M
    rotate ${DROPLOG_ROTATE_COUNT}
    copytruncate
    compress
    delaycompress
    missingok
    notifempty
}
LREOF
    /bin/sh -c "
        while true; do
            sleep 43200
            logrotate -s \"${LOGROTATE_STATE}\" \"${LOGROTATE_CONF}\"
        done
    " &

elif [ "$OPFLEXAGENT_DROPLOG_SYSLOG" = "true" ]; then
    EXTRA_ARGS="--drop_log_syslog"
fi

# background opflex connection monitoring script
/bin/sh -c "
    sleep 120
    # Wait until we can determine the opflex port
    while true; do
        OPFLEX_PORT=\$(grep -rIE 'hostname' ${OPFLEXAGENT_CONF_PATH}/* | awk -F\":\" '{print \$NF}' | awk -F'\"' '{print \$2}')
        if [ -n \"\${OPFLEX_PORT}\" ]; then
            break
        fi
        echo \"Could not determine opflex port, retrying...\"
        sleep 1
    done
    # Monitor opflex connections
    while true; do
        if ! netstat -natp | grep -q \"\${OPFLEX_PORT}\"; then
            sleep 60
            if ! netstat -natp | grep -q \"\${OPFLEX_PORT}\"; then
                echo \"No opflex connections detected, triggering reset\"
                date >> ${OPFLEXAGENT_REBOOT_CONFD}/reset.conf
            fi
            sleep 60
        fi
        # Sleep for a while before checking again
        sleep 2
    done
" &

if [ "$REBOOT_WITH_OVS" = "true" ]; then
    exec ${OPFLEXAGENT} -w \
         -c ${OPFLEXAGENT_DISABLED_CONF} \
         -c ${OPFLEXAGENT_BASE_CONF} \
         -c ${OPFLEXAGENT_CONFD} \
         -c ${OPFLEXAGENT_REBOOT_CONFD} \
         "${EXTRA_ARGS}"
else
    exec ${OPFLEXAGENT} -w \
         -c ${OPFLEXAGENT_DISABLED_CONF} \
         -c ${OPFLEXAGENT_BASE_CONF} \
         -c ${OPFLEXAGENT_CONFD} \
         "${EXTRA_ARGS}"
fi
