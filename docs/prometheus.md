# Prometheus Integration

[Prometheus] is an open-source systems monitoring and alerting toolkit which can act as data source for [grafana], a frontend visualization for the exported metrics. Unlike many other stats collectors, prometheus prefers collecting metrics via a pull model from each of the exporters.

Opflex-agent and opflex-server have been integrated with [prometheus-cpp] client exporter library. By default opflex-agent exports metrics on port [9612] and opflex-server exports metrics on port [9632].

# Configuration
Following are some of the opflex-agent and opflex-server configuration options to control what gets exported to Prometheus:

### opflex-agent:
  - prometheus.enabled: Default is true. This can be used to stop exporting statistics, there by reducing load in prometheus server.
  - prometheus.localhost-only: Default is to expose any IP on node:9612. This can be used if the export needs to be specific to 127.0.0.1.
  - prometheus.expose-epsvc-nan: This can be used to avoid exporting Nan metrics between endpoints and services to reduce load on prometheus server. By default this optimization is kept on.
  - prometheus.ep-attributes: If an element of this list is also an attribute in endpoint file, then it will be used for annotating the endpont metric.
  - opflex.statistics.service.flow-disabled: By default all service metric reporting is enabled. This can be used to stop exporting metrics to decrease prometheus server load and also to not create openvswitch flows for this metric collection.
  - To decrease load on prometheus server, statistics for some of the exported metrics can be turned off. Check opflex.statistics in the [agent configuration file][agent.conf].

### opflex-server:
  - --disable-prometheus: Disable exporting metrics to prometheus.
  - --enable-prometheus-localhost: If enabled, export prometheus port only on localhost.

# Metrics exported from opflex-agent

### Endpoint

| Family | Annotations | Description |
| ------ | ------ | ------ |
| opflex_endpoint_rx_bytes | name, namespace | local endpoint rx bytes |
| opflex_endpoint_rx_packets | name, namespace | local endpoint rx packets |
| opflex_endpoint_rx_drop_packets | name, namespace | local endpoint rx dropped packets |
| opflex_endpoint_rx_ucast_packets | name, namespace | local endpoint rx unicast packets |
| opflex_endpoint_rx_mcast_packets | name, namespace | local endpoint rx multicast packets |
| opflex_endpoint_rx_bcast_packets | name, namespace | local endpoint rx broadcast packets |
| opflex_endpoint_tx_packets | name, namespace | local endpoint tx packets |
| opflex_endpoint_tx_bytes | name, namespace | local endpoint tx bytes |
| opflex_endpoint_tx_drop_packets | name, namespace | local endpoint tx dropped packets |
| opflex_endpoint_tx_ucast_packets | name, namespace | local endpoint tx unicast packets |
| opflex_endpoint_tx_mcast_packets | name, namespace | local endpoint tx multicast packets |
| opflex_endpoint_tx_bcast_packets | name, namespace | local endpoint tx broadcast packets |
| opflex_endpoint_active_total | | total active local endpoints |
| opflex_endpoint_created_total | | total created local endpoints |
| opflex_endpoint_removed_total | | total removed local endpoints |

### Services

##### Endpoint <--> Service
This collects flow east-west stats between endpoints and cluster services. All of these metrics are annotated with ep_name, ep_namespace, svc_name, svc_namespace, and svc_scope, where svc_scope will be "cluster".

| Family | Description |
| ------ | ------ |
| opflex_endpoint_to_svc_bytes | Endpoint to Service bytes |
| opflex_endpoint_to_svc_packets | Endpoint to Service packets |
| opflex_svc_to_endpoint_bytes | Service to Endpoint bytes |
| opflex_svc_to_endpoint_packets | Service to Endpoint packets |

These metrics answer below operational questions:
* what services are used by this deployment
* what clients consume this service
* top-N users of a service
* top-N services used by a client

##### Service (aggregate)

These display stats at a service level agnostic of individual service-endpoint that contribute to these stats. The annotated "scope" can be "cluster", "nodePort" or "ext" to report statistics of ClusterIP, NodePort and LoadBalancer k8s service types.

* If k8s user creates nodePort service, then 1 service file gets consumed by opflex-agent, but individual metrics with scope="cluster" and scope="nodePort" will get created.
* If k8s user creates clusterIP service, then 1 service file gets consumed by opflex-agent, and metrics will have scope="cluster".
* If k8s user creates LoadBalancer service in an on-prem environment with ACI fabric, then 2 service files get consumed by opflex-agent. Metrics get created with all of three scopes.
* If k8s user creates LoadBalancer service in a cloud environment, then 1 service file gets consumed by opflex-agent and individual metrics will get created with scope="cluster" and scope="nodePort".

| Family | Annotations | Description |
| ------ | ------ | ------ |
| opflex_svc_rx_bytes | name, namespace, scope | Service rx bytes |
| opflex_svc_rx_packets | name, namespace, scope | Service rx packets |
| opflex_svc_tx_bytes | name, namespace, scope | Service tx bytes |
| opflex_svc_tx_packets | name, namespace, scope | Service tx packets |
| opflex_svc_active_total |  | Total active service files processed by the agent |
| opflex_svc_created_total |  | Total service file creates processed by the agent |
| opflex_svc_removed_total |  | Total service file removes processed by the agent |

The packet and byte metrics help with answering how much traffic in ingressing/egressing this service across all nodes of a cluster.

##### Service Load-Balancing

These metrics display granular per-service-endpoint stats and are annotated with:
* service-endpoint's IP address, ep_name and ep_namespace
* service's svc_name, svc_namespace, and svc_scope

| Family | Description |
| ------ | ------ |
| opflex_svc_target_rx_bytes | Service-endpoint rx bytes |
| opflex_svc_target_rx_packets | Service-endpoint rx packets |
| opflex_svc_target_tx_bytes | Service-endpoint tx bytes |
| opflex_svc_target_tx_packets | Service-endpoint tx packets |

These metrics answer below operational questions:
* how much traffic in ingressing/egressing this service across all nodes of a cluster
* is LB working reasonably for this service
* cost analysis for local vs remote region service-pods

### Drops

| Family | Annotations | Description |
| ------ | ------ | ------ |
| opflex_policy_drop_bytes | routing_domain="<tenant>:<vrf>" | Per VRF policy/contract table dropped bytes |
| opflex_policy_drop_packets | routing_domain="<tenant>:<vrf>" | Per VRF policy/contract table dropped packets |
| opflex_table_drop_bytes | table="<ovs_name>_<table_name>" | Per table per ovs dropped bytes |
| opflex_table_drop_packets | table="<ovs_name>_<table_name>" | Per table per ovs dropped packets |

Please refer [drop-logs] for more details on how table drop stats are collected.

### Contracts

These metrics are annotated with src_epg, dst_epg, and concise version of classifier where:
* src_epg is the source endpoint group (k8s pod) qualified with the tenant name
* dst_epg is the destination endpoint group (k8s pod) qualified with the tenant name
* classifier is qualified with tenant, policy, subject and rule if this information is present in opflex-agent

| Family | Description |
| ------ | ------ |
| opflex_contract_bytes | Byte count of traffic per contract |
| opflex_contract_packets | Packet count of traffic per contract |

### Security Groups

These metrics are annotated with a concise version of classifier which is qualified with tenant, policy, subject and rule if this information is present in opflex-agent.

| Family | Description |
| ------ | ------ |
| opflex_sg_rx_bytes | Rx Byte count of traffic per security group |
| opflex_sg_rx_packets | Rx Packet count of traffic per security group |
| opflex_sg_tx_bytes | Tx Byte count of traffic per security group |
| opflex_sg_tx_packets | Tx Packet count of traffic per security group |

### Remote EP

This represents the total number of endpoints under the same physical interface connected to leaf. For e.g. if there are multiple blades connected via chassis to leaf, then EPs on these blades are kept as remote EPs to know their TEPs so that broadcasting of packets are avoided between the blades. In cloud deployments, until ivxlan/conversation based learning gets enabled, all the non-local endpoints are kept as remote EP within opflex-agent.

Remote EP count is exported to mainly help identify issues where the remote EPs don’t get created.

| Family | Description |
| ------ | ------ |
| opflex_remote_ep_count | Count of total remote eps provisioned |

### Peer

Opflex-agent declares and resolves policies with peer agent. These metrics are annotated with peer IP address and port.
| Family | Description |
| ------ | ------ |
 | opflex_peer_identity_req_count | number of identity requests sent to opflex peer |
 | opflex_peer_identity_resp_count | number of identity responses received from opflex peer |
 | opflex_peer_identity_err_count | number of identity error responses from opflex peer |
 | opflex_peer_policy_resolve_req_count | number of policy resolves sent to opflex peer |
 | opflex_peer_policy_resolve_resp_count | number of policy resolve responses received from opflex peer |
 | opflex_peer_policy_resolve_err_count | number of policy resolve error responses from opflex peer |
 | opflex_peer_policy_unresolve_req_count | number of policy unresolves sent to opflex peer |
 | opflex_peer_policy_unresolve_resp_count | number of policy unresolve responses received from opflex peer |
 | opflex_peer_policy_unresolve_err_count | number of policy unresolve error responses from opflex peer |
 | opflex_peer_policy_update_receive_count | number of policy updates received from opflex peer |
 | opflex_peer_ep_declare_req_count | number of endpoint declares sent to opflex peer |
 | opflex_peer_ep_declare_resp_count | number of endpoint declare responses received from opflex peer |
 | opflex_peer_ep_declare_err_count | number of endpoint declare error responses from opflex peer |
 | opflex_peer_ep_undeclare_req_count | number of endpoint undeclares sent to opflex peer |
 | opflex_peer_ep_undeclare_resp_count | number of endpoint undeclare responses received from opflex peer |
 | opflex_peer_ep_undeclare_err_count | number of endpoint undeclare error responses from opflex peer |
 | opflex_peer_state_report_req_count | number of state reports sent to opflex peer |
 | opflex_peer_state_report_resp_count | number of state reports responses received from opflex peer |
 | opflex_peer_state_report_err_count | number of state reports error repsonses from opflex peer |
 | opflex_peer_unresolved_policy_count | number of policies requested by agent which aren't yet resolved by opflex peer |

# Metrics exported from opflex-server

### Agent

Opflex-server connects with gbp server to accept policies. Opflex-agent connects with opflex-server to download policies. These metrics are accumulated per connected agent and annotated with agent's IP address and port.
| Family | Description |
| ------ | ------ |
 | opflex_agent_identity_req_count | number of identity requests received from an opflex agent |
 | opflex_agent_policy_update_count | number of policy updates received from grpc server that are sent to an opflex agent |
 | opflex_agent_policy_unavailable_resolve_count | number of unavailable policies on resolves received from an opflex agent |
 | opflex_agent_policy_resolve_count | number of policy resolves received from an opflex agent |
 | opflex_agent_policy_resolve_err_count | number of errors on policy resolves received from an opflex agent |
 | opflex_agent_policy_unresolve_count | number of policy unresolves received from an opflex agent |
 | opflex_agent_policy_unresolve_err_count | number of errors on policy unresolves received from an opflex agent |
 | opflex_agent_ep_declare_count | number of endpoint declares received from an opflex agent |
 | opflex_agent_ep_declare_err_count | number of errors on endpoint declares received from an opflex agent |
 | opflex_agent_ep_undeclare_count | number of endpoint undeclares received from an opflex agent |
 | opflex_agent_ep_undeclare_err_count | number of errors on endpoint undeclares received from an opflex agent |
 | opflex_agent_ep_resolve_count | number of endpoint resolves received from an opflex agent |
 | opflex_agent_ep_resolve_err_count | number of errors on endpoint resolves received from an opflex agent |
 | opflex_agent_ep_unresolve_count | number of endpoint unresolves received from an opflex agent |
 | opflex_agent_ep_unresolve_err_count | number of errors on endpoint unresolves received from an opflex agent |
 | opflex_agent_state_report_count | number of state reports received from an opflex agent |
 | opflex_agent_state_report_err_count | number of errors on state reports received from an opflex agent |

# Grafana
Following are a few graphs created in grafana using the exported opflex metrics.
### Endpoint
![][grafana-endpoint-1]
![][grafana-endpoint-2]
### Services
##### Top 5 Services (ClusterIP)
![][grafana-services-1]
##### Per-Service and Per-Pod Load-Balancing of All Services (ClusterIP)
![][grafana-services-2]
##### Per-Service and Per-Pod Load-Balancing of Kube-dns (ClusterIP)
![][grafana-services-3]
##### Per-Service and Per-Pod Load-Balancing of Nginx (LoadBalancer)
![][grafana-services-4]
##### Endpoint(Pod) <--> Service
![][grafana-services-5]
![][grafana-services-6]
### Drops
![][grafana-drops]
### Contracts
![][grafana-contracts]
### Security-Groups
![][grafana-sg]
### Opflex Peer metrics from Agent
![][grafana-ofpeer-1]
![][grafana-ofpeer-2]
![][grafana-ofpeer-3]
### Opflex Agent metrics from Server
![][grafana-server-1]
![][grafana-server-2]

Sample [grafana-json-templates] for opflex-agent metrics can be imported in grafana.

# Disclaimer
Opflex-agent exports a number of metrics based on the current implementation choices. This is still WIP. Useful metrics will be added every release. There could be few changes to the exported metrics across releases in light of optimizations in opflex-agent, prometheus and feedback from customers.

   [Prometheus]: <https://prometheus.io/>
   [grafana]: <https://grafana.com/>
   [prometheus-cpp]: <https://github.com/jupp0r/prometheus-cpp>
   [9612]: <https://github.com/prometheus/prometheus/wiki/Default-port-allocations>
   [9632]: <https://github.com/prometheus/prometheus/wiki/Default-port-allocations>
   [agent.conf]: <https://github.com/noironetworks/opflex/blob/master/agent-ovs/opflex-agent-ovs.conf.in>
   [grafana-json-templates]: <https://github.com/noironetworks/opflex/tree/master/agent-ovs/grafana>
   [drop-logs]: <https://github.com/noironetworks/opflex/blob/master/docs/drop_logs.md>
   [grafana-endpoint-1]: <https://github.com/noironetworks/opflex/blob/master/agent-ovs/grafana/images/Endpoint-1.png?raw=true>
   [grafana-endpoint-2]: <https://github.com/noironetworks/opflex/blob/master/agent-ovs/grafana/images/Endpoint-2.png?raw=true>
   [grafana-services-1]: <https://github.com/noironetworks/opflex/blob/master/agent-ovs/grafana/images/Service-EW-LB-Top5.png?raw=true>
   [grafana-services-2]: <https://github.com/noironetworks/opflex/blob/master/agent-ovs/grafana/images/Service-EW-PerPodLB-all.png?raw=true>
   [grafana-services-3]: <https://github.com/noironetworks/opflex/blob/master/agent-ovs/grafana/images/Service-EW-PerPodLB-kubedns.png?raw=true>
   [grafana-services-4]: <https://github.com/noironetworks/opflex/blob/master/agent-ovs/grafana/images/Service-ExtLB-PerPodLB-nginx.png?raw=true>
   [grafana-services-5]: <https://github.com/noironetworks/opflex/blob/master/agent-ovs/grafana/images/PodService.png?raw=true>
   [grafana-services-6]: <https://github.com/noironetworks/opflex/blob/master/agent-ovs/grafana/images/PodService-ServiceUsagePerPod.png?raw=true>
   [grafana-drops]: <https://github.com/noironetworks/opflex/blob/master/agent-ovs/grafana/images/Drop.png?raw=true>
   [grafana-contracts]: <https://github.com/noironetworks/opflex/blob/master/agent-ovs/grafana/images/Contract.png?raw=true>
   [grafana-sg]: <https://github.com/noironetworks/opflex/blob/master/agent-ovs/grafana/images/SecurityGroup.png?raw=true>
   [grafana-ofpeer-1]: <https://github.com/noironetworks/opflex/blob/master/agent-ovs/grafana/images/OFPeer-1.png?raw=true>
   [grafana-ofpeer-2]: <https://github.com/noironetworks/opflex/blob/master/agent-ovs/grafana/images/OFPeer-2.png?raw=true>
   [grafana-ofpeer-3]: <https://github.com/noironetworks/opflex/blob/master/agent-ovs/grafana/images/OFPeer-3.png?raw=true>
   [grafana-server-1]: <https://github.com/noironetworks/opflex/blob/master/agent-ovs/grafana/images/Server1.png?raw=true>
   [grafana-server-2]: <https://github.com/noironetworks/opflex/blob/master/agent-ovs/grafana/images/Server2.png?raw=true>
