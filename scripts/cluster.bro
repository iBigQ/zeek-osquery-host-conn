#! Provide synchronization of state from manager to workers

module osquery::state::process_connections;

event osquery::process_connection_added(host_id: string, process_info: osquery::ProcessInfo, socket_info: osquery::SocketInfo) &priority=10 {
	add_entry(host_id, process_info, socket_info);
}

event osquery::process_connection_host_removed(host_id: string) &priority=10 {
	remove_host(host_id);
}

event osquery::process_connection_removed(host_id: string, process_info: osquery::ProcessInfo, socket_info: osquery::SocketInfo) &priority=10 {
	remove_socket_entry(host_id, socket_info);
}
