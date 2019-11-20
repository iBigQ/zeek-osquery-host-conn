#! Provide synchronization of state from manager to workers

module osquery::state::process_connections;

event osquery::process_connection_added(t: time, host_id: string, process_info: osquery::ProcessInfo, socket_info: osquery::SocketInfo) &priority=10 {
	add_entry(t, host_id, process_info, socket_info);
}

event osquery::process_connection_host_removed(t: time, now: time, host_id: string) &priority=10 {
	remove_host(t, now, host_id);
}

event osquery::process_connection_removed(t: time, now: time, host_id: string, process_info: osquery::ProcessInfo, socket_info: osquery::SocketInfo) &priority=10 {
	remove_socket_entry(t, now, host_id, socket_info);
}
