#! Provide current process connection information about hosts.

module osquery::state::process_connections;

event osquery::process_state_added(t: time, host_id: string, process_info: osquery::ProcessInfo) {
	# Try to find SocketInfo candidates in state
	local socket_infos = osquery::getSocketInfosByHostIDByPID(host_id, process_info$pid);
	if (|socket_infos| == 0) { return; }

	# Correlate with socket candidates
	for (idx in socket_infos) {
		add_entry(t, host_id, process_info, socket_infos[idx]);
	}
}

event osquery::socket_state_added(t: time, host_id: string, socket_info: osquery::SocketInfo) {
	# Try to find ProcessInfo candidates in state
	local process_infos = osquery::getProcessInfosByHostIDByPID(host_id, socket_info$pid);
	if (|process_infos| == 0) { return; }

	# Correlate with process candidates
	for (process_info in process_infos) {
		add_entry(t, host_id, process_info, socket_info);
	}
}

event osquery::process_state_removed(t: time, now: time, host_id: string, process_info: osquery::ProcessInfo) {
	remove_process_entry(t, now, host_id, process_info);
}

event osquery::socket_state_removed(t: time, now: time, host_id: string, socket_info: osquery::SocketInfo) {
	remove_socket_entry(t, now, host_id, socket_info);
}

event osquery::process_host_state_removed(t: time, now: time, host_id: string) {
	remove_host(t, now, host_id);
}

event osquery::socket_host_state_removed(t: time, now: time, host_id: string) {
	remove_host(t, now, host_id);
}
