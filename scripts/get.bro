#! Provide access to process connection information about hosts.

module osquery;

export {
	## Get the ProcessConnectionInfos of a host by its id
	##
	## host_id: The identifier of the host
	global getProcessConnectionInfosByHostID: function(host_id: string): set[ProcessConnectionInfo];

	## Get the ProcessInfo of a host by its id
	##
	## host_id: The identifier of the host
	## pid: The identifier of the process
	global getProcessConnectionInfosByHostIDByPID: function(host_id: string, pid: int): set[ProcessConnectionInfo];
}

function getProcessConnectionInfosByHostID(host_id: string): set[ProcessConnectionInfo] {
	local proc_conn_infos: set[ProcessConnectionInfo] = set();
	if (host_id !in osquery::state::process_connections::proc_conns) { return proc_conn_infos; }

	for ([pid, fd] in osquery::state::process_connections::proc_conns[host_id]) {
		for (idx in osquery::state::process_connections::proc_conns[host_id][pid, fd]) {
			add proc_conn_infos[osquery::state::process_connections::proc_conns[host_id][pid, fd][idx]];
		}
	}

	return proc_conn_infos;
}

function getProcessConnectionInfosByHostIDByPID(host_id: string, pid: int): set[ProcessConnectionInfo] {
	local proc_conn_infos: set[ProcessConnectionInfo] = set();
	if (host_id !in osquery::state::process_connections::proc_conns) { return proc_conn_infos; }
	if (pid !in osquery::state::process_connections::proc_fds[host_id]) { return proc_conn_infos; }
	

	for (fd in osquery::state::process_connections::proc_fds[host_id][pid]) {
		for (idx in osquery::state::process_connections::proc_conns[host_id][pid, fd]) {
			add proc_conn_infos[osquery::state::process_connections::proc_conns[host_id][pid, fd][idx]];
		}
	}

	return proc_conn_infos;
}
