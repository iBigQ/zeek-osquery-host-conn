#! Provide access to process connection information about hosts.

module osquery;

export {
	## Get the ProcessConnectionInfos of a host by its id
	##
	## host_id: The identifier of the host
	global getProcessConnectionInfosByHostID: function(host_id: string): set[ProcessConnectionInfo];

	## Get the ProcessConnectionInfo of a host by its id and process id
	##
	## host_id: The identifier of the host
	## pid: The identifier of the process
	global getProcessConnectionInfosByHostIDByPID: function(host_id: string, pid: int): set[ProcessConnectionInfo];

	## Get the ProcessConnectionInfo of a host by its id and connection
	##
	## host_id: The identifier of the host
	## c: The network connection
	global getProcessConnectionInfosByHostIDByConn: function(host_id: string, c: connection, src: bool &default=T): set[ProcessConnectionInfo];
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


function getProcessConnectionInfosByHostIDByConn(host_id: string, c: connection, src: bool): set[ProcessConnectionInfo] {
	local proc_conn_infos: set[ProcessConnectionInfo] = set();
	local proc_conn_info: ProcessConnectionInfo;
	local conn_pattern: osquery::ConnectionTuple;
	if (host_id !in osquery::state::process_connections::proc_conns) { return proc_conn_infos; }

	for ([pid, fd] in osquery::state::process_connections::proc_conns[host_id]) {
		for (idx in osquery::state::process_connections::proc_conns[host_id][pid, fd]) {
			proc_conn_info = osquery::state::process_connections::proc_conns[host_id][pid, fd][idx];
			if (!osquery::matchConnectionTuplePattern(convert_conn_to_conntuple(c, !src), proc_conn_info$socket_info$connection)) { next; }
			add proc_conn_infos[proc_conn_info];
		}
	}

	return proc_conn_infos;
}
