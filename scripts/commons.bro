#! Provide process connection state commons

module osquery;

export {
	## Event when added to the state of process connections
	##
	## <params missing>
	global process_connection_added: event(host_id: string, process_info: ProcessInfo, socket_info: SocketInfo);
	
	## Event when removing a host from the state of process connections
	##
	## <params missing>
	global process_connection_host_removed: event(host_id: string);
	
	## Event when removing from the state of process connections
	##
	## <params missing>
	global process_connection_removed: event(host_id: string, process_info: ProcessInfo, socket_info: SocketInfo);
}

#@if ( Cluster::local_node_type() == Cluster::MANAGER )
## Manager need ability to forward state to workers.
#event zeek_init() {
#	Broker::auto_publish(Cluster::worker_topic, osquery::process_connection_added);
#	Broker::auto_publish(Cluster::worker_topic, osquery::process_connection_host_removed);
#	Broker::auto_publish(Cluster::worker_topic, osquery::process_connection_removed);
#}
#@endif

module osquery::state::process_connections;

export {
	# Table to access ProcessConnectionInfo by HostID
	global proc_conns: table[string] of table[int, int] of vector of osquery::ProcessConnectionInfo;

	# Add an entry to the process connection state
	global add_entry: function(host_id: string, process_info: osquery::ProcessInfo, socket_info: osquery::SocketInfo);

	# Remove an entry from the process connection state
	global remove_entry: function(host_id: string, process_info: osquery::ProcessInfo, socket_info: osquery::SocketInfo);

	# Remove all entries for host from the process connection state
	global remove_host: function(host_id: string);

	# Current FD set for each PID by HostID
	global proc_fds: table[string] of table[int] of set[int];
}

function add_entry(host_id: string, process_info: osquery::ProcessInfo, socket_info: osquery::SocketInfo) {
	local proc_conn_info: osquery::ProcessConnectionInfo = [$process_info=process_info, $socket_info=socket_info];
	local pid = process_info$pid;
	local fd = socket_info$fd;
	
	# Insert into state
	if (host_id !in proc_conns) {
		proc_conns[host_id] = table();
	}
	if ([pid, fd] in proc_conns[host_id]) {
		proc_conns[host_id][pid, fd] += proc_conn_info;
	} else {
		proc_conns[host_id][pid, fd] = vector(proc_conn_info);
	}

	# Track FD
	if (host_id !in proc_fds) { proc_fds[host_id] = table(); }
	if (pid in proc_fds[host_id]) { 
		add proc_fds[host_id][pid][fd];
	} else {
		proc_fds[host_id][pid] = set(fd);
	}

	# Set fresh
	if (!Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER) {
		event osquery::process_connection_added(host_id, process_info, socket_info);
		Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::process_connection_added, host_id, process_info, socket_info));
	}
}

function remove_process_entry(host_id: string, process_info: osquery::ProcessInfo) {
	local pid = process_info$pid;
	
	# Check if process connection exists
	if (host_id !in proc_conns) { return; }
	if (pid !in proc_fds[host_id]) { return; }
	if (|proc_fds[host_id][pid]| == 0) { return; }

	# For each FD of the PID
	local fds_to_delete: set[int] = set();
	for (fd in proc_fds[host_id][pid]) {
		# Remove from state
		local proc_conn_info: osquery::ProcessConnectionInfo;
		local proc_conns_new: vector of osquery::ProcessConnectionInfo = vector();
		for (idx in proc_conns[host_id][pid, fd]) {
			proc_conn_info = proc_conns[host_id][pid, fd][idx];
			# Delete element (skip on copy)
			if (osquery::equalProcessInfos(proc_conn_info$process_info, process_info)) {
				if (!Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER) {
					event osquery::process_connection_removed(host_id, process_info, proc_conn_info$socket_info);
					Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::process_connection_removed, host_id, process_info, proc_conn_info$socket_info));
				}
				next;
			}
			proc_conns_new += proc_conn_info;
		}
	
		# Delete
		if (|proc_conns_new| == 0) {
			delete proc_conns[host_id][pid, fd];
			add fds_to_delete[fd];
		} else {
			proc_conns[host_id][pid, fd] = proc_conns_new;
		}
	}

	# Untrack FD
	for (fd in fds_to_delete) {
		delete proc_fds[host_id][pid][fd];
		if (|proc_fds[host_id][pid]| == 0) { delete proc_fds[host_id][pid]; }
	}
}

function remove_socket_entry(host_id: string, socket_info: osquery::SocketInfo) {
	local pid = socket_info$pid;
	local fd = socket_info$fd;
	
	# Check if process connection exists
	if (host_id !in proc_conns) { return; }
	if ([pid, fd] !in proc_conns[host_id]) { return; }
	if (|proc_conns[host_id][pid, fd]| == 0) { return; }

	# Remove from state
	local proc_conn_info: osquery::ProcessConnectionInfo;
	local proc_conns_new: vector of osquery::ProcessConnectionInfo = vector();
	for (idx in proc_conns[host_id][pid, fd]) {
		proc_conn_info = proc_conns[host_id][pid, fd][idx];
		# Delete element (skip on copy)
		if (osquery::equalSocketInfos(proc_conn_info$socket_info, socket_info)) {
			if (!Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER) {
				event osquery::process_connection_removed(host_id, proc_conn_info$process_info, socket_info);
				Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::process_connection_removed, host_id, proc_conn_info$process_info, socket_info));
			}
			next;
		}
		proc_conns_new += proc_conn_info;
	}
	
	# Delete and Untrack FD
	if (|proc_conns_new| == 0) {
		delete proc_conns[host_id][pid, fd];
		delete proc_fds[host_id][pid][fd];
		if (|proc_fds[host_id][pid]| == 0) { delete proc_fds[host_id][pid]; }
	} else {
		proc_conns[host_id][pid, fd] = proc_conns_new;
	}
}

function remove_host(host_id: string) {
	if (host_id !in proc_conns) { return; }

	if (!Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER) {
		for ([pid, fd] in proc_conns[host_id]) {
			for (idx in proc_conns[host_id][pid, fd]) {
				event osquery::process_connection_removed(host_id, proc_conns[host_id][pid, fd][idx]$process_info, proc_conns[host_id][pid, fd][idx]$socket_info);
				Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::process_connection_removed, host_id, proc_conns[host_id][pid, fd][idx]$process_info, proc_conns[host_id][pid, fd][idx]$socket_info));
			}
		}
	}
	delete proc_conns[host_id];
	delete proc_fds[host_id];
}
