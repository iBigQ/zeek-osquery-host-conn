#! Logs process connection state activity

module osquery::logging::state_process_connections;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		t_effective: time &log &optional;
		host: string &log;
		added: bool &log;
		pid: int &log;

		name: string &log &optional;
		binary_path: string &log &optional;
		cmdline: string &log &optional;
		uid: int &log &optional;
		parent: int &log &optional;

		fd: int &log;
		state: string &log;
		local_addr: addr &log &optional;
		remote_addr: addr &log &optional;
		local_port: int &log &optional;
		remote_port: int &log &optional;
		protocol: int &log &optional;
                sock_path: string &log &optional;
		family: int &log &optional;
		success: int &log &optional;
	};
}

@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
event osquery::process_connection_added(t: time, host_id: string, process_info: osquery::ProcessInfo, socket_info: osquery::SocketInfo) {
	local info: Info = [
		$t = t,
		$host = host_id,
		$added = T,
               	$pid = process_info$pid,
		$fd = socket_info$fd,
		$state = socket_info$state
	];
	if (process_info?$name) { info$name = process_info$name; }
	if (process_info?$path) { info$binary_path = process_info$path; }
	if (process_info?$cmdline) { info$cmdline = process_info$cmdline; }
	if (process_info?$uid) { info$uid = process_info$uid; }
	if (process_info?$parent) { info$parent = process_info$parent; }
	if (socket_info$connection?$local_address) { info$local_addr = socket_info$connection$local_address; }
	if (socket_info$connection?$remote_address) { info$remote_addr = socket_info$connection$remote_address; }
	if (socket_info$connection?$local_port) { info$local_port = socket_info$connection$local_port; }
	if (socket_info$connection?$remote_port) { info$remote_port = socket_info$connection$remote_port; }
	if (socket_info$connection?$protocol) { info$protocol = socket_info$connection$protocol; }
	if (socket_info?$path) { info$sock_path = socket_info$path; }
	if (socket_info?$family) { info$family = socket_info$family; }
	if (socket_info?$success) { info$success = socket_info$success; }

	Log::write(LOG, info);
}

event osquery::process_connection_removed(t: time, now: time, host_id: string, process_info: osquery::ProcessInfo, socket_info: osquery::SocketInfo) {
	local info: Info = [
		$t = t,
		$t_effective = now,
		$host = host_id,
		$added = F,
               	$pid = process_info$pid,
		$fd = socket_info$fd,
		$state = socket_info$state
	];
	if (process_info?$name) { info$name = process_info$name; }
	if (process_info?$path) { info$binary_path = process_info$path; }
	if (process_info?$cmdline) { info$cmdline = process_info$cmdline; }
	if (process_info?$uid) { info$uid = process_info$uid; }
	if (process_info?$parent) { info$parent = process_info$parent; }
	if (socket_info$connection?$local_address) { info$local_addr = socket_info$connection$local_address; }
	if (socket_info$connection?$remote_address) { info$remote_addr = socket_info$connection$remote_address; }
	if (socket_info$connection?$local_port) { info$local_port = socket_info$connection$local_port; }
	if (socket_info$connection?$remote_port) { info$remote_port = socket_info$connection$remote_port; }
	if (socket_info$connection?$protocol) { info$protocol = socket_info$connection$protocol; }
	if (socket_info?$path) { info$sock_path = socket_info$path; }
	if (socket_info?$family) { info$family = socket_info$family; }
	if (socket_info?$success) { info$success = socket_info$success; }

	Log::write(LOG, info);
}
@endif

event bro_init() {
	Log::create_stream(LOG, [$columns=Info, $path="osq-process_connections"]);
}
