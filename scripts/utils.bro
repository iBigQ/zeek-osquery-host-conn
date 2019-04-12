#! Provide process connection state utils

module osquery;

export {
	type ProcessConnectionInfo: record {
		process_info: ProcessInfo;
		socket_info: SocketInfo;
	};

	## Check if two process connections infos have equal keys
	##
	## <params missing>
	global equalProcessConnectionKeys: function(proc_conn1: ProcessConnectionInfo, proc_conn2: ProcessConnectionInfo): bool;

	## Check if two process connections infos are equal
	##
	## <params missing>
	global equalProcessConnectionInfos: function(proc_conn1: ProcessConnectionInfo, proc_conn2: ProcessConnectionInfo): bool;
}

function equalProcessConnectionKeys(proc_conn1: ProcessConnectionInfo, proc_conn2: ProcessConnectionInfo): bool {
	if (!equalProcessKeys(proc_conn1$process_info, proc_conn2$process_info)) {
		return F;
	}
	if (!equalSocketKeys(proc_conn1$socket_info, proc_conn2$socket_info)) {
		return F;
	}
	
	return T;
}

function equalProcessConnectionInfos(proc_conn1: ProcessConnectionInfo, proc_conn2: ProcessConnectionInfo): bool {
	if (!equalProcessInfos(proc_conn1$process_info, proc_conn2$process_info)) {
		return F;
	}
	if (!equalSocketInfos(proc_conn1$socket_info, proc_conn2$socket_info)) {
		return F;
	}
	
	return T;
}

