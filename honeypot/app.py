# поднимает все сенсоры вместе
from honeypot.sensors import ssh_server, http_server, telnet_server


async def start_all(host="0.0.0.0", ssh_port=2222, http_port=8080,
                    key_path="keys/ssh_host_key", db_path="logs/events.db",
                    log_path="logs/events.jsonl", quarantine_path="quarantine",
                    telnet_port=None):
    ssh = await ssh_server.start_server(host, ssh_port, key_path, db_path, log_path,
                                        quarantine_path=quarantine_path)
    web = await http_server.start_server(host, http_port, db_path, log_path)
    telnet = None
    if telnet_port:
        telnet = await telnet_server.start_server(host, telnet_port, db_path,
                                                  log_path, quarantine_path)
    return ssh, web, telnet