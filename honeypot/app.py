# поднимает все сенсоры вместе
from honeypot.sensors import ssh_server, http_server


async def start_all(host="0.0.0.0", ssh_port=2222, http_port=8080,
                    key_path="keys/ssh_host_key", db_path="logs/events.db",
                    log_path="logs/events.jsonl", quarantine_path="quarantine"):
    ssh = await ssh_server.start_server(host, ssh_port, key_path, db_path, log_path,
                                        quarantine_path=quarantine_path)
    web = await http_server.start_server(host, http_port, db_path, log_path)
    return ssh, web