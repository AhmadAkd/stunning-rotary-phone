import base64
import json
import re
from urllib.parse import urlparse, parse_qs, unquote
import subprocess
import time
import os
import sys

def parse_vless(vless_link):
    try:
        parsed_url = urlparse(vless_link)
        params = parse_qs(parsed_url.query)
        
        config = {
            "v": "2",
            "ps": unquote(parsed_url.fragment),
            "add": parsed_url.hostname,
            "port": parsed_url.port,
            "id": parsed_url.username,
            "aid": "0",
            "net": params.get("type", [""])[0],
            "type": "none",
            "host": params.get("host", [""])[0],
            "path": params.get("path", [""])[0],
            "tls": params.get("security", [""])[0],
            "sni": params.get("sni", [""])[0],
            "alpn": params.get("alpn", [""])[0]
        }
        return config
    except Exception as e:
        # print(f"Error parsing VLESS link: {vless_link}")
        # print(e)
        return None

def parse_vmess(vmess_link):
    try:
        if vmess_link.startswith("vmess://"):
            decoded_config = base64.b64decode(vmess_link[8:]).decode("utf-8")
            return json.loads(decoded_config)
    except Exception as e:
        # print(f"Error parsing VMess link: {vmess_link}")
        # print(e)
        return None

def parse_trojan(trojan_link):
    try:
        parsed_url = urlparse(trojan_link)
        params = parse_qs(parsed_url.query)
        
        config = {
            "v": "2",
            "ps": unquote(parsed_url.fragment),
            "add": parsed_url.hostname,
            "port": parsed_url.port,
            "id": parsed_url.username,
            "aid": "0",
            "net": params.get("type", [""])[0],
            "type": "none",
            "host": params.get("host", [""])[0],
            "path": params.get("path", [""])[0],
            "tls": params.get("security", [""])[0],
            "sni": params.get("sni", [""])[0],
            "alpn": ""
        }
        return config
    except Exception as e:
        # print(f"Error parsing Trojan link: {trojan_link}")
        # print(e)
        return None

def parse_ss(ss_link):
    try:
        if "#" not in ss_link:
            return None

        link_body, remarks = ss_link.split("#", 1)
        if "@" not in link_body:
            # Base64 encoded
            encoded_part = link_body[5:]
            decoded_part = base64.b64decode(encoded_part).decode("utf-8")
            parts = decoded_part.split(":")
            method = parts[0]
            password, server_port = parts[1].split("@")
            server, port = server_port.split(":")
        else:
            # Plain text
            link_body = link_body[5:]
            parts = link_body.split(":")
            method = parts[0]
            password_server_port = ":".join(parts[1:])
            password, server_port = password_server_port.split("@")
            if ":" in server_port:
                server, port = server_port.split(":")
            else:
                server = server_port
                port = ""

        config = {
            "ps": unquote(remarks),
            "add": server,
            "port": port,
            "method": method,
            "password": password,
            "protocol": "ss"
        }
        return config

    except Exception as e:
        # print(f"Error parsing SS link: {ss_link}")
        # print(e)
        return None

def test_v2ray_config(config_data):
    # Create a V2Ray client configuration for testing
    client_config = {
        "inbounds": [
            {
                "port": 1080,
                "protocol": "socks",
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
                "settings": {"auth": "noauth", "udp": True}
            }
        ],
        "outbounds": [
            {
                "protocol": config_data.get("protocol", "vmess"),
                "settings": {
                    "vnext": [
                        {
                            "address": config_data.get("add"),
                            "port": int(config_data.get("port")),
                            "users": [
                                {
                                    "id": config_data.get("id"),
                                    "alterId": int(config_data.get("aid", 0)),
                                    "security": "auto"
                                }
                            ]
                        }
                    ]
                },
                "streamSettings": {
                    "network": config_data.get("net", "tcp"),
                    "security": config_data.get("tls", "none"),
                    "tlsSettings": {"allowInsecure": True, "sni": config_data.get("sni", "")},
                    "wsSettings": {"path": config_data.get("path", ""), "headers": {"Host": config_data.get("host", "")}} 
                }
            },
            {"protocol": "freedom", "settings": {}}
        ]
    }

    # Write the client configuration to a temporary file
    config_file_path = "test_config.json"
    with open(config_file_path, "w", encoding="utf-8") as f:
        json.dump(client_config, f, ensure_ascii=False, indent=4)

    # Run v2ray.exe with the temporary config and check if it starts without errors
    try:
        process = subprocess.Popen(["./v2ray.exe", "-config", config_file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(5)  # Give V2Ray some time to start
        # Check if the process is still running (i.e., didn't crash immediately)
        if process.poll() is None:
            # print(f"V2Ray started successfully for {config_data.get('ps')}")
            # Here, you would ideally implement a more robust connectivity test
            # For now, we'll consider it successful if it starts without crashing
            process.terminate()  # Terminate the V2Ray process
            return True
        else:
            stderr_output = process.stderr.read().decode("utf-8", errors="ignore")
            # print(f"V2Ray failed to start for {config_data.get('ps')}: {stderr_output}")
            return False
    except Exception as e:
        # print(f"Error running V2Ray for {config_data.get('ps')}: {e}")
        return False
    finally:
        if os.path.exists(config_file_path):
            os.remove(config_file_path)

def main():
    with open("sources.txt", "r", encoding="utf-8") as f:
        configs = f.read().splitlines()

    all_parsed_configs = []
    for config_link in configs:
        if config_link.startswith("vless://"):
            parsed = parse_vless(config_link)
            if parsed:
                all_parsed_configs.append(parsed)
        elif config_link.startswith("vmess://"):
            parsed = parse_vmess(config_link)
            if parsed:
                all_parsed_configs.append(parsed)
        elif config_link.startswith("trojan://"):
            parsed = parse_trojan(config_link)
            if parsed:
                all_parsed_configs.append(parsed)
        elif config_link.startswith("ss://"):
            parsed = parse_ss(config_link)
            if parsed:
                all_parsed_configs.append(parsed)

    working_configs = []
    for i, config in enumerate(all_parsed_configs):
        # Encode the string to UTF-8 before printing to console
        progress_message = f"Testing config {i+1}/{len(all_parsed_configs)}: {config.get('ps', 'No remarks')}\n"
        sys.stdout.buffer.write(progress_message.encode('utf-8'))

        if test_v2ray_config(config):
            working_configs.append(config)

    with open("working_configs.json", "w", encoding="utf-8") as f:
        json.dump(working_configs, f, ensure_ascii=False, indent=4)

    print(f"Successfully found {len(working_configs)} working configs and saved to working_configs.json")


if __name__ == "__main__":
    main()
