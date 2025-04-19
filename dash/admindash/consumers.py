import asyncio
import json
import re
from collections import deque
from channels.generic.websocket import AsyncWebsocketConsumer

class RTConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        self.snort_alerts_path = "/var/log/snort/alert"
        self.keep_running = True
        asyncio.create_task(self.send_snort_alerts())
        asyncio.create_task(self.send_cpu_usage())
        asyncio.create_task(self.send_dpi_alerts())

    async def disconnect(self, close_code):
        self.keep_running = False

    async def send_cpu_usage(self):
        while self.keep_running:
            try:
            # Read the one-liner content from the file
                with open("/home/vm3/Codes/DpiIds/cpu_usage.txt", "r") as file:
                    cpu_usage = file.readline().strip()

            # Send the CPU usage to the WebSocket
                await self.send(text_data=json.dumps({"cpu_usage": cpu_usage}))

            except Exception as e:
                await self.send(text_data=json.dumps({"error_cpu_usage": str(e)}))

            # Wait for 1 second before reading the file again
            await asyncio.sleep(1)

    async def send_snort_alerts(self):
        while self.keep_running:
            try:
                # Read only the last 3 lines of the file
                with open(self.snort_alerts_path, "r") as file:
                    last_lines = deque(file, maxlen=3)

                parsed_alerts = []
                for line in last_lines:
                    alert_dict = {
                        "timestamp": "NA",
                        "sid": "NA",
                        "attack_type": "NA",
                        "priority": "NA",
                        "source_ip": "NA",
                        "destination_ip": "NA"
                    }

                    # Extract timestamp
                    timestamp_match = re.search(r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d{6})', line)
                    if timestamp_match:
                        alert_dict["timestamp"] = timestamp_match.group(1)

                    # Extract SID and attack type
                    attack_type_match = re.search(r'\[\*\*\] \[(\d+:\d+:\d+)\] (.*?) \[\*\*\]', line)
                    if attack_type_match:
                        alert_dict["sid"] = attack_type_match.group(1)
                        alert_dict["attack_type"] = attack_type_match.group(2)

                    # Extract priority
                    priority_match = re.search(r'\[Priority: (\d+)\]', line)
                    if priority_match:
                        alert_dict["priority"] = priority_match.group(1)

                    # Extract source and destination IPs
                    ips_match = re.findall(r'(\d+\.\d+\.\d+\.\d+):\d+', line)
                    if len(ips_match) == 2:
                        alert_dict["source_ip"] = ips_match[0]
                        alert_dict["destination_ip"] = ips_match[1]

                    parsed_alerts.append(alert_dict)

                # Send the alerts to the WebSocket
                await self.send(text_data=json.dumps({"alerts": parsed_alerts}))


            except Exception as e:
                await self.send(text_data=json.dumps({"error": str(e)}))


            # Wait for 1 second before reading the file again
            await asyncio.sleep(1)

    async def send_dpi_alerts(self):
        dpi_alerts_path = "/home/vm3/Codes/DpiIds/threat_log.txt"
        while self.keep_running:
            try:
                # Read only the last 3 alerts
                with open(dpi_alerts_path, "r") as file:
                    last_alerts = deque(file.read().strip().split('\n\n'), maxlen=3)

                parsed_alerts = []
                for alert in last_alerts:
                    alert_dict = {
                        "timestamp": "NA",
                        "threat_level": "NA",
                        "source_ip": "NA",
                        "destination_ip": "NA"
                    }

                    # Extract timestamp
                    timestamp_match = re.search(r'\[(.*?)\]', alert)
                    if timestamp_match:
                        alert_dict['timestamp'] = timestamp_match.group(1)

                    # Extract threat level
                    threat_level_match = re.search(r'\((.*?)\)', alert)
                    if threat_level_match:
                        alert_dict['threat_level'] = threat_level_match.group(1)

                    # Extract source and destination IPs
                    ips_match = re.findall(r'IP: (\d+\.\d+\.\d+\.\d+)', alert)
                    if len(ips_match) == 2:
                        alert_dict['source_ip'] = ips_match[0]
                        alert_dict['destination_ip'] = ips_match[1]

                    parsed_alerts.append(alert_dict)

                await self.send(text_data=json.dumps({"dpi_alerts": parsed_alerts}))

            except Exception as e:
                await self.send(text_data=json.dumps({"error_dpi_alerts": str(e)}))

            # Wait for 1 second before reading the file again
            await asyncio.sleep(1)
