import asyncio
import inspect
import ipaddress
import json
import logging
import os
import socket
import time
import urllib.request
from collections import deque
from pathlib import Path
from typing import Any

import apprise
from mac_vendor_lookup import AsyncMacLookup, BaseMacLookup
from nicegui import app, run, ui
from scapy.arch import get_if_addr
from scapy.config import conf
from scapy.interfaces import network_name
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import AsyncSniffer, send, sendp
from starlette.responses import PlainTextResponse

from database import database

HOME_ASSISTANT_INGRESS = os.getenv("HOME_ASSISTANT_INGRESS", "").lower() in {"1", "true", "yes"}
HOME_ASSISTANT_INGRESS_PROXY = "172.30.32.2"
PACKET_COUNT_WINDOW_SECONDS = 60
DEFAULT_TABLE_ROWS_PER_PAGE = 50
TABLE_ROWS_PER_PAGE_CONFIG_KEY = "table.rows_per_page"
NEW_DEVICE_NOTIFICATIONS_ENABLED_CONFIG_KEY = "notifications.new_devices.enabled"
APPRISE_URLS_CONFIG_KEY = "notifications.apprise.urls"
PROTOCOL_FILTERS = {
    "dhcp": "udp port 67 or udp port 68",
    "arp": "arp",
    "dns": "udp port 5353 and (udp[10] & 0x80 != 0)",
}
PROTOCOL_CONFIG_KEYS = {protocol: f"capture.{protocol}.enabled" for protocol in PROTOCOL_FILTERS}


class HomeAssistantIngressMiddleware:
    def __init__(self, application, enabled: bool):
        self.application = application
        self.enabled = enabled

    async def __call__(self, scope, receive, send):
        if not self.enabled or scope["type"] not in {"http", "websocket"}:
            await self.application(scope, receive, send)
            return

        headers = list(scope.get("headers", []))
        ingress_path = next((value for name, value in headers if name == b"x-ingress-path"), None)
        client = scope.get("client")
        if not ingress_path or not client or client[0] != HOME_ASSISTANT_INGRESS_PROXY:
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            else:
                await PlainTextResponse("Forbidden", status_code=403)(scope, receive, send)
            return

        headers = [(name, value) for name, value in headers if name != b"x-forwarded-prefix"]
        headers.append((b"x-forwarded-prefix", ingress_path.rstrip(b"/")))
        scope["headers"] = headers
        await self.application(scope, receive, send)


def get_ingress_port() -> int:
    token = os.environ["SUPERVISOR_TOKEN"]
    request = urllib.request.Request("http://supervisor/addons/self/info", headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(request) as response:
        result = json.load(response)
    return result["data"]["ingress_port"]


def get_network_interface() -> str:
    conf.route.resync()
    default_interface, default_address, _ = conf.route.route()
    try:
        address = ipaddress.IPv4Address(default_address)
        if not address.is_unspecified and not address.is_loopback and not address.is_link_local:
            return network_name(default_interface)
    except ValueError:
        pass

    candidates = []
    for net, mask, gateway, interface, route_address, metric in conf.route.routes:
        try:
            address = ipaddress.IPv4Address(route_address)
            network = ipaddress.IPv4Network(f"{ipaddress.IPv4Address(net)}/{ipaddress.IPv4Address(mask)}")
            interface = network_name(interface)
        except ValueError:
            continue
        if net == 0 or mask in {0, 0xFFFFFFFF} or address not in network:
            continue
        if address.is_unspecified or address.is_loopback or address.is_link_local:
            continue
        candidates.append((not address.is_private, gateway != "0.0.0.0", metric, -network.prefixlen, interface))

    if not candidates:
        raise RuntimeError("no active IPv4 network interface found")
    return min(candidates)[-1]


def get_subnet(iface: str) -> str:
    iface = network_name(iface)
    ip = ipaddress.IPv4Address(get_if_addr(iface))
    conf.route.resync()
    networks = []
    for net, mask, gateway, route_iface, _, _ in conf.route.routes:
        if route_iface != iface or net == 0 or mask == 0xFFFFFFFF:
            continue
        network = ipaddress.IPv4Network(f"{ipaddress.IPv4Address(net)}/{ipaddress.IPv4Address(mask)}")
        if ip in network:
            networks.append(network)
    if not networks:
        raise RuntimeError(f"no ipv4-subnet for {iface} found")
    return str(max(networks, key=lambda network: network.prefixlen))


def resolve_hostname_sync(ip: str) -> str | None:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror):
        return None

    hostname = hostname.strip().rstrip(".")
    if not hostname:
        return None
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return hostname
    return None


async def resolve_hostname(ip: str) -> str | None:
    return await run.io_bound(resolve_hostname_sync, ip)


class LanRadar:
    def __init__(self, iface: str | None = None):
        self.iface = network_name(iface) if iface else get_network_interface()
        self.subnet = get_subnet(self.iface)
        self.queue = asyncio.Queue()
        self.loop = None
        self.sniffer = None
        self.sniffer_lock = asyncio.Lock()
        self.protocol_enabled = {protocol: True for protocol in PROTOCOL_FILTERS}
        self.packet_timestamps = {protocol: deque() for protocol in PROTOCOL_FILTERS}
        self.new_device_notifications_enabled = False
        self.apprise_urls = ""
        self.notifier = apprise.Apprise()
        self.notification_tasks = set()
        logging.info("Using network interface %s with subnet %s", self.iface, self.subnet)

    async def load_protocol_settings(self):
        for protocol, key in PROTOCOL_CONFIG_KEYS.items():
            value = await database.get_config(key)
            if value is not None:
                self.protocol_enabled[protocol] = value.lower() in {"1", "true", "yes", "on"}

    @staticmethod
    def normalize_apprise_urls(urls: str) -> str:
        return "\n".join(url.strip() for url in urls.splitlines() if url.strip())

    @staticmethod
    def create_notifier(urls: str) -> apprise.Apprise:
        notifier = apprise.Apprise()
        url_list = urls.splitlines()
        if not url_list or not notifier.add(url_list):
            raise ValueError("At least one valid Apprise URL is required")
        return notifier

    async def load_notification_settings(self):
        enabled = await database.get_config(NEW_DEVICE_NOTIFICATIONS_ENABLED_CONFIG_KEY, "false")
        self.apprise_urls = self.normalize_apprise_urls(await database.get_config(APPRISE_URLS_CONFIG_KEY, ""))
        self.new_device_notifications_enabled = enabled.lower() in {"1", "true", "yes", "on"}
        if not self.new_device_notifications_enabled:
            return
        try:
            self.notifier = self.create_notifier(self.apprise_urls)
        except ValueError as exc:
            self.new_device_notifications_enabled = False
            logging.warning("Notifications disabled: %s", exc)

    def get_capture_filter(self) -> str | None:
        filters = [f"({PROTOCOL_FILTERS[protocol]})" for protocol, enabled in self.protocol_enabled.items() if enabled]
        return " or ".join(filters) or None

    def start_sniffer(self):
        capture_filter = self.get_capture_filter()
        if capture_filter is None:
            logging.info("Packet capture disabled")
            return
        self.sniffer = AsyncSniffer(iface=self.iface, filter=capture_filter, store=False, prn=self.packet_received)
        self.sniffer.start()
        logging.info("Packet capture filter: %s", capture_filter)

    def stop_sniffer(self):
        sniffer = self.sniffer
        self.sniffer = None
        if sniffer and sniffer.running:
            sniffer.stop()

    async def set_settings(
            self,
            protocol_settings: dict[str, bool],
            notifications_enabled: bool,
            apprise_urls: str,
    ):
        new_protocol_settings = {protocol: bool(protocol_settings[protocol]) for protocol in PROTOCOL_FILTERS}
        normalized_urls = self.normalize_apprise_urls(apprise_urls)
        new_notifier = self.create_notifier(normalized_urls) if notifications_enabled else apprise.Apprise()
        async with self.sniffer_lock:
            config = {
                PROTOCOL_CONFIG_KEYS[protocol]: str(enabled).lower()
                for protocol, enabled in new_protocol_settings.items()
            }
            config.update({
                NEW_DEVICE_NOTIFICATIONS_ENABLED_CONFIG_KEY: str(bool(notifications_enabled)).lower(),
                APPRISE_URLS_CONFIG_KEY: normalized_urls,
            })
            await database.set_config(config)
            changed_protocols = [protocol for protocol in PROTOCOL_FILTERS
                                 if self.protocol_enabled[protocol] != new_protocol_settings[protocol]]
            self.protocol_enabled.update(new_protocol_settings)
            self.new_device_notifications_enabled = bool(notifications_enabled)
            self.apprise_urls = normalized_urls
            self.notifier = new_notifier
            for protocol in changed_protocols:
                self.packet_timestamps[protocol].clear()
            if not changed_protocols:
                return
            self.stop_sniffer()
            self.start_sniffer()

    def schedule_new_device_notification(
            self,
            mac_addr: str,
            source: str,
            ip: str | None = None,
            hostname: str | None = None,
            vendor: str | None = None,
    ):
        if not self.new_device_notifications_enabled:
            return
        task = asyncio.create_task(
            self.send_new_device_notification(self.notifier, mac_addr, source, ip, hostname, vendor)
        )
        self.notification_tasks.add(task)
        task.add_done_callback(self.notification_tasks.discard)

    @staticmethod
    async def send_new_device_notification(
            notifier: apprise.Apprise,
            mac_addr: str,
            source: str,
            ip: str | None = None,
            hostname: str | None = None,
            vendor: str | None = None,
    ):
        details = [f"MAC: {mac_addr}", f"Detected via: {source}"]
        if ip:
            details.append(f"IP: {ip}")
        if hostname:
            details.append(f"Hostname: {hostname}")
        if vendor:
            details.append(f"Vendor: {vendor}")
        try:
            result = await notifier.async_notify(title="New device on the LAN", body="\n".join(details))
        except Exception:
            logging.exception("Apprise notification failed")
        else:
            if result is not True:
                logging.error("Apprise notification could not be delivered")

    def packet_received(self, packet):
        self.loop.call_soon_threadsafe(self.enqueue_packet, packet, time.monotonic())

    @staticmethod
    def get_packet_protocol(packet) -> str | None:
        if ARP in packet:
            return "arp"
        if DHCP in packet:
            return "dhcp"
        if DNS in packet:
            return "dns"
        return None

    def enqueue_packet(self, packet, received_at: float):
        protocol = self.get_packet_protocol(packet)
        if protocol is None or not self.protocol_enabled[protocol]:
            return
        self.packet_timestamps[protocol].append(received_at)
        self.queue.put_nowait(packet)

    def get_packet_counts(self) -> dict[str, int]:
        cutoff = time.monotonic() - PACKET_COUNT_WINDOW_SECONDS
        counts = {}
        for protocol, timestamps in self.packet_timestamps.items():
            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()
            counts[protocol] = len(timestamps)
        return counts

    def send_arp_discovery_sync(self):
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.subnet)
        sendp(packet, iface=self.iface, inter=0.01, verbose=False)

    async def send_arp_discovery(self):
        await run.io_bound(self.send_arp_discovery_sync)

    def send_mdns_discovery(self):
        packet = (
                IP(dst=f"224.0.0.251%{self.iface}")
                / UDP(sport=5353, dport=5353)
                / DNS(rd=0, qd=[DNSQR(qname="_services._dns-sd._udp.local.", qtype="PTR")])
        )
        send(packet, verbose=False)

    async def reverse_dns_lookup(self):
        devices = await database.get_device_ips()
        for device in devices:
            ip = device["ip"]
            if not ip:
                continue
            hostname = await resolve_hostname(ip)
            if not hostname:
                continue
            await database.add_hostname_of_ip(ip, hostname, "reverse_dns")

    async def lookup_vendor(self, mac_addr: str | None):
        try:
            return await mac.lookup(mac_addr)
        except KeyError:
            return None

    async def update_vendors(self):
        await mac.update_vendors()
        updated = 0
        for mac_addr in await database.get_device_macs():
            vendor = await self.lookup_vendor(mac_addr)
            if await database.update_device_vendor(mac_addr, vendor):
                updated += 1
        if updated:
            await database.flush()
        return updated

    async def process_arp(self, arp: ARP):
        vendor = await self.lookup_vendor(arp.hwsrc)
        is_new = await database.upsert_device(arp.hwsrc, arp.psrc, vendor)
        if is_new:
            self.schedule_new_device_notification(arp.hwsrc, "ARP", ip=arp.psrc, vendor=vendor)

    async def process_dhcp(self, packet):
        bootp = packet[BOOTP]
        options = {
            option[0]: option[1] for option in packet[DHCP].options if isinstance(option, tuple) and len(option) >= 2
        }
        mac_addr = bytes(bootp.chaddr[: bootp.hlen]).hex(":")
        message_type = options.get("message-type")
        hostname = options.get("hostname")
        fqdn = options.get("client_FQDN")
        requested_ip = options.get("requested_addr")
        vendor_class = options.get("vendor_class_id")
        server_id = options.get("server_id")
        if isinstance(hostname, bytes):
            hostname = hostname.decode(errors="ignore")
        if isinstance(fqdn, bytes):
            fqdn = fqdn[3:].decode(errors="ignore")
        if isinstance(vendor_class, bytes):
            vendor_class = vendor_class.decode(errors="ignore")
        logging.info(
            "DHCP: %s hostname=%s requested_ip=%s vendor=%s server=%s yiaddr=%s ciaddr=%s mac=%s fqdn=%s",
            message_type,
            hostname,
            requested_ip,
            vendor_class,
            server_id,
            bootp.yiaddr,
            bootp.ciaddr,
            mac_addr,
            fqdn,
        )
        vendor = await self.lookup_vendor(mac_addr)
        is_new = await database.upsert_device(mac_addr, None, vendor)
        await database.add_hostname_of_mac(mac_addr, hostname, "dhcp")
        if fqdn:
            await database.add_hostname_of_mac(mac_addr, fqdn, "dhcp")
        if is_new:
            self.schedule_new_device_notification(mac_addr, "DHCP", hostname=hostname or fqdn, vendor=vendor)

    async def process_dns(self, packet):
        packet_source_mac = packet[Ether].src
        packet_source_ip = packet[IP].src if IP in packet else None
        vendor = await self.lookup_vendor(packet_source_mac)
        is_new = await database.upsert_device(packet_source_mac, packet_source_ip, vendor)

        dns = packet[DNS]
        records = []
        packet_source_hostname = None
        if dns.an:
            records.extend(dns.an)
        if dns.ar:
            records.extend(dns.ar)
        for record in records:
            if record.type == 1:
                hostname = record.rrname.decode(errors="ignore").rstrip(".")
                ip = record.rdata
                await database.add_hostname_of_ip(ip, hostname, "mdns")
                if ip == packet_source_ip:
                    packet_source_hostname = hostname
        if is_new:
            self.schedule_new_device_notification(
                packet_source_mac,
                "mDNS",
                ip=packet_source_ip,
                hostname=packet_source_hostname,
                vendor=vendor,
            )

    async def process_packets(self):
        while True:
            packet = await self.queue.get()
            try:
                protocol = self.get_packet_protocol(packet)
                if protocol is None or not self.protocol_enabled[protocol]:
                    continue
                if protocol == "arp":
                    await self.process_arp(packet[ARP])
                elif protocol == "dhcp":
                    await self.process_dhcp(packet)
                elif protocol == "dns":
                    await self.process_dns(packet)
            finally:
                self.queue.task_done()

    async def run(self):
        self.loop = asyncio.get_running_loop()
        await self.load_protocol_settings()
        await self.load_notification_settings()
        async with self.sniffer_lock:
            self.start_sniffer()
        try:
            await self.process_packets()
        finally:
            async with self.sniffer_lock:
                self.stop_sniffer()


@ui.page("/")
async def index():
    edit_mode = False

    def prepare_rows(rows):
        for row in rows:
            row["_edit_mode"] = edit_mode
        return rows

    async def reload_rows():
        table.rows = prepare_rows(await database.get_devices())

    async def update_vendors():
        updated = await lan_radar.update_vendors()
        await reload_rows()
        noun = "vendor" if updated == 1 else "vendors"
        return f"Vendor list updated; {updated} device {noun} changed"

    async def save_note(event):
        try:
            changed = await database.set_device_note(event.args["mac"], event.args.get("note"))
        except Exception as exc:
            logging.exception("Saving note failed")
            ui.notify(f"Saving note failed: {exc}", type="negative", multi_line=True)
        else:
            if changed:
                ui.notify("Note saved", type="positive")

    def request_device_deletion(event):
        nonlocal device_to_delete
        device_to_delete = event.args["mac"]
        delete_device_label.set_text(f"Delete device {device_to_delete} and all of its data?")
        delete_device_dialog.open()

    async def confirm_device_deletion():
        nonlocal device_to_delete
        mac = device_to_delete
        if mac is None:
            return
        try:
            deleted = await database.delete_device(mac)
        except Exception as exc:
            logging.exception("Could not delete device")
            ui.notify(f"Could not delete device: {exc}", type="negative", multi_line=True)
        else:
            delete_device_dialog.close()
            device_to_delete = None
            await reload_rows()
            if deleted:
                ui.notify("Device deleted", type="positive")

    async def run_action(label, action):
        ui.notify(f"{label} started", type="info")
        try:
            result = action()
            if inspect.isawaitable(result):
                result = await result
        except Exception as exc:
            logging.exception("%s failed", label)
            ui.notify(f"{label} failed: {exc}", type="negative", multi_line=True)
        else:
            message = result if isinstance(result, str) else f"{label} completed"
            ui.notify(message, type="positive")

    stored_rows_per_page = await database.get_config(TABLE_ROWS_PER_PAGE_CONFIG_KEY, str(DEFAULT_TABLE_ROWS_PER_PAGE))
    try:
        rows_per_page = int(stored_rows_per_page)
        if rows_per_page < 0:
            raise ValueError
    except (TypeError, ValueError):
        rows_per_page = DEFAULT_TABLE_ROWS_PER_PAGE

    pagination_save_lock = asyncio.Lock()

    async def save_rows_per_page(event):
        nonlocal rows_per_page
        try:
            new_rows_per_page = int(event.value["rowsPerPage"])
        except (KeyError, TypeError, ValueError):
            return
        if new_rows_per_page < 0:
            return
        async with pagination_save_lock:
            if new_rows_per_page == rows_per_page:
                return
            try:
                await database.set_config({TABLE_ROWS_PER_PAGE_CONFIG_KEY: str(new_rows_per_page)})
            except Exception as exc:
                logging.exception("Could not save page size")
                ui.notify(f"Could not save page size: {exc}", type="negative", multi_line=True)
            else:
                rows_per_page = new_rows_per_page

    columns: list[dict[str, Any]] = [
        {"name": "mac"},
        {"name": "ip"},
        {"name": "hostname"},
        {"name": "vendor"},
        {"name": "note"},
        {"name": "first_seen"},
        {"name": "last_seen"},
    ]
    action_column = {"name": "actions", "label": "", "field": "actions", "sortable": False, "align": "right"}
    for column in columns:
        if "field" not in column: column["field"] = column["name"]
        if "label" not in column: column["label"] = column["name"]
    rows = prepare_rows(await database.get_devices())
    table = ui.table(
        rows=rows,
        columns=columns,
        column_defaults={"align": "left", "sortable": True},
        pagination=rows_per_page,
        on_pagination_change=save_rows_per_page,
    )
    table.props("dense").classes("w-full")
    table.add_slot(
        "body-cell-ip",
        """
        <q-td :props="props">
            <div class="row items-center no-wrap">
                <span>
                    {{ props.row.ip || '-' }}
                </span>
                <q-badge
                    v-if="props.row.ip_count > 1"
                    class="q-ml-xs"
                >
                    +{{ props.row.ip_count - 1 }}
                </q-badge>
                <q-tooltip v-if="props.row.ips">
                    {{ props.row.ips }}
                </q-tooltip>
            </div>
        </q-td>
    """)
    table.add_slot("body-cell-hostname", """
        <q-td :props="props">
            <div class="row items-center no-wrap" style="max-width: 280px">
                <span class="ellipsis">
                    {{ props.row.hostname || '-' }}
                </span>
                <q-badge
                    v-if="props.row.hostname_count > 1"
                    class="q-ml-xs"
                >
                    +{{ props.row.hostname_count - 1 }}
                </q-badge>
                <q-tooltip v-if="props.row.hostnames">
                    {{ props.row.hostnames }}
                </q-tooltip>
            </div>
        </q-td>
    """)
    table.add_slot("body-cell-note", """
        <q-td :props="props" style="max-width: 260px">
            <div v-if="props.row._edit_mode" class="row items-center no-wrap q-gutter-xs">
                <q-input
                    v-model="props.row.note"
                    type="textarea"
                    autogrow
                    dense
                    outlined
                    class="col"
                    style="min-width: 180px; max-width: 260px"
                />
                <q-btn
                    icon="save"
                    flat
                    round
                    dense
                    color="primary"
                    @click="$parent.$emit('note-change', {mac: props.row.mac, note: props.row.note})"
                >
                    <q-tooltip>Save note</q-tooltip>
                </q-btn>
            </div>
            <div v-else class="row items-center no-wrap">
                <span class="ellipsis" :class="{'text-grey-5': !props.row.note}">
                    {{ props.row.note || '-' }}
                </span>
            </div>
        </q-td>
    """)
    table.add_slot(
        "body-cell-actions",
        """
        <q-td :props="props" style="width: 40px">
            <q-btn
                v-if="props.row._edit_mode"
                icon="delete"
                flat
                round
                dense
                color="negative"
                @click="$parent.$emit('delete-device', {mac: props.row.mac})"
            >
                <q-tooltip>Delete device</q-tooltip>
            </q-btn>
        </q-td>
    """)
    table.on("note-change", save_note)
    table.on("delete-device", request_device_deletion)
    timestamp_slot = """
        <q-td :props="props">
            {{ props.value
                ? new Date(props.value * 1000).toLocaleString('en-US', {
                    day: '2-digit', month: '2-digit', year: '2-digit',
                    hour: '2-digit', minute: '2-digit', hour12: false,
                }).replace(',', '')
                : '-'
            }}
        </q-td>
    """
    table.add_slot("body-cell-first_seen", timestamp_slot)
    table.add_slot("body-cell-last_seen", timestamp_slot)
    packet_count_labels = {}
    with table.add_slot("bottom-row"):
        with ui.element("q-tr"):
            with ui.element("q-td").props("colspan=100"):
                with ui.row().classes("items-center q-gutter-md"):
                    ui.label("Packets in the last 60 seconds:").classes("text-caption text-grey-5")
                    for protocol in ("dhcp", "arp", "dns"):
                        packet_count_labels[protocol] = ui.badge(f"{protocol.upper()}: 0/min").props("outline")

    def update_packet_counts():
        for protocol, count in lan_radar.get_packet_counts().items():
            text = f"{count}/min" if lan_radar.protocol_enabled[protocol] else "off"
            packet_count_labels[protocol].set_text(f"{protocol.upper()}: {text}")

    update_packet_counts()
    ui.timer(1.0, update_packet_counts)

    settings_switches = {}
    device_to_delete = None

    def toggle_edit_mode():
        nonlocal edit_mode
        edit_mode = not edit_mode
        for row in table.rows:
            row["_edit_mode"] = edit_mode
        table.columns = columns + ([action_column] if edit_mode else [])
        edit_button.set_icon("done" if edit_mode else "edit")
        table.update()
        if edit_mode:
            edit_button.props(remove="color")
        else:
            edit_button.props("color=primary")

    async def save_settings():
        protocol_settings = {protocol: switch.value for protocol, switch in settings_switches.items()}
        try:
            await lan_radar.set_settings(
                protocol_settings,
                new_device_notifications_switch.value,
                apprise_urls_input.value or "",
            )
        except Exception as exc:
            logging.exception("Could not save settings")
            ui.notify(f"Could not save settings: {exc}", type="negative", multi_line=True)
        else:
            settings_dialog.close()
            ui.notify("Settings saved", type="positive")

    def open_settings():
        for protocol, switch in settings_switches.items():
            switch.value = lan_radar.protocol_enabled[protocol]
        new_device_notifications_switch.value = lan_radar.new_device_notifications_enabled
        apprise_urls_input.value = lan_radar.apprise_urls
        settings_dialog.open()

    with ui.dialog() as settings_dialog, ui.card().classes("min-w-96"):
        ui.label("Packet capture").classes("text-h6")
        ui.label("Select which packet types should be captured.").classes("text-caption text-grey-5")
        for protocol in PROTOCOL_FILTERS:
            settings_switches[protocol] = ui.switch(protocol.upper())
        ui.separator()
        ui.label("Notifications").classes("text-h6")
        new_device_notifications_switch = ui.switch("Notify me about new devices")
        apprise_urls_input = ui.textarea(
            "Apprise URLs",
            placeholder="One destination URL per line",
        ).props("outlined autogrow").classes("w-full")
        apprise_urls_input.bind_enabled_from(new_device_notifications_switch, "value")
        ui.link("Supported notification services", "https://appriseit.com/services/", new_tab=True)
        ui.separator()
        ui.label("Maintenance").classes("text-h6")
        ui.label("Refresh vendor data and update known devices.").classes("text-caption text-grey-5")
        ui.button("Update MAC vendors",
                  on_click=lambda: run_action("MAC vendor update", update_vendors)).props("outline")
        with ui.row().classes("w-full justify-end"):
            ui.button("Cancel", on_click=settings_dialog.close).props("flat")
            ui.button("Save", on_click=save_settings)

    with table.add_slot("top-right"):
        ui.input(placeholder="search...").bind_value(table, "filter").props("flat dense")
        ui.button("mdns", on_click=lambda: run_action("mDNS", lan_radar.send_mdns_discovery)).props("flat dense")
        ui.button("rdns", on_click=lambda: run_action("Reverse DNS", lan_radar.reverse_dns_lookup)).props("flat dense")
        ui.button("arp", on_click=lambda: run_action("ARP", lan_radar.send_arp_discovery)).props("flat dense")
        ui.button(icon="refresh", on_click=lambda: run_action("Refresh", reload_rows)).props("flat dense")
        edit_button = ui.button(icon="edit", on_click=toggle_edit_mode).props("flat dense")
        edit_button.tooltip("Toggle edit mode")
        ui.button(icon="settings", on_click=open_settings).props("flat dense").tooltip("Settings")

    with ui.dialog() as delete_device_dialog, ui.card():
        ui.label("Delete device").classes("text-h6")
        delete_device_label = ui.label()
        with ui.row().classes("w-full justify-end"):
            ui.button("Cancel", on_click=delete_device_dialog.close).props("flat")
            ui.button("Delete", on_click=confirm_device_deletion, color="negative")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    logging.info('Starting LAN Radar.')
    mac = AsyncMacLookup()
    BaseMacLookup.cache_path = str(Path.cwd() / "mac-vendors.txt")
    lan_radar = LanRadar()


    async def startup():
        await database.connect()
        await lan_radar.run()


    app.on_startup(startup)
    app.on_shutdown(database.close)
    app.add_middleware(HomeAssistantIngressMiddleware, enabled=HOME_ASSISTANT_INGRESS)
    if HOME_ASSISTANT_INGRESS:
        host = "0.0.0.0"
        port = get_ingress_port()
    else:
        host = "127.0.0.1"
        port = 8080
    try:
        ui.run(
            host=host,
            port=port,
            title="LAN-Radar",
            dark=True,
            language="en-US",
            show=False,
            reload=False,
        )
    except KeyboardInterrupt:
        logging.info('KeyboardInterrupt received. Stopping.')
