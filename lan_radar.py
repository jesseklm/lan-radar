import asyncio
import inspect
import ipaddress
import os
import socket
from pathlib import Path
from typing import Any

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
        if net == 0 or mask in {0, 0xffffffff} or address not in network:
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
        if route_iface != iface or net == 0 or mask == 0xffffffff:
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
        print(f"Using network interface {self.iface} with subnet {self.subnet}")

    def packet_received(self, packet):
        self.loop.call_soon_threadsafe(self.queue.put_nowait, packet)

    def send_arp_discovery_sync(self):
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.subnet)
        sendp(packet, iface=self.iface, inter=0.01, verbose=False)

    async def send_arp_discovery(self):
        await run.io_bound(self.send_arp_discovery_sync)

    def send_mdns_discovery(self):
        packet = (IP(dst=f"224.0.0.251%{self.iface}") / UDP(sport=5353, dport=5353)
                  / DNS(rd=0, qd=[DNSQR(qname="_services._dns-sd._udp.local.", qtype="PTR")]))
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
        # print("ARP:", arp.psrc, arp.hwsrc, vendor)
        await database.upsert_device(arp.hwsrc, arp.psrc, vendor)

    async def process_dhcp(self, packet):
        bootp = packet[BOOTP]
        options = {option[0]: option[1] for option in packet[DHCP].options
                   if isinstance(option, tuple) and len(option) >= 2}
        mac_addr = bytes(bootp.chaddr[:bootp.hlen]).hex(":")
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
        # await database.add_hostname_of_ip(ip, hostname, "mdns")
        print("DHCP:", message_type, "hostname=", hostname, "requested_ip=", requested_ip, "vendor=", vendor_class,
              "server=", server_id, bootp.yiaddr, bootp.ciaddr, mac_addr, fqdn)
        vendor = await self.lookup_vendor(mac_addr)
        await database.upsert_device(mac_addr, None, vendor)
        await database.add_hostname_of_mac(mac_addr, hostname, "dhcp")
        if fqdn:
            await database.add_hostname_of_mac(mac_addr, fqdn, "dhcp")

    async def process_dns(self, packet):
        packet_source_mac = packet[Ether].src
        packet_source_ip = packet[IP].src if IP in packet else None
        vendor = await self.lookup_vendor(packet_source_mac)
        await database.upsert_device(packet_source_mac, packet_source_ip, vendor)

        dns = packet[DNS]
        if dns.qr != 1:
            return
        records = []
        if dns.an:
            records.extend(dns.an)
        if dns.ar:
            records.extend(dns.ar)
        for record in records:
            if record.type == 1:
                hostname = record.rrname.decode(errors="ignore").rstrip(".")
                ip = record.rdata
                # print(f"mDNS hostname: {hostname} -> {ip}")
                await database.add_hostname_of_ip(ip, hostname, "mdns")

    async def process_packets(self):
        while True:
            packet = await self.queue.get()
            if ARP in packet:
                await self.process_arp(packet[ARP])
            elif DHCP in packet:
                await self.process_dhcp(packet)
            elif DNS in packet:
                await self.process_dns(packet)
            self.queue.task_done()

    async def run(self):
        self.loop = asyncio.get_running_loop()
        self.sniffer = AsyncSniffer(iface=self.iface, filter="arp or udp port 5353 or udp port 67 or udp port 68",
                                    store=False, prn=self.packet_received)
        self.sniffer.start()
        try:
            await self.process_packets()
        finally:
            self.sniffer.stop()


@ui.page("/")
async def index():
    async def reload_rows():
        table.rows = await database.get_devices()

    async def update_vendors():
        updated = await lan_radar.update_vendors()
        await reload_rows()
        noun = "vendor" if updated == 1 else "vendors"
        return f"Vendor list updated; {updated} device {noun} changed"

    async def save_note(event):
        try:
            changed = await database.set_device_note(event.args["mac"], event.args.get("note"))
        except Exception as exc:
            print("Saving note failed:", exc)
            ui.notify(f"Saving note failed: {exc}", type="negative", multi_line=True, position="bottom-right")
        else:
            if changed:
                ui.notify("Note saved", type="positive", position="bottom-right")

    async def run_action(label, action):
        ui.notify(f"{label} started", type="info", position="bottom-right")
        try:
            result = action()
            if inspect.isawaitable(result):
                result = await result
        except Exception as exc:
            print(f"{label} failed:", exc)
            ui.notify(f"{label} failed: {exc}", type="negative", multi_line=True, position="bottom-right")
        else:
            message = result if isinstance(result, str) else f"{label} completed"
            ui.notify(message, type="positive", position="bottom-right")

    columns: list[dict[str, Any]] = [{"name": "mac"}, {"name": "ip"}, {"name": "hostname"},
                                     {"name": "vendor"}, {"name": "note"}, {"name": "first_seen"},
                                     {"name": "last_seen"}]
    for column in columns:
        if "field" not in column: column["field"] = column["name"]
        if "label" not in column: column["label"] = column["name"]
    rows = await database.get_devices()
    table = ui.table(rows=rows, columns=columns, column_defaults={'align': 'left', 'sortable': True}, pagination=50)
    table.props('dense').classes('w-full')
    table.add_slot("body-cell-ip", """
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
            <div class="row items-center no-wrap cursor-pointer">
                <span class="ellipsis" :class="{'text-grey-5': !props.row.note}">
                    {{ props.row.note || 'Add note...' }}
                </span>
                <q-icon name="edit" size="xs" class="q-ml-xs text-grey-5" />
            </div>
            <q-popup-edit
                v-model="props.row.note"
                v-slot="scope"
                buttons
                label-set="Save"
                label-cancel="Cancel"
                @save="$parent.$emit('note-change', {mac: props.row.mac, note: $event})"
            >
                <q-input v-model="scope.value" type="textarea" autogrow autofocus dense style="min-width: 300px" />
            </q-popup-edit>
        </q-td>
    """)
    table.on("note-change", save_note)
    timestamp_slot = """
        <q-td :props="props">
            {{ props.value
                ? new Date(props.value * 1000).toLocaleString('de-DE', {
                    day: '2-digit', month: '2-digit', year: '2-digit',
                    hour: '2-digit', minute: '2-digit', hour12: false,
                }).replace(',', '')
                : '-'
            }}
        </q-td>
    """
    table.add_slot("body-cell-first_seen", timestamp_slot)
    table.add_slot("body-cell-last_seen", timestamp_slot)
    with table.add_slot("top-right"):
        ui.input(placeholder='search...').bind_value(table, 'filter').props('flat dense')
        ui.button('macs', on_click=lambda: run_action('MAC update vendors', update_vendors)).props('flat dense')
        ui.button('mdns', on_click=lambda: run_action('mDNS', lan_radar.send_mdns_discovery)).props('flat dense')
        ui.button('rdns', on_click=lambda: run_action('Reverse DNS', lan_radar.reverse_dns_lookup)).props('flat dense')
        ui.button('arp', on_click=lambda: run_action('ARP', lan_radar.send_arp_discovery)).props('flat dense')
        ui.button(icon='refresh', on_click=lambda: run_action('Refresh', reload_rows)).props('flat dense')


if __name__ == "__main__":
    mac = AsyncMacLookup()
    BaseMacLookup.cache_path = str(Path.cwd() / "mac-vendors.txt")
    lan_radar = LanRadar()
    app.on_startup(database.connect)
    app.on_startup(lan_radar.run)
    app.on_shutdown(database.close)
    app.add_middleware(HomeAssistantIngressMiddleware, enabled=HOME_ASSISTANT_INGRESS)
    host = "0.0.0.0" if HOME_ASSISTANT_INGRESS else "127.0.0.1"
    port = 8099 if HOME_ASSISTANT_INGRESS else 8080
    ui.run(host=host, port=port, title="LAN-Radar", dark=True, language="en-US", show=False, reload=False)
