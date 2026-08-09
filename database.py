import asyncio
import ipaddress
import time
from collections import defaultdict
from contextlib import suppress

import aiosqlite


class Database:
    def __init__(self, path: str = "lanradar.db", flush_interval: int = 300):
        self.path = path
        self.flush_interval = flush_interval
        self.db = None

        # Complete current state in memory
        self.devices = {}
        self.device_ips = {}
        self.device_hostnames = {}

        # Latest IP -> MAC(s), so add_hostname_of_ip() does not need SQL and
        # historical assignments cannot produce incorrect hostnames.
        self.ip_to_macs = defaultdict(set)

        # Only these entries need to be written during the next flush
        self.dirty_devices = set()
        self.dirty_ips = set()
        self.dirty_hostnames = set()

        self.flush_task = None
        self.flush_lock = asyncio.Lock()

    async def connect(self):
        if self.db:
            return

        self.db = await aiosqlite.connect(self.path)
        self.db.row_factory = aiosqlite.Row

        await self.db.execute("PRAGMA foreign_keys = ON")

        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY COLLATE NOCASE,
                vendor TEXT,
                note TEXT,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL
            )
        """)

        cursor = await self.db.execute("PRAGMA table_info(devices)")
        if "note" not in {row["name"] for row in await cursor.fetchall()}:
            await self.db.execute("ALTER TABLE devices ADD COLUMN note TEXT")

        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS device_ips (
                id INTEGER PRIMARY KEY,
                device_mac TEXT NOT NULL,
                ip_packed BLOB NOT NULL,
                ip_version INTEGER NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                FOREIGN KEY(device_mac) REFERENCES devices(mac) ON DELETE CASCADE,
                UNIQUE(device_mac, ip_version, ip_packed)
            )
        """)

        await self.db.execute("""
            CREATE INDEX IF NOT EXISTS idx_device_ips_address
            ON device_ips(ip_version, ip_packed)
        """)

        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS device_hostnames (
                id INTEGER PRIMARY KEY,
                device_mac TEXT NOT NULL,
                hostname TEXT NOT NULL COLLATE NOCASE,
                source TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                FOREIGN KEY(device_mac) REFERENCES devices(mac) ON DELETE CASCADE,
                UNIQUE(device_mac, hostname, source)
            )
        """)

        await self.db.commit()
        await self.load_cache()

        self.flush_task = asyncio.create_task(self.flush_loop())

    async def close(self):
        if not self.db:
            return

        if self.flush_task:
            self.flush_task.cancel()
            with suppress(asyncio.CancelledError):
                await self.flush_task
            self.flush_task = None

        await self.flush()

        await self.db.close()
        self.db = None

    async def load_cache(self):
        self.devices.clear()
        self.device_ips.clear()
        self.device_hostnames.clear()
        self.ip_to_macs.clear()
        self.dirty_devices.clear()
        self.dirty_ips.clear()
        self.dirty_hostnames.clear()

        cursor = await self.db.execute("""
            SELECT
                mac,
                vendor,
                note,
                first_seen,
                last_seen
            FROM devices
        """)

        for row in await cursor.fetchall():
            device = dict(row)
            mac = device["mac"]
            self.devices[mac] = device

        cursor = await self.db.execute("""
            SELECT
                device_mac,
                ip_packed,
                ip_version,
                first_seen,
                last_seen
            FROM device_ips
        """)

        for row in await cursor.fetchall():
            entry = dict(row)
            key = self._ip_key(entry["device_mac"], entry["ip_version"], entry["ip_packed"])
            self.device_ips[key] = entry

        for device in self.devices.values():
            latest_ip = self._latest_ip(device["mac"])
            if latest_ip:
                self._add_ip_index(latest_ip)

        cursor = await self.db.execute("""
            SELECT
                device_mac,
                hostname,
                source,
                first_seen,
                last_seen
            FROM device_hostnames
        """)

        for row in await cursor.fetchall():
            entry = dict(row)
            key = self._hostname_key(entry["device_mac"], entry["hostname"], entry["source"])
            self.device_hostnames[key] = entry

    def _hostname_key(self, mac: str, hostname: str, source: str):
        return (mac.strip().lower(), hostname.strip().rstrip(".").casefold(), source.strip().lower())

    def _ip_key(self, mac: str, ip_version: int, ip_packed: bytes):
        return (mac.strip().lower(), ip_version, ip_packed)

    def _ips_for_mac(self, mac: str):
        return [entry for entry in self.device_ips.values() if entry["device_mac"] == mac]

    def _latest_ip(self, mac: str):
        entries = self._ips_for_mac(mac)
        if not entries:
            return None

        return max(entries, key=lambda entry: (
            entry["last_seen"], entry["first_seen"], entry["ip_version"], entry["ip_packed"]
        ))

    def _device_sort_key(self, device):
        latest_ip = self._latest_ip(device["mac"])
        return (
            latest_ip is None,
            latest_ip["ip_version"] if latest_ip else 0,
            latest_ip["ip_packed"] if latest_ip else b"",
        )

    def _add_ip_index(self, entry):
        self.ip_to_macs[(entry["ip_version"], entry["ip_packed"])].add(entry["device_mac"])

    def _remove_ip_index(self, entry):
        key = (entry["ip_version"], entry["ip_packed"])
        macs = self.ip_to_macs.get(key)
        if not macs:
            return

        macs.discard(entry["device_mac"])
        if not macs:
            self.ip_to_macs.pop(key, None)

    def get_preferred_hostname(self, mac: str):
        entries = [entry for entry in self.device_hostnames.values() if entry["device_mac"] == mac]

        if not entries:
            return None

        priority = {"dhcp": 0, "reverse_dns": 1, "mdns": 2}

        return min(entries, key=lambda entry: (priority.get(entry["source"], 99), -entry["last_seen"]))["hostname"]

    async def get_devices(self):
        devices = []

        for device in sorted(self.devices.values(), key=self._device_sort_key):
            ip_entries = sorted(self._ips_for_mac(device["mac"]), key=lambda entry: (
                -entry["last_seen"], -entry["first_seen"], entry["ip_version"], entry["ip_packed"]
            ))
            latest_ip = ip_entries[0] if ip_entries else None
            hostnames = [entry for entry in self.device_hostnames.values() if entry["device_mac"] == device["mac"]]

            all_hostnames = sorted(f'{entry["hostname"]} [{entry["source"]}]' for entry in hostnames)
            all_ips = [str(ipaddress.ip_address(entry["ip_packed"])) for entry in ip_entries]

            devices.append({
                "mac": device["mac"],
                "ip": str(ipaddress.ip_address(latest_ip["ip_packed"])) if latest_ip else None,
                "ip_count": len(ip_entries),
                "ips": ", ".join(all_ips) if all_ips else None,
                "hostname": self.get_preferred_hostname(device["mac"]),
                "hostname_count": len(hostnames),
                "hostnames": ", ".join(all_hostnames) if all_hostnames else None,
                "vendor": device["vendor"],
                "note": device["note"],
                "first_seen": device["first_seen"],
                "last_seen": device["last_seen"],
            })

        return devices

    async def get_device_ips(self):
        result = []

        for device in sorted(self.devices.values(), key=self._device_sort_key):
            latest_ip = self._latest_ip(device["mac"])
            result.append({
                "mac": device["mac"],
                "ip": str(ipaddress.ip_address(latest_ip["ip_packed"])) if latest_ip else None,
            })

        return result

    async def get_device_macs(self):
        return sorted(self.devices)

    async def get_device_by_mac(self, mac: str):
        mac = mac.strip().lower()
        device = self.devices.get(mac)
        if not device:
            return None

        result = dict(device)
        latest_ip = self._latest_ip(mac)
        result["ip_packed"] = latest_ip["ip_packed"] if latest_ip else None
        result["ip_version"] = latest_ip["ip_version"] if latest_ip else None
        return result

    async def get_device_hostname_by_mac(self, mac: str):
        mac = mac.strip().lower()

        hostnames = [f'{entry["hostname"]} [{entry["source"]}]' for entry in self.device_hostnames.values()
                     if entry["device_mac"] == mac]

        return ", ".join(sorted(hostnames)) if hostnames else None

    async def set_device_note(self, mac: str, note: str | None):
        mac = mac.strip().lower()
        note = note.strip() if note and note.strip() else None
        device = self.devices.get(mac)
        if not device or device["note"] == note:
            return False

        device["note"] = note
        self.dirty_devices.add(mac)
        await self.flush()
        return True

    async def update_device_vendor(self, mac: str, vendor: str | None):
        mac = mac.strip().lower()
        vendor = vendor.strip() if vendor else None
        device = self.devices.get(mac)
        if not device or not vendor or device["vendor"] == vendor:
            return False

        device["vendor"] = vendor
        self.dirty_devices.add(mac)
        return True

    async def upsert_device(self, mac: str, ip: str | None, vendor: str | None):
        mac = mac.strip().lower()
        vendor = vendor.strip() if vendor else None
        now = int(time.time())

        ip_packed = None
        ip_version = None

        if ip is not None:
            address = ipaddress.ip_address(ip)

            # Do not treat 0.0.0.0 or :: as an actual device IP
            if not address.is_unspecified:
                ip_packed = address.packed
                ip_version = address.version

        device = self.devices.get(mac)

        if device:
            if vendor:
                device["vendor"] = vendor

            device["last_seen"] = now

        else:
            device = {"mac": mac, "vendor": vendor, "note": None, "first_seen": now, "last_seen": now}

            self.devices[mac] = device

        self.dirty_devices.add(mac)

        if ip_packed is not None:
            old_latest_ip = self._latest_ip(mac)
            key = self._ip_key(mac, ip_version, ip_packed)
            entry = self.device_ips.get(key)

            if entry:
                entry["last_seen"] = now
            else:
                entry = {
                    "device_mac": mac, "ip_packed": ip_packed, "ip_version": ip_version,
                    "first_seen": now, "last_seen": now,
                }
                self.device_ips[key] = entry

            self.dirty_ips.add(key)

            new_latest_ip = self._latest_ip(mac)
            if old_latest_ip is not new_latest_ip:
                if old_latest_ip:
                    self._remove_ip_index(old_latest_ip)
                self._add_ip_index(new_latest_ip)

    async def add_hostname_of_mac(self, mac: str, hostname: str | None, source: str):
        if not hostname:
            return False

        mac = mac.strip().lower()
        hostname = hostname.strip().rstrip(".")
        source = source.strip().lower()

        if not hostname:
            return False

        now = int(time.time())
        key = self._hostname_key(mac, hostname, source)

        entry = self.device_hostnames.get(key)

        if entry:
            entry["last_seen"] = now
        else:
            self.device_hostnames[key] = {
                "device_mac": mac, "hostname": hostname, "source": source, "first_seen": now, "last_seen": now,
            }

        self.dirty_hostnames.add(key)
        return True

    async def add_hostname_of_ip(self, ip: str, hostname: str | None, source: str):
        if not hostname:
            return False

        address = ipaddress.ip_address(ip)
        key = (address.version, address.packed)

        macs = self.ip_to_macs.get(key)

        if not macs:
            return False

        for mac in tuple(macs):
            await self.add_hostname_of_mac(mac, hostname, source)

        return True

    async def flush_loop(self):
        while True:
            await asyncio.sleep(self.flush_interval)

            try:
                await self.flush()
            except Exception as exc:
                print("Database flush failed:", exc)

    async def flush(self):
        if not self.db:
            return

        async with self.flush_lock:
            if not self.dirty_devices and not self.dirty_ips and not self.dirty_hostnames:
                return

            device_keys = self.dirty_devices.copy()
            ip_keys = self.dirty_ips.copy()
            hostname_keys = self.dirty_hostnames.copy()

            # Remove these keys from the dirty sets now. Changes made during
            # the following await are automatically marked for the next flush.
            self.dirty_devices.difference_update(device_keys)
            self.dirty_ips.difference_update(ip_keys)
            self.dirty_hostnames.difference_update(hostname_keys)

            devices = [self.devices[key].copy() for key in device_keys if key in self.devices]
            ips = [self.device_ips[key].copy() for key in ip_keys if key in self.device_ips]
            hostnames = [self.device_hostnames[key].copy() for key in hostname_keys if key in self.device_hostnames]

            try:
                if devices:
                    await self.db.executemany("""
                        INSERT INTO devices (
                            mac,
                            vendor,
                            note,
                            first_seen,
                            last_seen
                        )
                        VALUES (?, ?, ?, ?, ?)

                        ON CONFLICT(mac) DO UPDATE SET
                            vendor = excluded.vendor,
                            note = excluded.note,
                            last_seen = excluded.last_seen
                    """, [
                        (device["mac"], device["vendor"], device["note"], device["first_seen"], device["last_seen"])
                        for device in devices
                    ])

                if ips:
                    await self.db.executemany("""
                        INSERT INTO device_ips (
                            device_mac,
                            ip_packed,
                            ip_version,
                            first_seen,
                            last_seen
                        )
                        VALUES (?, ?, ?, ?, ?)

                        ON CONFLICT(device_mac, ip_version, ip_packed) DO UPDATE SET
                            last_seen = excluded.last_seen
                    """, [
                        (entry["device_mac"], entry["ip_packed"], entry["ip_version"], entry["first_seen"],
                         entry["last_seen"])
                        for entry in ips
                    ])

                if hostnames:
                    await self.db.executemany("""
                        INSERT INTO device_hostnames (
                            device_mac,
                            hostname,
                            source,
                            first_seen,
                            last_seen
                        )
                        VALUES (?, ?, ?, ?, ?)

                        ON CONFLICT(device_mac, hostname, source) DO UPDATE SET
                            last_seen = excluded.last_seen
                    """, [
                        (entry["device_mac"], entry["hostname"], entry["source"], entry["first_seen"],
                         entry["last_seen"])
                        for entry in hostnames
                    ])

                await self.db.commit()

                if devices or ips or hostnames:
                    print(f"DB flush: {len(devices)} devices, {len(ips)} IPs, {len(hostnames)} hostnames")

            except Exception:
                await self.db.rollback()

                # Mark the entries as dirty again after an error.
                self.dirty_devices.update(device_keys)
                self.dirty_ips.update(ip_keys)
                self.dirty_hostnames.update(hostname_keys)

                raise


database = Database()
