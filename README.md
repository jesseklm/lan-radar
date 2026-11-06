# LAN Radar

LAN Radar keeps an inventory of devices seen on your local network. It listens for ARP, DHCP and mDNS traffic, combines observations by MAC address, and displays device details in a NiceGUI web interface.

[Installation](#installation) · [Docker Compose](#docker-compose) · [Home Assistant add-on](#home-assistant-add-on) · [Using LAN Radar](#using-lan-radar) · [Configuration](#configuration) · [Storage](#storage-and-backups) · [Troubleshooting](#troubleshooting)

## Features

- Discover devices through passive ARP, DHCP and mDNS capture, with manual ARP and mDNS discovery actions.
- Track MAC addresses, IP address history, hostnames and their sources, manufacturers, and first/last seen times.
- Search and sort the device table, add notes, and delete devices and their recorded history.
- View packet counts for each protocol over the last 60 seconds and enable or disable capture per protocol.
- Send notifications about newly discovered devices through [Apprise](https://appriseit.com/services/), including a test notification from the settings dialog.
- Keep devices and settings in SQLite, with optional Keycloak sign-in and Home Assistant Supervisor ingress integration.

## How discovery works

LAN Radar listens on one network interface. All three capture protocols are enabled initially:

| Protocol | Observations |
| --- | --- |
| ARP | Device MAC addresses and IPv4 addresses |
| DHCP | Client MAC addresses, hostnames and fully qualified domain names |
| mDNS | Sender MAC/IP addresses and hostnames from IPv4 address records in responses on UDP port 5353 |

Discovery depends on the traffic that reaches the selected interface. Switches, VLANs, Wi-Fi client isolation and quiet devices can limit what the host sees. Place LAN Radar on the network segment you want to observe; promiscuous capture alone does not make a switch forward every device's traffic to it.

The interface must have an IPv4 address and a matching subnet route. Manual ARP discovery covers that subnet; mDNS discovery sends a multicast query through the same interface. Active discovery runs when you use the corresponding button. A device's **last seen** time records its most recent observation; it is not a continuous availability check.

## Installation

Choose the deployment that fits your setup:

| Method | Requirements | Web interface |
| --- | --- | --- |
| [Docker Compose](#docker-compose) | Docker Engine on Linux with Docker Compose | `http://127.0.0.1:8080` on the Docker host |
| [Home Assistant add-on](#home-assistant-add-on) | Home Assistant with Supervisor and the app/add-on store | Open Web UI inside Home Assistant |

Both methods run LAN Radar in a container with its Python and packet capture dependencies included. The host needs an interface connected to the LAN you want to observe.

### Docker Compose

Create a `compose.yaml` file:

```yaml
services:
  lan-radar:
    image: ghcr.io/jesseklm/lan-radar:master
    restart: unless-stopped
    network_mode: host
    cap_add:
      - NET_RAW
    environment:
      NETWORK_INTERFACE: "${NETWORK_INTERFACE:-}"
    volumes:
      - lan-radar-data:/data

volumes:
  lan-radar-data:
```

The example follows the `master` image. To pin a release, replace `master` with a published version tag. The [Docker workflow](.github/workflows/docker-publish.yml) builds images for `linux/amd64` and `linux/arm64/v8`.

`NETWORK_INTERFACE` is optional. Leave it unset for automatic selection, or create a `.env` file next to `compose.yaml` to select your host's LAN interface:

```dotenv
NETWORK_INTERFACE=enp3s0
```

Replace `enp3s0` with the name shown by `ip -br -4 addr`. Compose [substitutes values from `.env`](https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/) into the container configuration. The selection applies to capture, ARP discovery and mDNS discovery; surrounding whitespace is ignored. An empty value uses automatic selection, and an invalid name stops startup with an error.

Start LAN Radar from the directory containing `compose.yaml`:

```sh
docker compose up -d
```

Open **[http://127.0.0.1:8080](http://127.0.0.1:8080)** on the Docker host. The standalone server listens on the loopback address. For access from another machine, use an SSH tunnel or a reverse proxy on the host that forwards HTTP and WebSocket traffic. Sign-in is disabled until you configure [Keycloak](#keycloak-sign-in).

Host networking gives the container access to the host's LAN interfaces; `NET_RAW` permits raw packet sockets. The named volume keeps application data under `/data`. See the [Compose service reference](https://docs.docker.com/reference/compose-file/services/) for these options.

This setup targets native Linux. [Docker Desktop's host networking](https://docs.docker.com/engine/network/drivers/host/#limitations) operates at TCP/UDP level and does not provide the same Ethernet access needed for ARP capture. Host networking uses the host's ports directly; omit a `ports:` mapping.

View logs, stop the service, or update the image:

```sh
docker compose logs --follow lan-radar
docker compose stop

docker compose pull
docker compose up -d
```

### Home Assistant add-on

Install **LAN Radar** from the [jesseklm/hassio-addons repository](https://github.com/jesseklm/hassio-addons):

1. In Home Assistant, open **Settings → Apps → Install app**. Older versions call this **Settings → Add-ons → Add-on store**.
2. Open the **⋮** menu, select **Repositories**, and add `https://github.com/jesseklm/hassio-addons`.
3. Find **LAN Radar** in the store and select **Install**.
4. Start the add-on. Optionally enable **Start on boot** and **Show in sidebar**.
5. Select **Open Web UI** to access LAN Radar through Home Assistant ingress.

See Home Assistant's [repository installation guide](https://www.home-assistant.io/common-tasks/os/#installing-a-third-party-app-repository) for the store setup.

The [add-on configuration](https://github.com/jesseklm/hassio-addons/blob/master/lan-radar/config.yaml) enables host networking, raw packet access and ingress for `amd64` and `aarch64` systems. Home Assistant supplies the Supervisor token and manages the ingress connection. Use the add-on's **Log** tab for startup information and the Home Assistant UI to install updates.

The current add-on uses automatic interface selection and does not expose a `NETWORK_INTERFACE` option. Configure capture preferences, notifications and display settings in LAN Radar's web interface.

## Using LAN Radar

The device table shows each device's most recently observed IP, a preferred hostname, manufacturer, note, and first/last seen timestamps. Badges and tooltips show additional recorded IP addresses and hostnames. Hostname selection prefers DHCP, then reverse DNS, then mDNS.

| Control | Action |
| --- | --- |
| Search | Filter the device table |
| `mdns` | Send a multicast service discovery query |
| `rdns` | Resolve the latest known IP address of each device through reverse DNS |
| `arp` | Send ARP requests across the selected IPv4 subnet |
| Refresh icon | Reload the device table from the current inventory |
| Edit icon | Show note editors and device deletion controls |
| Settings icon | Configure capture, notifications and date formatting, or update MAC vendor data |

Packet counters update every second. Use **Refresh** to load new device observations into the table. The selected page size is saved between visits.

### Capture and display settings

Open **Settings** to enable or disable DHCP, ARP and mDNS capture individually. Saving applies the capture filter immediately; disabling all three stops capture. Manual discovery actions remain available.

Date/time display supports English (`MM/DD/YY`) and German (`DD.MM.YY`) formats, both with a 24-hour clock. The default is English. Settings are shared by the application, including when multiple users sign in.

### New-device notifications

1. Open **Settings** and enable **Notify me about new devices**.
2. Enter a network name to include in notification titles.
3. Add one Apprise destination URL per line. Use the [supported service documentation](https://appriseit.com/services/) to find the URL format for your service.
4. Click **Send test notification** to check delivery, then **Save**.

Notifications are disabled by default. They are triggered when a MAC address is first added to the inventory. Deleting a device removes its history; a later observation can add it again and trigger another notification. Devices using changing/private MAC addresses can therefore appear as separate devices.

## Configuration

For Docker Compose, pass startup options through the service's `environment` mapping. A `.env` file supplies values for `${VARIABLE}` references in that mapping; the application itself reads the resulting environment variables. Capture preferences, notifications and display settings are saved through the web interface.

The Home Assistant add-on manages its own startup environment. The table below describes application variables; it is not a list of options exposed by the add-on.

| Variable | Default | Purpose |
| --- | --- | --- |
| `NETWORK_INTERFACE` | Automatic selection | Interface for capture and discovery |
| `KEYCLOAK_BASE_URL` | Unset | Keycloak server URL, without `/realms/<realm>` |
| `KEYCLOAK_REALM` | Unset | Keycloak realm name |
| `KEYCLOAK_CLIENT_ID` | Unset | OpenID Connect client ID |
| `KEYCLOAK_CLIENT_SECRET` | Unset | OpenID Connect client secret |
| `STORAGE_SECRET` | Unset | NiceGUI session/storage secret; required with Keycloak |
| `KEYCLOAK_CUSTOM_CA_FILE` | Unset | Path to a trusted CA certificate file for Keycloak connections |
| `HOME_ASSISTANT_INGRESS` | Disabled | Enable Supervisor ingress; set to `true` by the Home Assistant add-on |
| `SUPERVISOR_TOKEN` | Unset | Supervisor API token, supplied by Home Assistant in ingress mode |

### Keycloak sign-in

Setting any of the four `KEYCLOAK_BASE_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID` or `KEYCLOAK_CLIENT_SECRET` values enables Keycloak configuration. All four values and `STORAGE_SECRET` must then be provided; incomplete configuration stops startup.

Create an OpenID Connect client in your realm with client authentication and the authorization code flow enabled. The application requests the `openid profile email` scopes and uses PKCE with `S256`.

Register the callback URL for the address you use to access LAN Radar:

```text
http://127.0.0.1:8080/auth/keycloak
```

For access through a reverse proxy, register the corresponding external URL, such as `https://radar.example.com/auth/keycloak`, and configure forwarded scheme/host handling so the application generates that URL.

For Docker Compose, extend the service's existing `environment` mapping:

```yaml
environment:
  NETWORK_INTERFACE: "${NETWORK_INTERFACE:-}"
  KEYCLOAK_BASE_URL: "${KEYCLOAK_BASE_URL}"
  KEYCLOAK_REALM: "${KEYCLOAK_REALM}"
  KEYCLOAK_CLIENT_ID: "${KEYCLOAK_CLIENT_ID}"
  KEYCLOAK_CLIENT_SECRET: "${KEYCLOAK_CLIENT_SECRET}"
  STORAGE_SECRET: "${STORAGE_SECRET}"
```

Add the corresponding values to `.env`:

```dotenv
KEYCLOAK_BASE_URL=https://keycloak.example.com
KEYCLOAK_REALM=home
KEYCLOAK_CLIENT_ID=lan-radar
KEYCLOAK_CLIENT_SECRET=replace-with-your-client-secret
STORAGE_SECRET=replace-with-a-long-random-secret
```

Generate `STORAGE_SECRET` once, for example with `openssl rand -hex 32`, and keep it stable across restarts. Apply the configuration with `docker compose up -d`. For a private certificate authority, mount its certificate file and set `KEYCLOAK_CUSTOM_CA_FILE` to the file's path inside the container.

Users are redirected to the sign-in page when Keycloak is enabled. The logout button clears the LAN Radar session; the Keycloak session is managed separately.

## Storage and backups

Both deployment methods store application data under `/data`: Docker Compose uses the `lan-radar-data` volume, and Home Assistant manages the add-on's persistent data directory.

| Path | Contents |
| --- | --- |
| `lanradar.db` | Devices, address/hostname history, notes and application settings |
| `mac-vendors.txt` | Local manufacturer lookup cache |
| `.nicegui/` | NiceGUI persistent storage used for sessions when enabled |

Device observations are buffered in memory and flushed to SQLite every **five minutes**, with a final flush on graceful shutdown. Settings and saved notes are committed immediately. Stop the application cleanly before copying its data directory for a simple backup. Keep the Compose volume when replacing the container; for Home Assistant, include LAN Radar in your Home Assistant backups.

Manufacturer lookup downloads a vendor list when no cached list is available. **Settings → Update MAC vendors** refreshes the list and updates known devices. Internet access is needed for these downloads and for any notification or authentication service hosted outside your network.

Apprise destination URLs are stored in the database and may contain service credentials. Include the database and NiceGUI storage in your deployment's access controls and backup handling.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| `Operation not permitted` or packet socket permission errors | Run with capture permissions; for the documented container setup, check the network capabilities. |
| Capture filter / `libpcap` errors | Install the system `libpcap` package and restart. |
| `Invalid NETWORK_INTERFACE` | Check `ip -br -4 addr`. In Docker, the interface must exist in the container's network namespace. |
| No active interface / no IPv4 subnet found | Check that the selected interface has an IPv4 address and a matching subnet route. |
| No devices, or only a few devices | Check the selected interface, enabled capture protocols, packet counters, and network segment. Try ARP discovery, then refresh the table. |
| Device table looks stale | Use Refresh; only packet counters update on a timer. |
| Browser cannot connect from another machine | Compose uses `127.0.0.1:8080`; use a tunnel or reverse proxy. For the Home Assistant add-on, use Open Web UI. |
| Vendor names are missing | Refresh the vendor list and check download connectivity; some MAC prefixes have no manufacturer entry. |
| Notifications fail | Use Send test notification, check the service URL format, and inspect the application logs. |
| Keycloak configuration / callback errors | Supply all required variables, keep the storage secret stable, and match the callback URL to the browser-facing address. |
| `403 Forbidden` in ingress mode | Check the Supervisor proxy address and ingress headers, and access the application through Home Assistant ingress. |

Startup logs report the selected interface, subnet and capture filter. Use `docker compose logs lan-radar` or the Home Assistant add-on's **Log** tab.

## Project structure

| File | Responsibility |
| --- | --- |
| [`lan_radar.py`](lan_radar.py) | Packet capture, discovery, notifications and web interface |
| [`database.py`](database.py) | SQLite persistence and in-memory device inventory |
| [`keycloak_auth.py`](keycloak_auth.py) | Optional Keycloak authentication |
| [`home_assistant_ingress.py`](home_assistant_ingress.py) | Home Assistant Supervisor ingress integration |
| [`Dockerfile`](Dockerfile) | Container build and runtime |
| [`pyproject.toml`](pyproject.toml) / [`uv.lock`](uv.lock) | Python requirements and locked dependency versions |

## License

GNU General Public License, version 3. See [LICENSE](LICENSE).
