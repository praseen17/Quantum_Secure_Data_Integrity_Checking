# Q-SAFE deployment guide

## Deployment scope

The supported deployment is a single-user local demonstration on an Ubuntu
host. The browser service binds only to `127.0.0.1`; it has no accounts,
external TLS, tenant separation, managed key custody, encryption at rest, or
remote cloud storage integration. Do not expose it directly to the internet.

## Run interactively

Build the project using [BUILD_GUIDE.md](BUILD_GUIDE.md), then run:

```sh
scripts/run_interface.sh --port 8765 \
  --data-dir "$HOME/.local/share/qsafe-ui"
```

Open <http://127.0.0.1:8765>. Stop with **Ctrl+C**. Data remains in the
specified directory after the server exits. Back up important originals
separately; Q-SAFE is a research prototype and not a backup product.

## Optional systemd user service

The repository includes `deploy/qsafe-interface.service` for starting the
interface after login. It expects the checkout at
`$HOME/projects/Q-SAFE`; edit `WorkingDirectory` and `ExecStart` if yours is
elsewhere. After building:

```sh
mkdir -p ~/.config/systemd/user
cp deploy/qsafe-interface.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now qsafe-interface.service
systemctl --user status qsafe-interface.service
```

Open <http://127.0.0.1:8765>. View logs with
`journalctl --user -u qsafe-interface.service -f`. Stop it with
`systemctl --user disable --now qsafe-interface.service`.

The service's persistent workspace is `~/.local/share/qsafe-ui`, protected by
owner-only permissions on Linux. It runs as the logged-in user and does not
need elevated privileges after build dependencies are installed.

## Remote private demonstration

For a private demo host, leave the service bound to loopback and use an SSH
tunnel from the browser workstation:

```sh
ssh -L 8765:127.0.0.1:8765 username@demo-host
```

Then browse to <http://127.0.0.1:8765> on the workstation. Do not change the
server bind address to `0.0.0.0` or place it behind a public endpoint without
adding authentication, TLS, request limits, tenant isolation, protected key
management, encryption at rest, monitoring, and a security review.

## Open it from another device on your home network

`127.0.0.1` always refers to the device running the browser. The Q-SAFE server
is deliberately limited to loopback and has no user login, so another device
cannot connect directly to that address. Keep Q-SAFE bound to loopback and use
an SSH tunnel through the Windows host instead. WSL2 forwards Linux loopback
services to Windows localhost; Windows OpenSSH can then forward a private
device connection to that localhost port.

On the Windows host, install **OpenSSH Server** from **Settings → System →
Optional features → Add an optional feature** if it is not already installed.
In an Administrator PowerShell window, start the service:

```powershell
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
```

Keep the Windows firewall rule for SSH limited to the **Private** network and
your local subnet. Microsoft documents installation and the SSH firewall rule
in its [OpenSSH Server guide](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse).

Start Q-SAFE in WSL with `scripts/run_interface.sh`. On the other device, run
this in a terminal, replacing the placeholders with your Windows account name
and Windows machine's local IPv4 address:

```sh
ssh -N -L 8765:127.0.0.1:8765 WindowsUser@WINDOWS-LAN-IP
```

Leave that terminal open, then open <http://127.0.0.1:8765> on the other
device. The browser connects through the encrypted SSH tunnel while Q-SAFE
continues to listen only on loopback. In WSL2's default NAT mode, Windows can
reach a Linux loopback service through `localhost`; LAN access otherwise
requires a service to accept LAN traffic, which Q-SAFE intentionally does not
do. See Microsoft's [WSL networking guide](https://learn.microsoft.com/en-us/windows/wsl/networking).

## Data lifecycle and removal

Uploaded data is encoded into local data/parity shards and proof metadata.
The stored workspace survives a restart. To remove a test session, stop the
service and delete that session directory under the configured data root.
Check the directory and make a separate backup before deleting anything.
