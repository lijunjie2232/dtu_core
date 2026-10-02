# Purpose

there's two windows under a LAN, but do not want to expose under network, they are to auth and share files by command or gui to spedified path.

## Layout

four separate crates (four git repos):

- `dtu_core` — this repo. library only: identity, trust, the transfer protocol, discovery and the loopback REST surface (`src/api.rs`). **no daemon, no binary**: it cannot run on its own, it only runs inside a client that hosts it (`embed::host`).
- `dtu_cli` — linux-like subcommands plus a small shell; hosts the core itself (`dtu` with no arguments stays up and reads commands).
- `dtu_tui` — terminal UI; hosts the core while open.
- `dtu_gui` — native client window (egui), not a web page; hosts the core while open.

rules that follow from that:

- every app is self-contained: it starts the listener, discovery and the REST surface in its own process, and they stop when the app exits.
- one process owns a data directory (`DTU_HOME`, default `%APPDATA%\dtu`). A second app on the same directory is refused, not silently attached.
- the bundled UIs call `dtu_core` in process; identity, trust, code and invitations are read from `embed::Daemon::state`.
- third-party frontends (web page, mobile, scripts) use the REST surface on `127.0.0.1:<port+1>`, authenticated with the local key in `control.token`. There is no page in core, and no remote shutdown: the app owns its lifetime.

## the app

- an app should keep running to receive files: while it runs, its listener serves the configured root.

- the app should be able to auth every transfer (auth each time of tcp, not each file)

- the app should be able to auth and record auth log to file. (no need to log the transfer)

## auth

first, every client should init a unique id of it's self

then, it should init the private and public key of it self

the app should support temporary transfer (a code used only once to accept files ) and peranant auth but should auth to trusted device first.

### Permanent Authorization (Trusted Devices)

permanent authorization should use JWT (if accept but with expiration time) contains the public key of unique id

add trust device mehtod:

- when open "manage trusted device" tab at machine `A`, scan LAN automaticly and list unknown device (only expose the unique id) that could be added, support search, click one (support specify expires time) to send invite to `B`, contains unique id of `A` and expire time, and wait for accept or deny. if accepted:
1. `A` will receive a response of a JWT contains the unique id and expiration of `A` form `B`
2. `A` add `B` to trust device list with the JWT from `B`
3. `A` use the JwT to send a JWT contains unique id and expiration of `B`
4. `B` add `A` to trust device list with the JWT from `A`
5. `B` reponse ok to `A`
- input the ip address(optional with port) or url to invite (the same as the above)


### Temporary Transfer (One-Time Code): Use Ephemeral Pairing Tokens

- randomly generate a simple code for transfer, password is optional

- manually refresh code (not affect exists connections)

- (optional)change after each connection build, but still valid until disconnected

- **Post-Auth Trust Option:** Once the temporary transfer completes successfully, your UI/CLI can prompt: *"Do you want to trust this device permanently for future transfers?"* If confirmed, it will do invitation.

### Unlimit Mode (Dangerous)

- to accept any invite

- only one-way unlimited

- (optional) not store any device to trust device list (but auth history must still log)


## CLI

use a linux-like command system with command:

- version
- device
	- ???
		- scan
		- add
	- ??? (handle invitations)
		- accept
		- list
		- deny
- push (upload local files to overwrite remote)
- pull (fetch from remote to overwrite files locally)
- async (sync files, process conflict and main args as real command `async` under linux/windows)
- diff (compare the files/directory between remote and local)
- config

## GUI

contains:
- a native egui window (no tray icon yet, no web view)
- tabs: status, trusted devices (scan/forget/rename), invitations (accept/deny), pairing code

## TUI

same four tabs in a terminal: `1-4` switch, `s` scan, `c` new code, `a`/`d` answer an invitation, `q` quit.

## Transfer

must auth (by jwt or random code) first before transfer unless in unlimit mode

Use TCP (specifically, managed over multiple TCP streams or custom multiplexing by yourself)

1. Supporting Breakpoint Resumption (断点续传)To resume a broken transfer, you don't need a special transport layer; you just need a protocol handshake:File Size Check: Before sending, the client connects to the server and asks: "I want to send file.zip, size 100MB. What is your current local file size?"Offset Negotiation: The server replies: "I already have 40MB."Stream Seeking: The client seeks its local file pointer to byte 40,000,000 and starts streaming only the remaining 60MB over the TCP socket. The server appends these bytes to the existing partial file.2. Achieving Parallelism (多线程/多路复用传输)If you want to saturate your local network bandwidth (e.g., gigabit LAN), a single TCP stream can sometimes be bottlenecked by TCP window scaling or single-core CPU limits. You have two ways to do parallelism:Multi-Connection Chunking (Multi-part download/upload):Divide a large file into $N$ chunks (e.g., 4 chunks of 250MB).Establish 4 parallel TCP connections to the server.Send each chunk concurrently over its own socket.The server writes each chunk to its correct offset in the file using random-access file writing (std::fs::File::seek in Rust).Using QUIC (Modern Alternative):If you really want modern transport, look into QUIC (which runs over UDP). Rust has fantastic libraries for it (like quinn). QUIC provides multiple independent streams over a single UDP connection, natively avoiding TCP head-of-line blocking. However, for a simple local network tool, multiple TCP connections are much easier to implement and debug.


## Pay Attention

- should support both ipv and ipv6
- think about other details not mentioned