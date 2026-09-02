# ArgusX

A fast, multithreaded TCP port scanner written in C++. Point it at a host, a
hostname, or a whole CIDR block and it'll chew through the port list with as
many threads as you throw at it, grab banners if you want them, and print a
clean colored summary when it's done.

No dependencies outside the standard library and your OS's socket API.

```
                :::     :::::::::   ::::::::  :::    :::  ::::::::          :::    :::
             :+: :+:   :+:    :+: :+:    :+: :+:    :+: :+:    :+:         :+:    :+:
           +:+   +:+  +:+    +:+ +:+        +:+    +:+ +:+                 +:+  +:+
         +#++:++#++: +#++:++#:  :#:        +#+    +:+ +#++:++#++           +#++:+
        +#+     +#+ +#+    +#+ +#+  ####         +#+        +#+          +#+  +#+
       #+#     #+# #+#    #+# #+#    #+  #+#    #+# #+#    #+#         #+#    #+#
      ###     ### ###    ###  ########   ########   ########          ###    ###
```

## What it does

- TCP connect scanning with a configurable per-port timeout
- Port ranges, lists, and combos: `80`, `1-1000`, `22,80,443`, `22,80,1000-2000`
- Single host, hostname, or CIDR block (`192.168.1.0/24`) as the target
- No target given at all? It auto-detects your local subnet and scans that
- Optional banner grabbing on open ports
- Basic service name guessing off a small table of well-known ports
- Two-level threading: N threads scanning hosts in parallel, each with its
  own pool of port-scanning threads
- Windows and Linux, same codebase, platform-specific backends swapped in
  via `#ifdef`


## Usage

```
argusX [host] -p <ports> [options]
```

If `[host]` is left out, ArgusX auto-detects your local subnet and scans
every host on it.

**Host formats:**

| Format              | Meaning                          |
|---------------------|-----------------------------------|
| `192.168.1.10`       | single host / IP                 |
| `example.com`        | hostname                         |
| `192.168.1.0/24`     | CIDR block (every usable host)   |

**Port formats:**

| Format          | Meaning        |
|------------------|----------------|
| `-p 80`          | single port    |
| `-p 1-1000`      | range          |
| `-p 22,80,443`   | list           |

**Options:**

| Flag             | Default | Description                          |
|------------------|---------|---------------------------------------|
| `-t <ms>`        | 400     | timeout per port, in milliseconds     |
| `--threads <n>`  | 500     | port-scanning threads                 |
| `--hosts <n>`    | 10      | parallel host threads (CIDR scans)    |
| `--banner`       | off     | grab service banners on open ports    |

**Examples:**

```bash
argusX 192.168.1.1 -p 1-1000
argusX vigil -p 22,80,443 --banner
argusX 10.0.0.0/24 -p 22,80,443
argusX -p 1-1000              # no host -> auto-detect local subnet
```

When scanning a CIDR block, the total thread budget (`--threads`) gets
split across the number of hosts actually being worked on at once
(`--hosts`), so a scan of a /24 with the defaults isn't going to fire 500
threads at every single host simultaneously — it divides it up sensibly.

## How it's put together

| File               | What's in it                                                  |
|--------------------|------------------------------------------------------------------|
| `ArgusX.cpp`       | argument parsing, host-queue orchestration, entry point         |
| `scanner.hpp`      | `Scanner` class and shared types (`ScanConfig`, `PortResult`)    |
| `scanner.cpp`      | POSIX backend — raw sockets, non-blocking connect + `select`     |
| `scanner_win.cpp`  | Winsock backend — same logic, Windows APIs                       |
| `common.cpp`       | port-string parsing, CIDR-to-host-list expansion                |
| `UI.hpp`           | terminal output — the animated rainbow banner, hit table, usage  |

Both scanner backends live in the same source tree and get gated by
`#ifdef _WIN32` / `#ifndef _WIN32`, so only one of them actually compiles
into the binary on a given platform, regardless of which build system
you're using.



## License

This project is licensed under the MIT License. The full license text is included in the separate LICENSE file in this repository.

```
─────────────────────────────────────
     ◉ ◉ ◉    made by snadderad
         github.com/snadderad
─────────────────────────────────────
```
