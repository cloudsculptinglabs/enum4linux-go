# enum4linux-go

SMB / Active Directory enumeration for Windows and Samba hosts. A modern Go
rewrite of [CiscoCXSecurity/enum4linux](https://github.com/CiscoCXSecurity/enum4linux)
(Perl).

The original shells out to `smbclient`, `rpcclient`, `net`, and `nmblookup`.
This rewrite does SMB session setup and share enumeration **natively** (via
`go-smb2`) — a single static binary, concurrent, with no Samba install needed
for the SMB checks. User/group/password-policy enumeration runs over MS-RPC.

> **Scope & ethics.** For authorized assessment of hosts you own or have
> written permission to test. Enumeration touches other people's systems —
> only point it where you're allowed to.

## Status

Early scaffold. Native SMB session + share enumeration and read-probing work
today. RPC user/group/policy enumeration currently drives `rpcclient` when it's
installed; native SAMR/LSA is the main roadmap item.

## Build

```sh
go build -o enum4linux-go .
```

## Usage

```sh
enum4linux-go 10.0.0.5                 # null-session share enum (default)
enum4linux-go -a 10.0.0.5              # all checks
enum4linux-go -S -u alice -p pass dc01 # shares as a named user
enum4linux-go -U -G -P dc01            # users, groups, password policy (RPC)
enum4linux-go -json 10.0.0.5           # machine-readable output
```

Flags: `-u` user (empty = null session), `-p` password, `-w` workgroup,
`-S` shares, `-U` users, `-G` groups, `-P` password policy, `-a` all,
`-t` timeout seconds, `-json`.

## License

GPL-3.0-or-later, matching the original enum4linux. See [`LICENSE`](./LICENSE).

## Roadmap

- [ ] Native SAMR/LSA (users, groups, RID cycling) — drop the rpcclient dependency
- [ ] NetBIOS name / OS fingerprint via native queries
- [ ] Concurrent multi-host scanning from a target file
- [ ] Session-key / signing detection and share ACL detail
