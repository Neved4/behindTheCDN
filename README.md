![Shell Script](https://img.shields.io/badge/Shell_Script-9DDE66?logo=gnubash&logoColor=000&style=for-the-badge)
[![POSIX.1%2D2017](https://img.shields.io/badge/POSIX.1&#8209;2017-6A737D?labelColor=6A737D&style=for-the-badge)][POSIX.1-2017]

# **[Draft]** `behindTheCDN.sh` - Bypass CDN/WAFs! 📍 📡

Red Team / OSINT reconnaissance tool that searches IP addresses behind
Content Delivery Networks (CDNs) and Web Application Firewalls (WAFs).

Leverages DNS resolution history, SSL certificate analysis and HTTP
response headers from VirusTotal, Censys and Shodan to determine potential
CDN/WAFs protecting a domain.

<div align="center">
  <img src="https://github.com/Neved4/behindTheCDN/assets/63655535/3a42d932-b871-4846-ba05-d96d74fb9fc9" alt="Image Description" style="width: 85%" />
  <h6>Catpuccin Mocha theme, font Menlo.</h6>
</div>

## Getting Started

### Prerequisites

> [!IMPORTANT]  
> _**The script requires API keys for the VirusTotal, Censys, and Shodan APIs.**_  
> _See: [VirusTotal API], [Censys API], [Shodan API]_.
>
> To succeed, you'll need:
> 1. The API keys.
> 2. Any shell listed in [Supported shells](#supported-shells).
> 3. The following dependencies: [`curl`], [`jq`], [`dig`], [`xmllint`].

### Online

Copy and paste the code below and press enter:
```sh
curl -fsSL https://raw.githubusercontent.com/Neved4/behindTheCDN/main/src/behindTheCDN.sh | sh -s -- --from-curl
```

### Installation

#### *Homebrew*

If you have [`brew`] installed, run:

```sh
$ brew install Neved4/homebrew-tap/behindTheCDN
```

#### *Basic Install*

```sh
$ /bin/sh -c "$(curl -fsSL https://raw.githubusercontent.com/Neved4/BehindTheCDN/HEAD/tools/install.sh)"
```

Set the APIs for VirustTotal and Censys on the [`API.conf`](conf/API.conf) file.

#### *Manual Installation*

First clone the `.git` repository:
```sh
$ git clone https://github.com/Loop-Man/BehindTheCDN
```

Then add permissions to execute:
```sh
$ chmod u+x behindTheCDN.sh
```

Finally, set the APIs for VirustTotal and Censys on the
[`API.conf`](API.conf) file.

## Usage

The following options are available:

<div align="center">
  <img src="https://github.com/Neved4/behindTheCDN/assets/63655535/c6ebea8b-f77c-4d28-9ebd-319307c5703c" alt="usage --help" style="width: 85%" />
</div>


<details>
  <summary>Usage (Offline)</summary>

```yaml
usage: behindTheCDN.sh [-ci] [-d <domain> | -f <file>] [-o <output>] ...

Options:
  -c          search by Censys API
  -d <domain> search by DNS history on a specific domain
  -f <file>   search by DNS history on every domain in the file
  -i          search by DNS history, SSL certificate, subdomains
  -o <output> save the output to a file
```

</details>

## Examples

The following option allows you to search for a particular domain:
```sh
$ ./behindTheCDN.sh -d example.com
```

Launch more queries and search by DNS history and SSL certificates:
```sh
$ ./behindTheCDN.sh -d example.com -i
```

Search using the Censys API:
```sh
$ ./behindTheCDN.sh -d example.com -c
```

Indicate a file with domains to look for a possible bypass:
```sh
$ ./behindTheCDN.sh -f domains.txt
```

Options can be combined and be used at the same time:
```sh
$ ./behindTheCDN.sh -d example.com -i -c

$ ./behindTheCDN.sh -ci -f domains.txt
```

By default `behindTheCDN.sh` writes its output to a timestamp file in the
`results/` folder.

## Performance

See: [Benchmarks](doc/Benchmark.md).

## Portability

### Supported systems

Most versions and distributions of Linux, FreeBSD, and macOS should work.
Here are the ones we've tested:

| System       | Supported |
| :----------- | :-------- |
| `macOS 14`   | ✅ Yes     |
| `FreeBSD 14` | ✅ Yes     |
| `Fedora 40`  | ✅ Yes     |
| `Debian 12`  | ✅ Yes     |
| `WSL 2`      | ✅ Yes     |

### Supported shells

|     Shell | Version       | Supported |
| --------: | :------------ | :-------- |
|  [`bash`] | `5.2.26`      | ✅ Yes     |
|  [`dash`] | `0.5.12`      | ✅ Yes     |
| [`ksh93`] | `93u+m/1.0.8` | ✅ Yes     |
|  [`mksh`] | `59c`         | ✅ Yes     |
|  [`oksh`] | `7.5`         | ✅ Yes     |
|  [`yash`] | `2.56.1`      | ✅ Yes     |
|   [`zsh`] | `5.9`         | ✅ Yes     |
|   [`osh`] | `0.20.0`      | ⚠️ No[^1]  |
|  [`posh`] | `0.14.1`      | ⚠️ No[^2]  |

[^1] and [^2] won't work with curl due to missing `-s` specified by POSIX:
-s
Read commands from the standard input.
https://pubs.opengroup.org/onlinepubs/9699919799/utilities/sh.html

## Standards

This script is compatible with [ISO 9945:2009][POSIX.1-2017], also known as
[POSIX.1-2017].[^1]

## License

This repository is licensed under the terms of the [MIT License].
   
See the [LICENSE](LICENSE) file for details.

[VirusTotal API]: https://www.virustotal.com/gui/user/username/apikey
[Censys API]:     https://www.search.censys.io/account/api
[Shodan API]:     https://developer.shodan.io/api/requirements

[POSIX.1-2017]:   https://pubs.opengroup.org/onlinepubs/9699919799/
[MIT License]:    https://opensource.org/license/mit/

[`brew`]:    https://brew.sh/
[`curl`]:    https://curl.se/
[`jq`]:      https://jqlang.github.io/jq/
[`dig`]:     https://en.wikipedia.org/wiki/Dig_(command)
[`xmllint`]: https://gitlab.gnome.org/GNOME/libxml2/-/wikis/home

[`bash`]:  https://git.savannah.gnu.org/cgit/bash.git/
[`dash`]:  https://git.kernel.org/pub/scm/utils/dash/dash.git
[`ksh93`]: https://github.com/ksh93/ksh
[`mksh`]:  https://github.com/MirBSD/mksh
[`osh`]:   https://www.oilshell.org/cross-ref.html?tag=OSH#OSH
[`oksh`]:  https://github.com/ibara/oksh
[`posh`]:  https://salsa.debian.org/clint/posh
[`yash`]:  https://github.com/magicant/yash
[`zsh`]:   https://github.com/zsh-users/zsh

[^1]: _IEEE Std 1003.1-2017: Standard for Information Technology — Portable_
      _Operating System Interface (POSIX®)_, ISO/IEC/IEEE 9945:2009/COR
      2:2017. URL: https://pubs.opengroup.org/onlinepubs/9699919799/
