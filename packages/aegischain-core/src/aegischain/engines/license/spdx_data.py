"""Subset of the SPDX License List used for validation (not exhaustive).

Identifiers outside this list are reported as UNKNOWN, never guessed.
Reference: https://spdx.org/licenses/
"""

from __future__ import annotations

_IDS = """
0BSD AAL AFL-3.0 AGPL-1.0-only AGPL-1.0-or-later AGPL-3.0-only AGPL-3.0-or-later Apache-1.0 Apache-1.1
Apache-2.0 APSL-2.0 Artistic-1.0 Artistic-2.0 Beerware BlueOak-1.0.0 BSD-1-Clause BSD-2-Clause
BSD-2-Clause-Patent BSD-3-Clause BSD-3-Clause-Clear BSD-3-Clause-LBNL BSD-4-Clause BSL-1.0 BUSL-1.1
CC-BY-3.0 CC-BY-4.0 CC-BY-NC-4.0 CC-BY-ND-4.0 CC-BY-SA-3.0 CC-BY-SA-4.0 CC0-1.0 CDDL-1.0 CDDL-1.1
CECILL-2.1 CPAL-1.0 CPL-1.0 ECL-2.0 EFL-2.0 EPL-1.0 EPL-2.0 EUPL-1.1 EUPL-1.2 FSFAP GFDL-1.1-only
GFDL-1.2-only GFDL-1.3-only GFDL-1.3-or-later GPL-1.0-only GPL-1.0-or-later GPL-2.0-only GPL-2.0-or-later
GPL-3.0-only GPL-3.0-or-later HPND ICU IJG Info-ZIP ISC JSON LGPL-2.0-only LGPL-2.0-or-later
LGPL-2.1-only LGPL-2.1-or-later LGPL-3.0-only LGPL-3.0-or-later LPPL-1.3c MIT MIT-0 MIT-CMU MPL-1.0
MPL-1.1 MPL-2.0 MS-PL MS-RL MulanPSL-2.0 NCSA NPOSL-3.0 OFL-1.1 OpenSSL OSL-3.0 PostgreSQL PSF-2.0
Python-2.0 Qhull SISSL Sleepycat SSPL-1.0 Unicode-3.0 Unicode-DFS-2016 Unlicense UPL-1.0 Vim
W3C W3C-20150513 WTFPL X11 Zlib ZPL-2.1 Zlib libpng-2.0 Libpng curl BSD-3-Clause-Attribution
Python-2.0.1 CNRI-Python Ruby TCL Apache-2.0-with-LLVM-exception NIST-PD NIST-PD-fallback blessing
Artistic-1.0-Perl Zed CC-PDDC OLDAP-2.8 OGL-UK-3.0 PDDL-1.0 ODbL-1.0 AFL-2.1 AFL-2.0 BitTorrent-1.1
"""

LICENSE_IDS: dict[str, str] = {token.lower(): token for token in _IDS.split()}

_EXC = """
Classpath-exception-2.0 LLVM-exception GCC-exception-3.1 GCC-exception-2.0 Autoconf-exception-2.0
Autoconf-exception-3.0 Bison-exception-2.2 Font-exception-2.0 GPL-3.0-linking-exception
LGPL-3.0-linking-exception OpenSSL-exception Qt-GPL-exception-1.0 Linux-syscall-note
Universal-FOSS-exception-1.0 u-boot-exception-2.0 openvpn-openssl-exception
"""

EXCEPTION_IDS: dict[str, str] = {token.lower(): token for token in _EXC.split()}

# Deprecated identifiers -> current SPDX identifiers.
DEPRECATED: dict[str, str] = {
    "gpl-1.0": "GPL-1.0-only",
    "gpl-2.0": "GPL-2.0-only",
    "gpl-3.0": "GPL-3.0-only",
    "lgpl-2.0": "LGPL-2.0-only",
    "lgpl-2.1": "LGPL-2.1-only",
    "lgpl-3.0": "LGPL-3.0-only",
    "agpl-1.0": "AGPL-1.0-only",
    "agpl-3.0": "AGPL-3.0-only",
    "gfdl-1.3": "GFDL-1.3-only",
    "gpl-2.0+": "GPL-2.0-or-later",
    "gpl-3.0+": "GPL-3.0-or-later",
    "lgpl-2.1+": "LGPL-2.1-or-later",
    "lgpl-3.0+": "LGPL-3.0-or-later",
    "agpl-3.0+": "AGPL-3.0-or-later",
}

# Exact, case-insensitive free-text names seen in package metadata. Ambiguous strings
# such as "BSD" or "GPL" are intentionally absent: they stay UNKNOWN.
ALIASES: dict[str, str] = {
    "mit license": "MIT",
    "the mit license": "MIT",
    "apache 2.0": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "bsd 3-clause": "BSD-3-Clause",
    "bsd-3": "BSD-3-Clause",
    "new bsd": "BSD-3-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "isc license": "ISC",
    "mozilla public license 2.0": "MPL-2.0",
    "public domain": "Unlicense",
    "python software foundation license": "PSF-2.0",
}
