# Third-Party Notices

This file lists the third-party open-source components used by the
SDMX Blockchain Validator, together with their upstream source,
SPDX license identifier and copyright. All listed components are
made available under their existing licenses. Full license texts are
distributed with each component via its respective package
distribution channel (PyPI, container registry, OS package).

This file is the human-readable companion to the machine-readable
Software Bill of Materials (`sbom.json`, CycloneDX format).

## How this list is generated

Python dependencies are enumerated from:

- [app/requirements.txt](app/requirements.txt) — backend
- [app/frontend-requirements.txt](app/frontend-requirements.txt) — frontend

Container runtime dependencies are enumerated from
[docker-compose.yml](docker-compose.yml).

Before each release, regenerate this file with:

```bash
pip install pip-licenses cyclonedx-bom
pip-licenses --format=markdown --with-urls --with-license-file --with-notice-file \
  --packages $(cat app/requirements.txt app/frontend-requirements.txt | sed 's/[<>=!~].*//' | sort -u)
cyclonedx-py requirements app/requirements.txt -o sbom-backend.json
cyclonedx-py requirements app/frontend-requirements.txt -o sbom-frontend.json
```

Container images should be scanned with `syft <image> -o cyclonedx-json`
and the result merged into `sbom.json`.

## Python dependencies (dynamically linked, not embedded)

### Backend ([app/requirements.txt](app/requirements.txt))

| Component | SPDX License | Upstream |
|---|---|---|
| fastapi | MIT | https://github.com/fastapi/fastapi |
| uvicorn[standard] | BSD-3-Clause | https://github.com/encode/uvicorn |
| python-dotenv | BSD-3-Clause | https://github.com/theskumar/python-dotenv |
| xrpl-py | ISC | https://github.com/XRPLF/xrpl-py |
| python-multipart | Apache-2.0 | https://github.com/Kludex/python-multipart |
| lxml | BSD-3-Clause | https://github.com/lxml/lxml |
| httpx | BSD-3-Clause | https://github.com/encode/httpx |
| requests | Apache-2.0 | https://github.com/psf/requests |
| python-jose[cryptography] | MIT | https://github.com/mpdavis/python-jose |

### Frontend ([app/frontend-requirements.txt](app/frontend-requirements.txt))

| Component | SPDX License | Upstream |
|---|---|---|
| streamlit | Apache-2.0 | https://github.com/streamlit/streamlit |
| requests | Apache-2.0 | https://github.com/psf/requests |
| python-dotenv | BSD-3-Clause | https://github.com/theskumar/python-dotenv |

### Transitive dependencies (non-exhaustive — see `sbom.json`)

The transitive closure of the above packages includes, among others:
starlette (BSD-3-Clause), pydantic (MIT), anyio (MIT), sniffio (MIT /
Apache-2.0), h11 (MIT), httpcore (BSD-3-Clause), idna (BSD-3-Clause),
certifi (MPL-2.0 — included as an unmodified data file), charset-normalizer
(MIT), urllib3 (MIT), click (BSD-3-Clause), ecdsa (MIT), pyasn1
(BSD-2-Clause), rsa (Apache-2.0), cryptography (Apache-2.0 OR BSD-3-Clause),
typing-extensions (PSF-2.0), websockets (BSD-3-Clause), watchfiles (MIT),
httptools (MIT), uvloop (MIT OR Apache-2.0), tornado (Apache-2.0),
altair (BSD-3-Clause), pandas (BSD-3-Clause), numpy (BSD-3-Clause),
pillow (HPND), protobuf (BSD-3-Clause), pyarrow (Apache-2.0),
toml (MIT), tornado (Apache-2.0), GitPython (BSD-3-Clause).

The authoritative, exhaustive list — including resolved versions and
full license texts — is produced in `sbom.json` at build time.

## Container runtime dependencies (not embedded; pulled at deploy time)

| Image | SPDX License | Upstream |
|---|---|---|
| python:3.11-slim | PSF-2.0 (Python) + Debian package licenses | https://github.com/docker-library/python |
| quay.io/keycloak/keycloak | Apache-2.0 | https://github.com/keycloak/keycloak |
| postgres | PostgreSQL License (BSD-style) | https://github.com/docker-library/postgres |

These images are not embedded in this repository; they are pulled from
their respective registries by Docker Compose at deploy time. Each image
carries its own license metadata and `LICENSE` / `NOTICE` files inside
the image filesystem.

## License compatibility statement

All licenses listed above belong to the permissive family
(MIT / BSD / ISC / Apache-2.0 / PostgreSQL / PSF / MPL-2.0 / HPND).
They are mutually compatible and compatible with the outbound license
of this software (Apache-2.0). No copyleft (GPL / LGPL / EPL)
components are embedded or linked.

## Disclaimer

All third-party open-source components are made available under their
existing license.
