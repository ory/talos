<!-- Follow-up: upload talos.svg to ory/meta:static/banners/talos.svg. -->
<h1 align="center">
  <img src="https://raw.githubusercontent.com/ory/meta/master/static/banners/talos.svg" alt="Ory Talos - API credential management for high-throughput systems">
</h1>

<h4 align="center">
  <a href="https://www.ory.com/chat">Chat</a> ·
  <a href="https://github.com/ory/talos/discussions">Discussions</a> ·
  <a href="https://www.ory.com/l/sign-up-newsletter">Newsletter</a> ·
  <a href="https://www.ory.com/docs/">Docs</a> ·
  <a href="https://console.ory.sh/">Try Ory Network</a> ·
  <a href="https://www.ory.com/jobs/">Jobs</a>
</h4>

Ory Talos is a scalable and secure API key server optimized for low-latency verification, horizontal
scaling, and predictable operations. It follows established security best-practices for API keys and
issues, verifies, revokes, and derives API keys and short-lived tokens for high-throughput systems.

---

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [What is Ory Talos?](#what-is-ory-talos)
  - [Why Ory Talos](#why-ory-talos)
- [Deployment options](#deployment-options)
  - [Use Ory Talos on the Ory Network](#use-ory-talos-on-the-ory-network)
  - [Self-host Ory Talos](#self-host-ory-talos)
- [Quickstart](#quickstart)
- [Who is using Ory Talos](#who-is-using-ory-talos)
- [Ecosystem](#ecosystem)
  - [Ory Kratos: Identity and User Infrastructure and Management](#ory-kratos-identity-and-user-infrastructure-and-management)
  - [Ory Hydra: OAuth2 & OpenID Connect Server](#ory-hydra-oauth2--openid-connect-server)
  - [Ory Oathkeeper: Identity & Access Proxy](#ory-oathkeeper-identity--access-proxy)
  - [Ory Keto: Access Control Policies as a Server](#ory-keto-access-control-policies-as-a-server)
- [Documentation](#documentation)
- [Developing Ory Talos](#developing-ory-talos)
- [Security](#security)
  - [Disclosing vulnerabilities](#disclosing-vulnerabilities)
- [Telemetry](#telemetry)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## What is Ory Talos?

Ory Talos is a server for issuing, verifying, and managing API keys. It follows
[cloud architecture best practices](https://www.ory.com/docs/ecosystem/software-architecture-philosophy)
and focuses on:

- Issuing, verifying, and revoking API keys at scale
- Importing externally-issued API keys for unified verification
- Deriving short-lived JWT and macaroon tokens from long-lived keys
- Side-car deployment for fast API key verification
- Low-latency verification with caching and eventual revocation
- Predictable operations through structured logging, metrics, and tracing

We recommend starting with the [Ory Talos documentation](https://www.ory.com/docs/talos) to learn
more about its architecture, feature set, and how it compares to other systems.

### Why Ory Talos

Ory Talos is designed to:

- Run as a single binary with three deployment modes: admin, self-service, or all-in-one
- Verify API keys against the database with caching for low latency, while derived JWT and macaroon
  tokens verify offline without a database lookup
- Separate admin and self-service surfaces so key creation, revocation, derivation, and verification
  scale and are secured independently from proof-of-possession self-revocation
- Scale horizontally with external databases (Postgres, MySQL, CockroachDB) and optional distributed
  caching
- Fit modern cloud-native environments such as Kubernetes and managed platforms
- Mint reduced-scope, short-lived tokens offline so agents, CI/CD jobs, and services don't call the
  server on every request
- Keep credential routing, hashing, and verification centralized and constant-time

## Deployment options

You can run Ory Talos in two main ways:

- As a managed service on the Ory Network
- As a self-hosted service under your own control, with or without the Ory Enterprise License

### Use Ory Talos on the Ory Network

The [Ory Network](https://www.ory.com/network) is the fastest way to use Ory Talos in production.

The Ory Network provides:

- API key issuance, verification, and derivation with low-latency global edge
- OAuth2 and OpenID Connect for single sign on, API access, and machine to machine authorization
- Identity and credential management that scales to billions of users and devices
- Registration, login, and account management flows for passkeys, biometrics, social login, SSO, and
  multi factor authentication
- Prebuilt login, registration, and account management pages and components
- Low latency permission checks based on the Zanzibar model with the Ory Permission Language
- GDPR friendly storage with data locality and compliance in mind
- Web based Ory Console and Ory CLI for administration and operations
- Cloud native APIs compatible with the open source servers
- Fair, usage based [pricing](https://www.ory.com/pricing)

Sign up for a
[free developer account](https://console.ory.sh/registration?utm_source=github&utm_medium=banner&utm_campaign=talos-readme)
to get started.

### Self-host Ory Talos

You can run Ory Talos yourself for full control over infrastructure, deployment, and customization.

The [install guide](https://www.ory.com/docs/talos/operate/install) explains how to:

- Install Ory Talos on Linux, macOS, Windows, and Docker
- Configure databases such as SQLite, PostgreSQL, MySQL, and CockroachDB
- Deploy to Kubernetes and other orchestration systems

The open source distribution runs as a single instance against an embedded SQLite database. It is a
great fit for individuals, researchers, hackers, and companies that want to experiment, prototype,
or run low-traffic workloads without service level agreements (SLAs).

If you run Ory Talos as part of a business-critical system, for example API key verification on a
hot path, you should use a commercial agreement to reduce operational and security risk. The
**[Ory Enterprise License (OEL)](https://www.ory.com/ory-enterprise-license)** layers on top of
self-hosted Ory Talos and provides:

- Multi-node deployments backed by external databases (Postgres, MySQL, CockroachDB)
- Multi-tenancy, distributed caching, rate-limit enforcement, and edge verification nodes
- Regular security releases, including CVE patches, with SLAs
- Support for advanced scaling and complex deployments
- Premium support options with response SLAs, direct access to engineers, and onboarding help
- Access to a private Docker registry with frequent, vetted enterprise builds

For guaranteed CVE fixes, current enterprise builds, advanced features, and production support, you
need a valid [Ory Enterprise License](https://www.ory.com/ory-enterprise-license) and access to the
Ory Enterprise Docker registry. To learn more, [contact the Ory team](https://www.ory.com/contact/).

## Quickstart

Install the [Ory CLI](https://www.ory.com/docs/guides/cli/installation) and use the managed Ory
Network, or run Ory Talos locally with Docker Compose.

```bash
# Install the Ory CLI if you do not have it yet:
bash <(curl https://raw.githubusercontent.com/ory/meta/master/install.sh) -b . ory
sudo mv ./ory /usr/local/bin/

# Sign in or sign up
ory auth

# Create a new project
ory create project --create-workspace "Ory Open Source" --name "GitHub Quickstart" --use-project
```

To run Ory Talos locally:

```bash
# Open source edition (SQLite, single-node)
docker-compose -f docker-compose.oss.yaml up --build
```

The API will be available at http://localhost:4420

For end-to-end walkthroughs of issuing, verifying, and revoking keys, see the
[Quickstart guide](https://www.ory.com/docs/talos/quickstart/index) and
[Issue and verify](https://www.ory.com/docs/talos/docs/integrate/issue-and-verify).

## Who is using Ory Talos

<!--BEGIN ADOPTERS-->

The Ory community stands on the shoulders of individuals, companies, and maintainers. The Ory team
thanks everyone involved - from submitting bug reports and feature requests, to contributing patches
and documentation. The Ory community counts more than 50.000 members and is growing. The Ory stack
protects 7.000.000.000+ API requests every day across thousands of companies. None of this would
have been possible without each and everyone of you!

If you would like to be featured here once Ory Talos lands on the Network, reach out to
<a href="mailto:office@ory.com">office@ory.com</a>.

Many thanks to all individual contributors

<a href="https://opencollective.com/ory" target="_blank"><img src="https://opencollective.com/ory/contributors.svg?width=890&limit=714&button=false" /></a>

<!--END ADOPTERS-->

## Ecosystem

<!--BEGIN ECOSYSTEM-->

We build Ory on several guiding principles when it comes to our architecture design:

- Minimal dependencies
- Runs everywhere
- Scales without effort
- Minimize room for human and network errors

Ory's architecture is designed to run best on a container orchestration system such as Kubernetes,
CloudFoundry, OpenShift, and similar projects. Binaries are small and available for all popular
processor types (ARM, AMD64, i386) and operating systems (FreeBSD, Linux, macOS, Windows) without
system dependencies (Java, Node, Ruby, libxml, ...).

### Ory Kratos: Identity and User Infrastructure and Management

[Ory Kratos](https://github.com/ory/kratos) is an API-first Identity and User Management system that
is built according to
[cloud architecture best practices](https://www.ory.com/docs/next/ecosystem/software-architecture-philosophy).
It implements core use cases that almost every software application needs to deal with: Self-service
Login and Registration, Multi-Factor Authentication (MFA/2FA), Account Recovery and Verification,
Profile, and Account Management.

### Ory Hydra: OAuth2 & OpenID Connect Server

[Ory Hydra](https://github.com/ory/hydra) is an OpenID Certified™ OAuth2 and OpenID Connect Provider
which easily connects to any existing identity system by writing a tiny "bridge" application. It
gives absolute control over the user interface and user experience flows.

### Ory Oathkeeper: Identity & Access Proxy

[Ory Oathkeeper](https://github.com/ory/oathkeeper) is a BeyondCorp/Zero Trust Identity & Access
Proxy (IAP) with configurable authentication, authorization, and request mutation rules for your web
services: Authenticate JWT, Access Tokens, API Keys, mTLS; Check if the contained subject is allowed
to perform the request; Encode resulting content into custom headers (`X-User-ID`), JSON Web Tokens
and more!

### Ory Keto: Access Control Policies as a Server

[Ory Keto](https://github.com/ory/keto) is a policy decision point. It uses a set of access control
policies, similar to AWS IAM Policies, in order to determine whether a subject (user, application,
service, car, ...) is authorized to perform a certain action on a resource.

<!--END ECOSYSTEM-->

## Documentation

The Ory Talos documentation lives at [www.ory.com/docs/talos](https://www.ory.com/docs/talos).

## Developing Ory Talos

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the contribution process: how to open an issue, agree
on an approach, and submit a pull request.

**Prerequisites**

- Go 1.26 or later
- Make
- Git
- Node.js 18+ (for documentation testing)

**Getting started**

```bash
# Clone the repository
git clone https://github.com/ory/talos.git
cd talos

# Install dependencies
make deps

# Build the binary
make build

# Run tests
make test

# Run full verification
make verify
```

**Testing requirements**

- Target ≥85% coverage (goal 90%).
- Use table-driven tests with `t.Run()` subtests and `t.Parallel()` where safe.
- Cover both happy and unhappy paths.
- Keep documentation examples working. Run `make docs-test` to verify them.

**Code guidelines**

Follow the engineering rules in [AGENTS.md](./AGENTS.md), including dependency injection over global
state, passing `context.Context` from the caller, structured JSON logging with `slog`, avoiding
`COUNT(*)`, `SELECT *`, and `OFFSET`, and keeping commercial code under `commercial/` behind build
tags.

## Security

Ory Talos handles credentials on the hot path: raw API keys, derived tokens, and signing keys. The
implementation uses constant-time comparisons, centralized credential routing, and per-tenant
network isolation. Read [the security model](https://www.ory.com/docs/talos/concepts/security-model)
and [security hardening guide](https://www.ory.com/docs/talos/operate/security-hardening) for the
details on cryptography, tenant isolation, and operational hardening.

### Disclosing vulnerabilities

If you think you found a security vulnerability, please refrain from posting it publicly on the
forums, the chat, or GitHub. You can find all info for responsible disclosure in our
[security.txt](https://www.ory.com/.well-known/security.txt).

## Telemetry

Our services collect summarized, anonymized data that can optionally be turned off. Click
[here](https://www.ory.com/docs/ecosystem/sqa) to learn more.

## Libraries and third-party projects

Ory Community:

- Visit
  [this document for an overview of community projects and articles](https://www.ory.com/docs/ecosystem/community)
