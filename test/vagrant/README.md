# GSSAPI functional test environment (Vagrant)

Two VirtualBox VMs reproducing the docker-compose dev environment, but with
real Kerberos/GSSAPI authentication:

| VM     | IP            | Role                                                        |
|--------|---------------|-------------------------------------------------------------|
| `ldap` | 192.168.56.10 | Samba AD DC, realm `BRIDOULOU.FR`, strong auth required     |
| `pg`   | 192.168.56.11 | PostgreSQL + ldap2pg + krb5 client + native `ldapsearch`    |

The Samba DC is provisioned with `ldap server require strong auth = yes`,
which is what produces `SASL:[GSSAPI]: Sign or Seal are required` when a
client authenticates with GSSAPI but negotiates no security layer.

## Usage

```sh
# 1. Build the linux binary (Docker is only used for compilation)
docker run --rm -v "$PWD/../..:/src" -w /src \
  -e GOOS=linux -e GOARCH=amd64 -e CGO_ENABLED=0 \
  golang:1.25 go build -o test/vagrant/.build/ldap2pg .

# 2. Bring up the VMs (ldap first: pg does not depend on it for provisioning,
#    but the test does)
vagrant up ldap
vagrant up pg

# 3. Run the functional test suite
vagrant ssh pg -c run-gssapi-test
```

To redeploy a freshly built binary without reprovisioning:

```sh
vagrant upload .build/ldap2pg /tmp/ldap2pg.bin pg
vagrant ssh pg -c 'sudo install -m 755 /tmp/ldap2pg.bin /usr/local/bin/ldap2pg'
```

## What the test covers

- Pure-Go GSSAPI authentication (`SASL_MECH=GSSAPI`, gokrb5 via the vendored
  go-ldap gssapi client) negotiating the SASL *integrity* security layer
  (sign, SSF 1) required by the server; all post-bind LDAP traffic is
  wrapped per RFC 4752/4121.
- Reproduction of the `Strong Auth Required` error with `-O maxssf=0`,
  demonstrating the root cause (GSSAPI without a security layer).
- Multi-buffer SASL reads (`probe-wide.yml`: one search returning the whole
  domain, ~200 entries) and diagnostics (`diag.sh`).
- The nominal sample config (`ldap2pg.yml`): role creation, memberships,
  parents, blacklist, role drop, privileges, idempotence (`--check`).
- LDIF parsing edge cases (`ldap2pg-edge.yml`): DNs longer than the LDIF
  76-column wrap (folded plain and folded base64 values), UTF-8 names,
  per-member sub-searches using the member DN as search base.
- Clean failure without a Kerberos ticket.
