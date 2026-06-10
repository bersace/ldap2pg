#!/bin/bash
# LDIF folding edge cases: entries whose DN exceeds the 76-column LDIF wrap of
# ldapsearch(1), both plain ASCII (folded plain value) and UTF-8 (folded
# base64 value). Used by ldap2pg-edge.yml.
set -eux

export LANG=C.UTF-8 LC_ALL=C.UTF-8

# 62-char OU name: any DN below it exceeds 76 chars once prefixed with
# "member: " or "dn: ", forcing ldapsearch to fold the line.
LONG_OU='LDIF Folding Tests Organizational Unit With A Quite Long Name'

samba-tool ou add "OU=${LONG_OU}"

# Plain ASCII user in the long OU: folded plain member value.
samba-tool user add fold1 --random-password --userou="OU=${LONG_OU}"

# UTF-8 user in the long OU: member value is base64-encoded by ldapsearch and
# the base64 text itself gets folded.
samba-tool user add 'zoé-fold2' --random-password --userou="OU=${LONG_OU}"

samba-tool group add foldgroup
samba-tool group addmembers foldgroup 'fold1,zoé-fold2'
