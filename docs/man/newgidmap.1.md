# newgidmap(1) - set the group ID mapping of a user namespace

## NAME

newgidmap - see **newuidmap**(1)

## DESCRIPTION

**newgidmap** is **newuidmap**(1) writing /proc/*pid*/gid_map against
/etc/subgid. Everything — the checks, the descriptor-bound write, the
**fd:***N* form, the exit status — is described there.

## SEE ALSO

newuidmap(1), subgid(5), user_namespaces(7)
