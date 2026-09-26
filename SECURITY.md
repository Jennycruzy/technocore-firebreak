# Security policy

Please report a suspected Firebreak vulnerability privately through GitHub's **Report a
vulnerability** form for this repository. Do not include exploit details in a public issue.

Useful reports include a minimal reproducer, the exact Firebreak commit, operating system, Python
version, and the expected versus observed capability decision. Never submit real private keys,
credentials, tokens, or hostile content taken from a live room; use synthetic local fixtures.

Firebreak 0.1.x is the supported release line. The portable adapter runner is explicitly not an OS
sandbox. A report that an already-malicious locally executed adapter can access its host is therefore
not, by itself, a boundary escape. The locked-down container configuration is the stronger boundary;
a demonstrated escape from its documented restrictions is in scope.
