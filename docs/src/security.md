# Reporting bypasses

If you found an input that defeats sieve, do not open a public PR/issue
first. See [SECURITY.md](https://github.com/Trit1967/sieve/blob/main/SECURITY.md)
for the disclosure workflow.

Every fixed bypass becomes a permanent regression test in
`crates/sieve-core/tests/regression/`. By v1.0 we expect hundreds of
these tests, each named after the issue / CVE that produced it.
