# Evaluation Limitations

* Synthetic and authored datasets only; no study on real public repositories was run.
* No false-positive/false-negative rate against real vulnerability data (OSV was not reachable
  during development).
* Single machine, single run environment; performance numbers are indicative.
* Memory is peak RSS of a whole child process, including the interpreter (about 37 MiB baseline).
* Sigstore verification, the HTTP layer, PostgreSQL and the dashboard are not covered by the
  evaluation (see `docs/security/limitations.md`).
