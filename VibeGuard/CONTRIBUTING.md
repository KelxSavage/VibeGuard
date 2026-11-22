# Contributing

1. Create a feature branch.
2. Keep website checks bounded, read-only, and within the explicit authorization model.
3. Add or update unit tests for scanner behavior and safety boundaries.
4. Run `python -m unittest discover -s tests -v` before opening a pull request.
5. Never include real credentials, private reports, customer data, or private target information in commits or fixtures. Use synthetic test values.

Pull requests should explain the finding or workflow improved, the tests added, and any new network behavior.
