# Dependency Risk Monitor

Evidence-oriented dependency advisory monitoring maintained by **Rohit Dixit — Cybersecurity Researcher**.

The monitor reads declared sample dependencies, queries the public [OSV API](https://osv.dev/docs/), normalizes advisory identifiers, and preserves the last valid report during service failures. “No advisory returned” is recorded as an observation, never as proof that a component is safe.

```bash
python scripts/monitor.py --input dependencies.json --output reports/latest.json
python -m pytest -q
```

The sample manifest is illustrative and is not an inventory of a production system. See [AUTOMATION.md](AUTOMATION.md).

## Author

Rohit Dixit — Cybersecurity Researcher · [rohitdixit.dev](https://rohitdixit.dev)

## License

MIT
