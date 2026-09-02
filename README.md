# Passive Subdomain Enumeration

A Go automation script that runs multiple passive subdomain enumeration sources against a target domain, then merges and deduplicates the results into a single clean list.

## Tools used

| Tool | Source type |
|---|---|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Multi-source passive API aggregator |
| [Findomain](https://github.com/Findomain/Findomain) | Certificate transparency + multi-API |
| [chaos-client](https://github.com/projectdiscovery/chaos-client) | ProjectDiscovery's curated dataset |
| [bbot](https://github.com/blacklanternsecurity/bbot) | Recursive OSINT framework (passive-only preset) |
| [github-subdomains](https://github.com/gwen001/github-subdomains) | GitHub code search |
| [gitlab-subdomains](https://github.com/gwen001/gitlab-subdomains) | GitLab code search |

All tools are run in **passive-only** mode — no DNS bruteforcing, no direct requests to the target's infrastructure.

## Requirements

- Go 1.21+
- The six tools above installed and available in your `$PATH`
- API keys for `chaos`, `github-subdomains`, and `gitlab-subdomains` (see below)

Any tool not found in `$PATH` is skipped automatically with a warning — the script does not stop.

## Installation

1. Clone the repo:
   ```bash
   git clone https://github.com/<your-username>/<your-repo>.git
   cd <your-repo>
   ```

2. Install dependencies:
   ```bash
   go mod tidy
   ```

3. Set up your API keys:
   ```bash
   cp .env.example .env
   ```
   Then edit `.env` with your own values:
   ```env
   GITHUB_TOKEN=token1,token2,token3
   GITLAB_TOKEN=your_gitlab_token
   PDCP_API_KEY=your_chaos_key
   ```

   - `GITHUB_TOKEN` / `GITLAB_TOKEN` — accept a single token or a comma-separated list (multiple tokens help avoid rate limits)
   - `PDCP_API_KEY` — get this from [cloud.projectdiscovery.io](https://cloud.projectdiscovery.io) if you're registered as a security researcher

   `subfinder`, `Findomain`, and `bbot` read their own API keys from their own config files, not from `.env`:
   - `subfinder`: `~/.config/subfinder/provider-config.yaml`
   - `Findomain`: `findomain_<source>_token` environment variables, or a `findomain.toml` config file
   - `bbot`: `~/.config/bbot/secrets.yml`

## Usage

```bash
go run . -d example.com
```

Optional flags:

```bash
go run . -d example.com -o my_output_dir
```

| Flag | Description | Default |
|---|---|---|
| `-d` | Target root domain (required) | — |
| `-o` | Output directory | `recon_out` |

Or build a binary and run it directly:

```bash
go build -o subdomain_enum .
./subdomain_enum -d example.com
```

## Output

Each tool writes its raw results as `<tool>_<target>.txt` inside the output directory (e.g. `subfinder_example.com.txt`, `github_example.com.txt`).

`bbot` writes to its own nested scan folder by default; the script automatically copies its `subdomains.txt` result out to `bbot_<target>.txt` so every tool follows the same naming convention.

At the end, everything is merged, lowercased, deduplicated, and filtered to only include real subdomains of the target into:

```
<output_dir>/<target>_all_subdomains.txt
```

## Notes

- This script is passive-only by design. It performs no active DNS resolution, bruteforcing, or requests to the target.
- Results depend heavily on which API keys you've configured — tools without keys will still run but return fewer results.
- Always confirm a discovered subdomain is in-scope before testing it against any bug bounty program.
# Passive-Subdomain-Enumeration
