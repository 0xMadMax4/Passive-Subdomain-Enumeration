# Passive Subdomain Enumeration

A Go automation script that runs multiple passive subdomain enumeration sources against a target domain, merges and deduplicates the results, then probes the live ones with `httpx` for status codes, titles, and tech stack.

## Tools used

| Tool                                                              | Source type                                                               |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------- |
| [subfinder](https://github.com/projectdiscovery/subfinder)        | Multi-source passive API aggregator                                       |
| [Findomain](https://github.com/Findomain/Findomain)               | Certificate transparency + multi-API                                      |
| [chaos-client](https://github.com/projectdiscovery/chaos-client)  | ProjectDiscovery's curated dataset                                        |
| [bbot](https://github.com/blacklanternsecurity/bbot)              | Recursive OSINT framework (passive-only preset)                           |
| [github-subdomains](https://github.com/gwen001/github-subdomains) | GitHub code search                                                        |
| [gitlab-subdomains](https://github.com/gwen001/gitlab-subdomains) | GitLab code search                                                        |
| [httpx](https://github.com/projectdiscovery/httpx)                | Live probing of the final subdomain list (status code, title, tech stack) |

All six enumeration tools are run in **passive-only** mode — no DNS bruteforcing, no direct requests to the target's infrastructure. `httpx`, run at the very end, is the one step that does talk to the target directly (see [Notes](#notes)).

## Requirements

- Go 1.21+
- The six enumeration tools above, plus `httpx`, installed and available in your `$PATH`
- API keys for `chaos`, `github-subdomains`, and `gitlab-subdomains` (see below)

Any tool not found in `$PATH` is skipped automatically with a warning — the script does not stop.

## Installation

1. Clone the repo:

   ```bash
   git clone https://github.com/0xMadMax4/Passive-Subdomain-Enumeration.git
   cd Passive-Subdomain-Enumeration
   ```

2. Install dependencies:

   ```bash
   go mod tidy
   ```

3. Set up your API keys:

   Create a file named `.env` in the project root with the following content:

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

| Flag | Description                   | Default     |
| ---- | ----------------------------- | ----------- |
| `-d` | Target root domain (required) | —           |
| `-o` | Output directory              | `recon_out` |

Or build a binary and run it directly:

```bash
go build -o subdomain_enum .
./subdomain_enum -d example.com
```

## Running from anywhere

By default, `go run .` and `./subdomain_enum` only work from inside the project folder. To be able to call the tool from **any directory**, install it into your Go bin path instead:

```bash
go install .
```

This builds the binary and places it in `$(go env GOPATH)/bin` (usually `~/go/bin`). Make sure that directory is in your `$PATH`:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

Add that line to your `~/.bashrc` or `~/.zshrc` to make it permanent. After that, you can run the tool from anywhere:

```bash
subdomain_enum -d example.com -o ~/recon/example
```

**Note on `.env`:** the tool loads `.env` from the directory you run it _from_, not from wherever the binary lives. If you're running it outside the project folder, either:

- keep a copy of `.env` in whichever directory you're working from, or
- export the variables globally in your shell profile instead (`~/.bashrc` / `~/.zshrc`):
  ```bash
  export GITHUB_TOKEN=token1,token2,token3
  export GITLAB_TOKEN=your_gitlab_token
  export PDCP_API_KEY=your_chaos_key
  ```

## Output

Each tool writes its raw results as `<tool>_<target>.txt` inside the output directory (e.g. `subfinder_example.com.txt`, `github_example.com.txt`).

`bbot` writes to its own nested scan folder by default; the script automatically copies its `subdomains.txt` result out to `bbot_<target>.txt` so every tool follows the same naming convention.

At the end, everything is merged, lowercased, deduplicated, and filtered to only include real subdomains of the target into:

```
<output_dir>/<target>_all_subdomains.txt
```

That file is then fed directly into `httpx`:

```bash
httpx -l <target>_all_subdomains.txt -silent -sc -title -td -server -location -cl -ip -json -o httpx_<target>.json
```

producing:

```
<output_dir>/httpx_<target>.json
```

Each line is a JSON object with the live host's status code, page title, detected technologies (Wappalyzer), server header, redirect location, content length, and resolved IP — ready to filter or feed into another tool.

## Notes

- The six enumeration tools are passive-only by design — no DNS bruteforcing, no direct requests to the target. `httpx`, however, sends real HTTP requests to every discovered subdomain to check if it's alive; this is the one active step in the pipeline, run last, on purpose.
- If `httpx` isn't installed, or the merged subdomain file is empty, that step is skipped with a warning — the rest of the pipeline still completes.
- Results depend heavily on which API keys you've configured — tools without keys will still run but return fewer results.
- Always confirm a discovered subdomain is in-scope before testing it against any bug bounty program.