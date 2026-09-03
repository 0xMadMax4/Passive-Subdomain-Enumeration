// Passive Subdomain Enumeration Automation
//
// Runs: subfinder, Findomain, chaos-client, bbot (passive-only), github-subdomains,
// gitlab-subdomains — then merges + dedupes everything into one final clean file.
//
// Output naming convention: <toolname>_<target>.txt
//
// Usage:
//   go run . -d feverup.com
//
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/joho/godotenv"
)

// ---------- config ----------

type tool struct {
	name    string   // used in output filename: <name>_<target>.txt
	bin     string   // binary to check exists in $PATH
	build   func(target, outFile string) []string // builds the command args
	envKeys []string // env vars this tool needs (just for a friendly warning if missing)
}

func main() {
	domain := flag.String("d", "", "target root domain (required)")
	outDir := flag.String("o", "recon_out", "output directory (relative to current directory, or absolute)")
	envFile := flag.String("env", "", "path to .env file (default: looks in current dir, then next to the binary)")
	flag.Parse()

	if *domain == "" {
		fmt.Println("Usage: subdomain_enum -d <domain> [-o output_dir] [-env /path/to/.env]")
		os.Exit(1)
	}

	loadEnv(*envFile)

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		fatal("could not create output dir: %v", err)
	}

	tools := buildToolList(*outDir)

	info("Target: %s", *domain)
	info("Output directory: %s", *outDir)
	fmt.Println()

	var producedFiles []string

	for _, t := range tools {
		info("==> Running %s", t.name)

		if _, err := exec.LookPath(t.bin); err != nil {
			warn("%s not found in $PATH — skipping", t.bin)
			continue
		}

		checkEnvKeys(t)

		outFile := filepath.Join(*outDir, fmt.Sprintf("%s_%s.txt", t.name, *domain))
		args := t.build(*domain, outFile)

		cmd := exec.Command(t.bin, args...)
		cmd.Stdin = os.Stdin // let interactive commands (e.g. bbot's "kill <module>") reach the subprocess
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			warn("%s exited with error: %v (continuing anyway)", t.name, err)
		}

		// bbot writes to a nested folder — flatten it to match the naming convention
		if t.name == "bbot" {
			flattenBBOTOutput(*outDir, *domain)
		}

		if fileExistsNonEmpty(outFile) {
			ok("%s done -> %s", t.name, outFile)
			producedFiles = append(producedFiles, outFile)
		} else {
			warn("%s produced no output file at %s", t.name, outFile)
		}
		fmt.Println()
	}

	finalFile := filepath.Join(*outDir, fmt.Sprintf("%s_all_subdomains.txt", *domain))
	count, err := mergeDedupe(producedFiles, finalFile, *domain)
	if err != nil {
		fatal("merge failed: %v", err)
	}

	fmt.Println()
	ok("===================================================")
	ok("Passive enumeration done. %d unique subdomains written to:", count)
	ok("  %s", finalFile)
	ok("===================================================")
	fmt.Println()

	httpxFile := filepath.Join(*outDir, fmt.Sprintf("httpx_%s.json", *domain))
	runHttpx(finalFile, httpxFile)

	liveFile := filepath.Join(*outDir, fmt.Sprintf("live_%s.txt", *domain))
	liveCount, err := extractLiveSubdomains(httpxFile, liveFile)
	if err != nil {
		warn("could not extract live subdomains from httpx output: %v", err)
	}

	fmt.Println()
	ok("===================================================")
	ok("ALL DONE.")
	ok("  Subdomains (passive)   : %s", finalFile)
	ok("  httpx raw output       : %s", httpxFile)
	ok("  Live subdomains (%3d)  : %s", liveCount, liveFile)
	ok("===================================================")
}

// ---------- extract live subdomains from httpx JSON ----------
//
// httpx -json writes one JSON object per line. Each object's "input" field
// is the exact hostname that was probed (no scheme, no path) — this pulls
// just that field out into a plain one-per-line list of hosts that are
// confirmed alive.
type httpxResult struct {
	Input string `json:"input"`
}

func extractLiveSubdomains(jsonFile, outFile string) (int, error) {
	if !fileExistsNonEmpty(jsonFile) {
		return 0, nil // httpx didn't run or produced nothing — nothing to extract
	}

	in, err := os.Open(jsonFile)
	if err != nil {
		return 0, err
	}
	defer in.Close()

	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // httpx lines can be long (redirect URLs, etc.)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var r httpxResult
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue // skip malformed lines instead of failing the whole run
		}
		if r.Input != "" {
			seen[strings.ToLower(r.Input)] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}

	out, err := os.Create(outFile)
	if err != nil {
		return 0, err
	}
	defer out.Close()

	writer := bufio.NewWriter(out)
	defer writer.Flush()
	for s := range seen {
		fmt.Fprintln(writer, s)
	}

	return len(seen), nil
}

// ---------- httpx (live probing) ----------
//
// Takes the final deduped subdomain list and probes each host for status
// code, title, tech stack, server, redirect location, content-length, and
// resolved IP — written as JSON lines for easy parsing later.
func runHttpx(inputFile, outputFile string) {
	if _, err := exec.LookPath("httpx"); err != nil {
		warn("httpx not found in $PATH — skipping live probing")
		return
	}

	if !fileExistsNonEmpty(inputFile) {
		warn("no subdomains to probe (input file empty) — skipping httpx")
		return
	}

	info("==> Running httpx")

	args := []string{
		"-l", inputFile,
		"-silent",
		"-sc",
		"-title",
		"-td",
		"-server",
		"-location",
		"-cl",
		"-ip",
		"-json",
		"-o", outputFile,
	}

	cmd := exec.Command("httpx", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		warn("httpx exited with error: %v (continuing anyway)", err)
	}

	if fileExistsNonEmpty(outputFile) {
		ok("httpx done -> %s", outputFile)
	} else {
		warn("httpx produced no output at %s", outputFile)
	}
}

func loadEnv(explicitPath string) {
	// 1. explicit -env flag always wins
	if explicitPath != "" {
		if err := godotenv.Load(explicitPath); err != nil {
			warn("could not load .env from %s: %v", explicitPath, err)
		} else {
			info("Loaded API keys from %s", explicitPath)
		}
		return
	}

	// 2. .env in the current working directory (per-project overrides)
	if err := godotenv.Load(); err == nil {
		info("Loaded API keys from ./.env")
		return
	}

	// 3. global fallback — works no matter which directory you run the tool from
	if home, err := os.UserHomeDir(); err == nil {
		globalEnv := filepath.Join(home, ".config", "subdomain-enum", ".env")
		if err := godotenv.Load(globalEnv); err == nil {
			info("Loaded API keys from %s", globalEnv)
			return
		}
	}

	warn("no .env found (checked ./.env and ~/.config/subdomain-enum/.env) — relying on already-exported env vars")
}

// ---------- tool definitions ----------

func buildToolList(outDir string) []tool {
	return []tool{
		{
			name: "subfinder",
			bin:  "subfinder",
			build: func(target, outFile string) []string {
				return []string{"-d", target, "-all", "-recursive", "-rl", "20", "-o", outFile}
			},
		},
		{
			name: "findomain",
			bin:  "findomain",
			build: func(target, outFile string) []string {
				return []string{"-t", target, "-u", outFile}
			},
		},
		{
			name:    "chaos",
			bin:     "chaos",
			envKeys: []string{"PDCP_API_KEY"},
			build: func(target, outFile string) []string {
				return []string{"-d", target, "-silent", "-o", outFile}
			},
		},
		{
			name: "bbot",
			bin:  "bbot",
			build: func(target, outFile string) []string {
				// -o here is a DIRECTORY, not a file — handled specially, see flattenBBOTOutput
				bbotOutDir := filepath.Join(outDir, "bbot_"+target)
				scanName := "scan_" + sanitize(target)
				return []string{
					"-t", target,
					"-p", "subdomain-enum",
					"-rf", "passive",
					"-em", "crt_db,wayback,asn",
					"-n", scanName,
					"-o", bbotOutDir,
					"-y",
				}
			},
		},
		{
			name:    "github",
			bin:     "github-subdomains",
			envKeys: []string{"GITHUB_TOKEN"},
			build: func(target, outFile string) []string {
				return []string{"-d", target, "-e", "-o", outFile}
			},
		},
		{
			name:    "gitlab",
			bin:     "gitlab-subdomains",
			envKeys: []string{"GITLAB_TOKEN"},
			build: func(target, outFile string) []string {
				return []string{"-d", target, "-e", "-o", outFile}
			},
		},
	}
}

// ---------- bbot output flattening ----------
//
// bbot writes to: <outDir>/bbot_<domain>/scan_<domain>/subdomains.txt
// We copy that into: <outDir>/bbot_<domain>.txt  (same convention as every other tool)
func flattenBBOTOutput(outDir, domain string) {
	bbotOutDir := filepath.Join(outDir, "bbot_"+domain)
	scanName := "scan_" + sanitize(domain)
	src := filepath.Join(bbotOutDir, scanName, "subdomains.txt")
	dst := filepath.Join(outDir, fmt.Sprintf("bbot_%s.txt", domain))

	data, err := os.ReadFile(src)
	if err != nil {
		warn("could not read bbot subdomains.txt at %s: %v", src, err)
		return
	}
	if err := os.WriteFile(dst, data, 0644); err != nil {
		warn("could not write flattened bbot output: %v", err)
	}
}

// ---------- merge + dedupe ----------

func mergeDedupe(files []string, finalFile, domain string) (int, error) {
	seen := make(map[string]struct{})
	suffixRe := regexp.MustCompile(`(^|\.)` + regexp.QuoteMeta(domain) + `$`)

	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			warn("could not open %s for merging: %v", f, err)
			continue
		}
		scanner := bufio.NewScanner(fh)
		for scanner.Scan() {
			line := strings.ToLower(strings.TrimSpace(scanner.Text()))
			line = strings.TrimPrefix(line, "*.")
			if line == "" {
				continue
			}
			if !suffixRe.MatchString(line) {
				continue // drop anything that isn't actually a subdomain of the target
			}
			seen[line] = struct{}{}
		}
		if err := scanner.Err(); err != nil {
			warn("error reading %s: %v", f, err)
		}
		fh.Close()
	}

	out, err := os.Create(finalFile)
	if err != nil {
		return 0, err
	}
	defer out.Close()

	writer := bufio.NewWriter(out)
	defer writer.Flush()
	for s := range seen {
		fmt.Fprintln(writer, s)
	}

	return len(seen), nil
}

// ---------- helpers ----------

func checkEnvKeys(t tool) {
	for _, k := range t.envKeys {
		if os.Getenv(k) == "" {
			warn("%s: env var %s is not set — results may be limited or the tool may fail", t.name, k)
		}
	}
}

func fileExistsNonEmpty(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fi.Size() > 0
}

func sanitize(s string) string {
	return strings.NewReplacer(".", "_", ":", "_", "/", "_").Replace(s)
}

func info(format string, a ...interface{}) { fmt.Printf("\033[1;34m[*]\033[0m "+format+"\n", a...) }
func ok(format string, a ...interface{})   { fmt.Printf("\033[1;32m[+]\033[0m "+format+"\n", a...) }
func warn(format string, a ...interface{}) { fmt.Printf("\033[1;33m[!]\033[0m "+format+"\n", a...) }
func fatal(format string, a ...interface{}) {
	fmt.Printf("\033[1;31m[-]\033[0m "+format+"\n", a...)
	os.Exit(1)
}