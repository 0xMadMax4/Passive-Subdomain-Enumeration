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
	outDir := flag.String("o", "recon_out", "output directory")
	flag.Parse()

	if *domain == "" {
		fmt.Println("Usage: go run . -d <domain> [-o output_dir]")
		os.Exit(1)
	}

	// load .env if present (GITHUB_TOKEN, GITLAB_TOKEN, PDCP_API_KEY, etc.)
	if err := godotenv.Load(); err != nil {
		warn(".env not found or unreadable — relying on already-exported env vars")
	}

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		fatal("could not create output dir: %v", err)
	}

	tools := buildToolList(*domain, *outDir)

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
	ok("DONE. %d unique subdomains written to:", count)
	ok("  %s", finalFile)
	ok("===================================================")
}

// ---------- tool definitions ----------

func buildToolList(domain, outDir string) []tool {
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
					"-em", "crt_db",
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
