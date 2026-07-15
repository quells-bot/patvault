package gitconfig

import (
	"fmt"
	"os/exec"
	"strings"
)

// Runner abstracts invoking git so callers can fake it in tests.
type Runner interface {
	Output(args ...string) ([]byte, error) // `git <args>...`, capturing stdout
	Run(args ...string) error              // `git <args>...`, discarding output
}

// GitRunner shells out to the real git binary.
type GitRunner struct{}

func (GitRunner) Output(args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	return cmd.Output()
}

func (GitRunner) Run(args ...string) error {
	cmd := exec.Command("git", args...)
	return cmd.Run()
}

// EnsureUseHTTPPath guarantees credential.https://<host>.useHttpPath is "true",
// setting it globally if missing or false. Without it git never sends the path,
// making per-repo matching impossible.
func EnsureUseHTTPPath(host string, r Runner) error {
	key := fmt.Sprintf("credential.https://%s.useHttpPath", host)
	out, err := r.Output("config", "--get", key)
	if err == nil && strings.TrimSpace(string(out)) == "true" {
		return nil
	}
	if err := r.Run("config", "--global", key, "true"); err != nil {
		return fmt.Errorf("set %s: %w", key, err)
	}
	return nil
}
