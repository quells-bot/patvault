package gitconfig

import (
	"errors"
	"strings"
	"testing"
)

type fakeRunner struct {
	vals map[string]string
	sets []string // recorded "key value" for each Run
}

func (f *fakeRunner) Output(args ...string) ([]byte, error) {
	// expect: config --get <key>
	key := args[len(args)-1]
	if v, ok := f.vals[key]; ok {
		return []byte(v), nil
	}
	return nil, errors.New("exit status 1")
}

func (f *fakeRunner) Run(args ...string) error {
	// expect: config --global <key> <value>
	f.sets = append(f.sets, args[len(args)-2]+" "+args[len(args)-1])
	return nil
}

func TestEnsureUseHTTPPathAlreadySet(t *testing.T) {
	r := &fakeRunner{vals: map[string]string{"credential.https://github.com.useHttpPath": "true"}}
	if err := EnsureUseHTTPPath("github.com", r); err != nil {
		t.Fatal(err)
	}
	if len(r.sets) != 0 {
		t.Fatalf("unexpected set calls: %v", r.sets)
	}
}

func TestEnsureUseHTTPPathSetsWhenMissing(t *testing.T) {
	r := &fakeRunner{vals: map[string]string{}}
	if err := EnsureUseHTTPPath("github.com", r); err != nil {
		t.Fatal(err)
	}
	if len(r.sets) != 1 {
		t.Fatalf("want 1 set call, got %v", r.sets)
	}
	if !strings.Contains(r.sets[0], "credential.https://github.com.useHttpPath true") {
		t.Errorf("set call = %q", r.sets[0])
	}
}

func TestEnsureUseHTTPPathOverwritesFalse(t *testing.T) {
	r := &fakeRunner{vals: map[string]string{"credential.https://github.com.useHttpPath": "false"}}
	if err := EnsureUseHTTPPath("github.com", r); err != nil {
		t.Fatal(err)
	}
	if len(r.sets) != 1 {
		t.Fatalf("want 1 set call to overwrite false, got %v", r.sets)
	}
}
