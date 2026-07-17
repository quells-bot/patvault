package relay

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/quells-bot/patvault/internal/urlparse"
)

// dqEscapable is the set of characters a backslash escapes inside double
// quotes. Anywhere else inside them a backslash is a literal backslash.
const dqEscapable = "\"\\$`"

// splitWords splits s into words the way a POSIX shell would: on unquoted
// whitespace, honoring single quotes, double quotes, and backslash escapes,
// with adjacent quoted and unquoted runs concatenating into one word.
//
// Git quotes the repository path with sq_quote, which renders an apostrophe as
// close-quote, escaped quote, reopen-quote. A real git sent this exec string,
// and it carries one path — /owner/it's.git:
//
//	git-upload-pack '/owner/it'\''s.git'
//
// That is why this splits rather than stripping the first and last quote,
// which would mangle that path into:
//
//	/owner/it'\''s.git
func splitWords(s string) ([]string, error) {
	var (
		words  []string
		cur    []rune
		inWord bool
	)
	rs := []rune(s)

	for i := 0; i < len(rs); i++ {
		switch c := rs[i]; {
		case c == ' ' || c == '\t':
			if inWord {
				words = append(words, string(cur))
				cur, inWord = nil, false
			}

		case c == '\'':
			inWord = true
			j := i + 1
			for j < len(rs) && rs[j] != '\'' {
				cur = append(cur, rs[j])
				j++
			}
			if j == len(rs) {
				return nil, errors.New("unterminated single quote")
			}
			i = j

		case c == '"':
			inWord = true
			j := i + 1
			for j < len(rs) && rs[j] != '"' {
				if rs[j] == '\\' && j+1 < len(rs) && strings.ContainsRune(dqEscapable, rs[j+1]) {
					j++
				}
				cur = append(cur, rs[j])
				j++
			}
			if j == len(rs) {
				return nil, errors.New("unterminated double quote")
			}
			i = j

		case c == '\\':
			if i+1 == len(rs) {
				return nil, errors.New("trailing backslash")
			}
			inWord = true
			i++
			cur = append(cur, rs[i])

		default:
			inWord = true
			cur = append(cur, c)
		}
	}
	if inWord {
		words = append(words, string(cur))
	}
	return words, nil
}

// The only two operations the relay serves. These are the hyphenated forms git
// the client always sends over SSH. git-upload-archive is deliberately absent:
// relaying it would expose git archive --remote.
const (
	opFetch = "git-upload-pack"  // read: clone/fetch
	opPush  = "git-receive-pack" // write: push
)

// GitHub's spelling of the two segments: a login is alphanumerics and interior
// hyphens; a repository name adds underscores and dots.
var (
	ownerPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$`)
	repoPattern  = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
)

// parseExec parses the exec request git sends as its transport command — e.g.
// git-upload-pack '/owner/repo.git' — into the operation and the normalized
// owner/repo it names.
//
// Every error it returns is one condition to the caller: the disallowed-exec
// refusal. The distinctions between them are for the host-side log.
func parseExec(cmd string) (op, repo string, err error) {
	words, err := splitWords(cmd)
	if err != nil {
		return "", "", fmt.Errorf("unparseable exec %q: %w", cmd, err)
	}
	if len(words) != 2 {
		return "", "", fmt.Errorf("exec must be one command and one path, got %d words", len(words))
	}

	op = words[0]
	if op != opFetch && op != opPush {
		return "", "", fmt.Errorf("disallowed command %q", op)
	}

	// The path is the URL's path verbatim — git neither adds nor strips the
	// .git suffix, so both forms arrive and both must resolve to the stored
	// (github.com, owner/repo) key.
	repo = urlparse.NormalizePath(strings.TrimPrefix(words[1], "/"))
	if err := checkRepoShape(repo); err != nil {
		return "", "", fmt.Errorf("bad repository path %q: %w", words[1], err)
	}
	return op, repo, nil
}

// checkRepoShape requires exactly owner/repo, both segments spelled the way
// GitHub spells them. It runs before the value reaches an upstream URL, so
// anything it does not recognize is refused rather than guessed at.
func checkRepoShape(repo string) error {
	owner, name, ok := strings.Cut(repo, "/")
	if !ok {
		return errors.New("expected owner/repo")
	}
	if strings.Contains(name, "/") {
		return errors.New("expected owner/repo, got extra path segments")
	}
	if !ownerPattern.MatchString(owner) {
		return fmt.Errorf("invalid owner %q", owner)
	}
	if name == "." || name == ".." || !repoPattern.MatchString(name) {
		return fmt.Errorf("invalid repository name %q", name)
	}
	return nil
}
