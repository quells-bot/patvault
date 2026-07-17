package relay

import (
	"errors"
	"strings"
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
