package db

// Credential is one stored PAT row. PAT holds the encrypted BLOB
// (nonce + ciphertext + tag); the db layer does not interpret it.
type Credential struct {
	ID       int64
	Host     string
	Path     string
	Username string
	PAT      []byte
	Label    string
	Created  int64
	Expires  *int64
}
