package common

import (
	"encoding/json"
	"time"
)

type KeyPair struct {
	EncryptedPrivateKey string `json:"encryptedPrivateKey"`
	PublicKey           string `json:"publicKey"`
}

type Account struct {
	Id                 string  `json:"id"`
	Name               string  `json:"name"`
	Email              string  `json:"email"`
	MasterPasswordHash string  `json:"masterPasswordHash"`
	MasterPasswordHint string  `json:"masterPasswordHint"`
	Key                string  `json:"key"`
	KeyPair            KeyPair `json:"keys"`
	RefreshToken       string  `json:"-"`
	TwoFactorSecret    string  `json:"-"`
	Kdf                int     `json:"kdf"`
	KdfIterations      int     `json:"kdfIterations"`
}

func (acc Account) GetProfile() Profile {
	name := acc.Name
	p := Profile{
		Id:                 acc.Id,
		Name:               &name,
		Email:              acc.Email,
		EmailVerified:      false,
		Premium:            false,
		Culture:            "en-US",
		Key:                acc.Key,
		SecurityStamp:      nil,
		Organizations:      make([]string, 0),
		MasterPasswordHint: nil,
		PrivateKey:         acc.KeyPair.EncryptedPrivateKey,
		Object:             "profile",
	}

	if len(acc.TwoFactorSecret) > 0 {
		p.TwoFactorEnabled = true
	}

	return p
}

// The data we store and send to the client
type Cipher struct {
	Type                int
	FolderId            *string // Must be pointer to output null in json. Android app will crash if not null
	OrganizationId      *string
	Favorite            bool
	Edit                bool
	Id                  string
	Data                CipherData // deprecated TODO: Stop depending on this
	Attachments         []string
	OrganizationUseTotp bool
	RevisionDate        time.Time
	Object              string
	CollectionIds       []string

	Card       *string
	Fields     []string
	Identity   *string
	Login      Login
	Name       *string
	Notes      *string // Must be pointer to output null in json. Android app will crash if not null
	SecureNote SecureNote
}

type CipherData struct {
	Uri      *string
	Username *string
	Password *string
	Totp     *string // Must be pointer to output null in json. Android app will crash if not null
	Name     *string
	Notes    *string // Must be pointer to output null in json. Android app will crash if not null
	Fields   []string
	Uris     []Uri
}

type Uri struct {
	Uri   *string
	Match *int
}

type Login struct {
	Password *string
	Totp     *string // Must be pointer to output null in json. Android app will crash if not null
	Uri      *string
	Uris     []Uri
	Username *string
}

type SecureNote struct {
	Type int
}

func (data *CipherData) Bytes() ([]byte, error) {
	b, err := json.Marshal(&data)
	return b, err
}

type Profile struct {
	Id                 string
	Name               *string
	Email              string
	EmailVerified      bool
	Premium            bool
	MasterPasswordHint *string
	Culture            string
	TwoFactorEnabled   bool
	Key                string
	PrivateKey         string
	SecurityStamp      *string
	Organizations      []string
	Object             string
}

// Copy from data to new fields
func FakeNewAPI(ciph *Cipher) {
	// TODO: Rewrite this when the data field is removed
	ciph.Card = nil // TODO: Implement
	ciph.Fields = nil
	ciph.Identity = nil // TODO: Implement
	ciph.Name = ciph.Data.Name

	// Set ciph.Data.Uris if it's not in the DB
	if ciph.Data.Uri != nil && ciph.Data.Uris == nil {
		ciph.Data.Uris = []Uri{Uri{
			Uri:   ciph.Data.Uri,
			Match: nil,
		}}
	}

	if ciph.Data.Username != nil {
		ciph.Login = Login{
			Username: ciph.Data.Username,
			Totp:     ciph.Data.Totp,
			Uri:      ciph.Data.Uri,
			Uris:     ciph.Data.Uris,
			Password: ciph.Data.Password,
		}
	}

	ciph.Notes = ciph.Data.Notes
	if ciph.Notes != nil {
		ciph.SecureNote = SecureNote{
			Type: 0,
		}
	}
}

type SyncData struct {
	Profile Profile
	Folders []Folder
	Ciphers []Cipher
	Domains Domains
	Object  string
}

type Domains struct {
	EquivalentDomains       []string
	GlobalEquivalentDomains []GlobalEquivalentDomains
	Object                  string
}

type GlobalEquivalentDomains struct {
	Type     int
	Domains  []string
	Excluded bool
}

type Folder struct {
	Id           string
	Name         string
	Object       string
	RevisionDate time.Time
}

type Data struct {
	Object string
	Data   interface{}
}
