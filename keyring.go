package keyctl

// ID is interface for all Keys and Keyrings that have unique 32-bit serial number identifiers.
type ID interface {
	ID() int32
	Info() (Info, error)

	private()
}

// Keyring is a basic interface to a linux keyctl keyring.
type Keyring interface {
	ID
	Add(string, []byte) (*Key, error)
	Search(string) (*Key, error)
	SetDefaultTimeout(uint)
}

// NamedKeyring are user-created keyrings linked to a parent keyring. The
// parent can be either named or one of the in-built keyrings (session, group
// etc.). The in-built keyrings have no parents. Keyring searching is performed
// hierarchically.
type NamedKeyring interface {
	Keyring
	Name() string
}

type keyring struct {
	id         keyID
	defaultTTL uint
}

type namedKeyring struct {
	*keyring
	parent keyID
	name   string // for non-anonymous keyrings
	ttl    uint
}

func (kr *keyring) private() {}

// ID returns the 32-bit kernel identifier of a keyring
func (kr *keyring) ID() int32 {
	return int32(kr.id)
}

// Info returns information about a keyring.
func (kr *keyring) Info() (Info, error) {
	return getInfo(kr.id)
}

// Name return the name of a NamedKeyring that was set when the keyring was created
// or opened.
func (kr *namedKeyring) Name() string {
	return kr.name
}

// SetDefaultTimeout in seconds, after which newly added keys will be destroyed.
func (kr *keyring) SetDefaultTimeout(nsecs uint) {
	kr.defaultTTL = nsecs
}

// Add a new key to a keyring. The key can be searched for later by name.
func (kr *keyring) Add(name string, key []byte) (*Key, error) {
	r, err := addKeyFunc("user", name, key, int32(kr.id))
	if err == nil {
		key := &Key{Name: name, id: keyID(r), ring: kr.id}
		if kr.defaultTTL != 0 {
			err = key.ExpireAfter(kr.defaultTTL)
		}
		return key, err
	}

	return nil, err
}

// Search for a key by name, this also searches child keyrings linked to this
// one. The key, if found, is linked to the top keyring that Search() was called
// from.
func (kr *keyring) Search(name string) (*Key, error) {
	id, err := searchKeyring(kr.id, name, "user")
	if err == nil {
		return &Key{Name: name, id: id, ring: kr.id}, nil
	}
	return nil, err
}

// SessionKeyring return the current login session keyring
func SessionKeyring() (Keyring, error) {
	return newKeyring(keySpecSessionKeyring)
}

// UserSessionKeyring return the current user-session keyring (part of session, but private to
// current user)
func UserSessionKeyring() (Keyring, error) {
	return newKeyring(keySpecUserSessionKeyring)
}

// GroupKeyring return the current group keyring.
func GroupKeyring() (Keyring, error) {
	return newKeyring(keySpecGroupKeyring)
}

// ThreadKeyring return the keyring specific to the current executing thread.
func ThreadKeyring() (Keyring, error) {
	return newKeyring(keySpecThreadKeyring)
}

// ProcessKeyring returns the keyring specific to the current executing process.
func ProcessKeyring() (Keyring, error) {
	return newKeyring(keySpecProcessKeyring)
}

// CreateKeyring creates a new named-keyring linked to a parent keyring. The parent may be
// one of those returned by SessionKeyring(), UserSessionKeyring() and friends,
// or it may be an existing named-keyring. When searching is performed, all
// keyrings form a hierarchy and are searched top-down. If the keyring already
// exists it will be destroyed and a new one with the same name created. Named
// sub-keyrings inherit their initial ttl (if set) from the parent but can
// outlive the parent as the timer is restarted at creation.
func CreateKeyring(parent Keyring, name string) (NamedKeyring, error) {
	var ttl uint

	parentID := keyID(parent.ID())
	kr, err := createKeyring(parentID, name)
	if err != nil {
		return nil, err
	}

	if pkr, ok := parent.(*namedKeyring); ok {
		ttl = pkr.ttl
	}
	ring := &namedKeyring{
		keyring: kr,
		parent:  parentID,
		name:    name,
		ttl:     ttl,
	}

	if ttl > 0 {
		err = keyctlSetTimeoutFunc(ring.id, ttl)
	}

	return ring, nil
}

// OpenKeyring search for and open an existing keyring with the given name linked to a
// parent keyring (at any depth).
func OpenKeyring(parent Keyring, name string) (NamedKeyring, error) {
	parentID := keyID(parent.ID())
	id, err := searchKeyring(parentID, name, "keyring")
	if err != nil {
		return nil, err
	}

	return &namedKeyring{
		keyring: &keyring{id: id},
		parent:  parentID,
		name:    name,
	}, nil
}

// SetKeyringTTL set the time to live in seconds for an entire keyring and all of its keys.
// Only named keyrings can have their time-to-live set, the in-built keyrings
// cannot (Session, UserSession, etc.).
func SetKeyringTTL(kr NamedKeyring, nsecs uint) error {
	err := keyctlSetTimeoutFunc(keyID(kr.ID()), nsecs)
	if err == nil {
		kr.(*namedKeyring).ttl = nsecs
	}
	return err
}

// Link an object to a keyring
func Link(parent Keyring, child ID) error {
	return keyctlLinkFunc(keyID(child.ID()), keyID(parent.ID()))
}

// Unlink an object from a keyring
func Unlink(parent Keyring, child ID) error {
	return keyctlUnlinkFunc(keyID(child.ID()), keyID(parent.ID()))
}

// UnlinkKeyring a named keyring from its parent.
func UnlinkKeyring(kr NamedKeyring) error {
	return keyctlUnlinkFunc(keyID(kr.ID()), kr.(*namedKeyring).parent)
}
