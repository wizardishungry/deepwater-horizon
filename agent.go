package deepwaterhorizon

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/user"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type authorizedKeysMap map[string]struct{}

func (akMap authorizedKeysMap) Exist(pubKey ssh.PublicKey) bool {
	_, ok := akMap[string(pubKey.Marshal())]
	return ok
}
func (akMap authorizedKeysMap) Set(pubKey ssh.PublicKey) {
	akMap[string(pubKey.Marshal())] = struct{}{}
}

func LoadAgent() (agent.ExtendedAgent, error) {
	var conn net.Conn
	socket := os.Getenv("SSH_AUTH_SOCK")
	conn, agentErr := net.Dial("unix", socket)
	if agentErr != nil {
		return nil, fmt.Errorf("Failed to open SSH_AUTH_SOCK: %w", agentErr)
	}
	agentClient := agent.NewClient(conn)
	if agentErr != nil {
		return nil, agentErr
	}

	return agentClient, nil
}

func getAuthorizedKeysMap(agent agent.Agent) (authorizedKeysMap, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}
	authorizedKeysPath := usr.HomeDir + "/.ssh/authorized_keys"

	// Public key authentication is done by comparing
	// the public key of a received connection
	// with the entries in the authorized_keys file.
	authorizedKeysBytes, err := ioutil.ReadFile(authorizedKeysPath)
	if err != nil {
		log.Fatalf("Failed to load authorized_keys, err: %v", err)
	}

	akMap := make(authorizedKeysMap)
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			return nil, err
		}

		akMap.Set(pubKey)
		authorizedKeysBytes = rest
	}

	agentKeys, err := agent.List()
	if err != nil {
		return nil, err
	}
	for _, pubKey := range agentKeys {
		akMap.Set(pubKey)
	}
	return akMap, nil
}

func getAuthorizedKeysCallback(akMap authorizedKeysMap) (func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error), error) {
	return func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
		if akMap.Exist(pubKey) {
			return &ssh.Permissions{
				// Record the public key used for authentication.
				Extensions: map[string]string{
					sshExtFp: ssh.FingerprintSHA256(pubKey),
				},
			}, nil
		}
		return nil, fmt.Errorf("unknown public key for %q", c.User())
	}, nil
}
