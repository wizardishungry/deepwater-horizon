package deepwaterhorizon

import (
	"context"
	"fmt"
	"net"

	"github.com/grandcat/zeroconf"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	sshExtFp   = "bp-fingerprint"
	bonjourKey = "bp-key"
)

type Server struct {
	instanceName string
	agent        agent.Agent // could be agent.ExtendedAgent
}

func NewServer(instanceName string, agent agent.Agent) *Server {
	return &Server{
		agent:        agent,
		instanceName: instanceName,
	}

}

func (s *Server) Run(ctx context.Context) error {
	lc := net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", "")
	if err != nil {
		return fmt.Errorf("net.Listen: %w", err)
	}
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	err = s.register(ctx, listener.Addr().(*net.TCPAddr))
	if err != nil {
		return fmt.Errorf("s.register: %w", err)
	}

	return nil
}

func (s *Server) register(ctx context.Context, tcpAddr *net.TCPAddr) error {
	txtRecords, err := s.txtRecords()
	if err != nil {
		return fmt.Errorf("txtRecords: %w", err)
	}
	zcService, err := zeroconf.Register(s.instanceName, Service, "local.", tcpAddr.Port, txtRecords, nil)
	if err != nil {
		return fmt.Errorf("zeroconf.Register: %w", err)
	}
	zcService.TTL(10) // hmm
	go func() {
		defer zcService.Shutdown()
		<-ctx.Done()
	}()

	return nil
}

func (s *Server) txtRecords() ([]string, error) {
	signers, err := s.agent.Signers()
	if err != nil {
		return nil, fmt.Errorf("s.agent.Signers(): %w", err)
	}

	txtRecords := make([]string, 0, len(signers))

	for _, signer := range signers {
		if signer.PublicKey().Type() != "ssh-ed25519" {
			continue
		}

		encoded := knownhosts.Line([]string{s.instanceName}, signer.PublicKey())
		txt := fmt.Sprintf("%s=%s", bonjourKey, encoded)
		txtRecords = append(txtRecords, txt)
	}
	if len(txtRecords) == 0 {
		return nil, fmt.Errorf("no server keys found")
	}
	txtRecords = append(txtRecords, "asdfsadads=1")
	return txtRecords, nil
}
