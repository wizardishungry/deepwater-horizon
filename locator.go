package deepwaterhorizon

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/grandcat/zeroconf"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
)

const Service = "_ssh._tcp"

type Locator struct{ instanceName string }

func NewLocator(instanceName string) *Locator {
	return &Locator{instanceName: instanceName}
}

func (l *Locator) Run(ctx context.Context) error {

	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return fmt.Errorf("zeroconf.NewResolver: %w", err)
	}

	entries := make(chan *zeroconf.ServiceEntry)
	err = resolver.Lookup(ctx, l.instanceName, Service, "local.", entries)
	if err != nil {
		return fmt.Errorf("zeroconf.NewResolver: %w", err)
	}

	agent, err := LoadAgent()
	if err != nil {
		return fmt.Errorf("LoadAgent: %w", err)
	}

	akMap, err := getAuthorizedKeysMap(agent)
	if err != nil {
		return fmt.Errorf("getAuthorizedKeysMap: %w", err)
	}

	g, ctx := errgroup.WithContext(ctx)
	c := make(chan dialParams)
	g.Go(func() error { return l.dial(ctx, c) })

	for entry := range entries {
		keyIntersect, err := l.match(ctx, entry, akMap)
		if err != nil {
			close(c)
			return fmt.Errorf("match: %w", err)
		}
		fmt.Println("match ", len(keyIntersect))
		if len(keyIntersect) > 0 {
			c <- dialParams{
				entry:             entry,
				authorizedKeysMap: keyIntersect,
			}
		}
	}
	close(c)

	return g.Wait()
}

type dialParams struct {
	entry             *zeroconf.ServiceEntry
	authorizedKeysMap authorizedKeysMap
}

func (l *Locator) dial(ctx context.Context, c <-chan dialParams) error {
	ctxMap := map[context.Context]func(){}
	g, ctx := errgroup.WithContext(ctx)

	ctxChan := make(chan context.Context)

	for params := range c {
		params := params
		ctxCancel, cancel := context.WithCancel(ctx)
		ctxMap[ctxCancel] = cancel
		g.Go(func() error { return l.dialSingleEntry(ctxCancel, params, ctxChan) })
	}
	return g.Wait()
}

func (l *Locator) dialSingleEntry(ctx context.Context, params dialParams, ctxChanOut chan<- context.Context) error {
	ctxMap := map[context.Context]func(){}
	g, ctx := errgroup.WithContext(ctx)

	ctxChan := make(chan context.Context)
	port := strconv.FormatInt(int64(params.entry.Port), 10)
	var addrs []net.IP = make([]net.IP, 0, len(params.entry.AddrIPv6)+len(params.entry.AddrIPv4))
	addrs = append(addrs, params.entry.AddrIPv4...)
	addrs = append(addrs, params.entry.AddrIPv6...)
	for _, addr := range addrs {
		addrStr := net.JoinHostPort(addr.String(), port)
		ctxCancel, cancel := context.WithCancel(ctx)
		ctxMap[ctxCancel] = cancel
		g.Go(func() error { return l.dialSingleAddr(ctxCancel, addrStr, ctxChan) })
	}

	return g.Wait()
}

func (l *Locator) dialSingleAddr(ctx context.Context, addrStr string, ctxChanOut chan<- context.Context) error {
	fmt.Println("addrStr", addrStr)
	return nil
}

func (l *Locator) match(ctx context.Context, entry *zeroconf.ServiceEntry, akMap authorizedKeysMap) (authorizedKeysMap, error) {
	pubKeys := make(authorizedKeysMap, len(entry.Text))
	for _, e := range entry.Text {
		bits := strings.SplitN(e, "=", 2)
		if len(bits) != 2 {
			continue
		}
		k, v := bits[0], bits[1]
		if k != bonjourKey {
			continue
		}
		_, _, pubKey, _, _, err := ssh.ParseKnownHosts([]byte(v))
		if err != nil {
			log.Printf("bad key in zeroconf: %v\n", err)
			continue
		}
		if akMap.Exist(pubKey) {
			pubKeys.Set(pubKey)
		}
	}
	return pubKeys, nil
}
