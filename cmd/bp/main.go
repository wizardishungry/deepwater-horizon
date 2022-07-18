package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/grandcat/zeroconf"
)

const Service = "_ssh._tcp"

func Must0(err error)                       { must[any](nil, err) }
func Must[T0 any](a0 T0, err error) (v0 T0) { return must(a0, err) }

func must[T0 any](a0 T0, err error) (v0 T0) {
	v0 = a0
	if err == nil {
		return
	}

	_, file, no, ok := runtime.Caller(2)
	if ok {
		fmt.Printf("called from %s#%d\n", file, no)
	}

	fp, err2 := os.Open(file)
	assert := ""
	if err2 == nil {
		defer fp.Close()
		scanner := bufio.NewScanner(fp)
		for i := 0; i < no && scanner.Scan(); i++ {
		}
		assert = strings.TrimSpace(scanner.Text())
	} else {
		assert = fmt.Sprintf("%T", a0)
	}

	log.Fatalf("%s: %v", assert, err)

	return
}

func main() {
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	resolver := Must(zeroconf.NewResolver(nil))

	flag.Parse()
	instance := flag.Arg(0)

	entries := make(chan *zeroconf.ServiceEntry)
	Must0(resolver.Lookup(ctx, instance, Service, "local.", entries))
	for entry := range entries {
		fmt.Println(entry)
	}
}
