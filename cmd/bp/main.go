package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	dh "jonwillia.ms/deepwater-horizon"
)

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

	listenFlag := flag.Bool("listen", false, "listen")
	flag.Parse()
	name := flag.Arg(0)

	agent := Must(dh.LoadAgent())

	var run func(ctx context.Context) error

	if *listenFlag {
		log.Println("listen")
		s := dh.NewServer(name, agent)
		run = s.Run
	} else {
		log.Println("locate")
		l := dh.NewLocator(name)
		run = l.Run

	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	err := run(ctx)
	if err != nil {
		log.Fatalf("Run: %v", err)
	}
	<-ctx.Done()
}
