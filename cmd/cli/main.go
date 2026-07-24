package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Damoz1606/go-safety/internal/safety/infrastructure/cli"
)

func main() {

	err := cli.Handle(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
