package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/DarlingGoose/krkrxp3/cmd"
)

func main() {
	if err := cmd.Execute(context.Background()); err != nil {
		slog.Error("command failed", "error", err)
		os.Exit(1)
	}
}
