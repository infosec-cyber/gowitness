package main

import (
	"embed"

	"github.com/infosec-cyber/gowitness/cmd"
)

//go:embed web/assets/* web/ui-templates/* web/static-templates/*
var assets embed.FS

func main() {
	cmd.Embedded = assets
	cmd.Execute()
}
