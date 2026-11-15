package main

// sage: Simple GUI for age. Encryption is done in-process by the official age
// library (filippo.io/age); the window is HTML/CSS/TypeScript served by Wails v3.

import (
	"embed"
	"log"
	"os"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// Paths given on the command line, e.g. by Explorer's "Send to".
	var launch []string
	for _, a := range os.Args[1:] {
		if a != "" {
			launch = append(launch, a)
		}
	}
	svc := NewSageService(launch)

	// Do not add a Logger or LogLevel (e.g. slog.LevelDebug) here: Wails logs the
	// arguments of every call from the window at Debug level, and Start receives the
	// passphrase. The default production logger discards them.
	app := application.New(application.Options{
		Name:        "sage",
		Description: "Simple GUI for age file encryption",
		Services: []application.Service{
			application.NewService(svc),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
	})
	svc.app = app

	window := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            appTitle,
		Width:            590,
		Height:           720,
		MinWidth:         520,
		MinHeight:        540,
		BackgroundColour: application.NewRGB(32, 32, 32), // --bg in style.css, so there's no flash at start
		URL:              "/",
		// Files dropped on elements marked data-file-drop-target arrive here.
		EnableFileDrop: true,
	})
	window.OnWindowEvent(events.Common.WindowFilesDropped, func(e *application.WindowEvent) {
		app.Event.Emit("files:dropped", e.Context().DroppedFiles())
	})

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
