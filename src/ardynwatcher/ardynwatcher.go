package ardynwatcher

import (
	"log"

	"github.com/fsnotify/fsnotify"
)

//-------------------------------------------------------

func ArdynWatch(file *string, action func()) {

	// Watch for changes in the configuration file
	// Better keep this code in ArdynCommon
	watcher, err := fsnotify.NewWatcher()

	if err != nil {
		log.Fatalf("Failed to create watcher: %v", err)
	}

	//Defer close the watcher
	defer watcher.Close()

	// Adding some sample config file
	err = watcher.Add(*file)

	if err != nil {
		log.Fatalf("Failed to add file to watcher: %v", err)
	}

	// Let's start the event loop
	for {
		select {
		case event := <-watcher.Events:
			// Checks for any modification in config file
			if event.Op&fsnotify.Write == fsnotify.Write {
				log.Println("Configuration file changed, reloading...")
				action()

			}
		case err := <-watcher.Errors:
			log.Printf("Watcher error: %v", err)
		}
	}
}

//-------------------------------------------------------
