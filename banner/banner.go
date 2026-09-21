// Package banner writes the shared Ardyn service banner.
package banner

import (
	"fmt"
	"io"
)

const Logo = `
                   _
     /\           | |
    /  \   _ __ __| |_   _ _ __
   / /\ \ | '__/ _  | | | | '_ \
  / ____ \| | | (_| | |_| | | | |
 /_/    \_\_|  \__,_|\__, |_| |_|
                      __/ |
                     |___/`

// Write renders the logo and identifies the running service. An io.Writer
// keeps startup logging testable and lets services choose their logger output.
func Write(w io.Writer, service, version string) error {
	_, err := fmt.Fprintf(w, "%s\n%s %s\n\n", Logo, service, version)
	return err
}
