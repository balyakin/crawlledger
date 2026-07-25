package cli

import (
	"io"

	"github.com/balyakin/crawlledger/internal/app"
	"github.com/balyakin/crawlledger/internal/parser"
	"github.com/spf13/cobra"
)

func newSanitizeCommand(stdout, stderr io.Writer) *cobra.Command {
	var request app.SanitizeRequest
	var format string
	command := &cobra.Command{
		Use:   "sanitize",
		Short: "Create a pseudonymized evidence bundle",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			request.Format = parser.Format(format)
			if err := validateInputs(request.Inputs, request.Format, false); err != nil ||
				request.OutputDir == "" {
				return usage("sanitize", "raw input, format and output are required", err)
			}
			if err := cmd.Context().Err(); err != nil {
				return err
			}
			result, err := app.NewCLI(stderr).Sanitize(cmd.Context(), request)
			if err != nil {
				return err
			}
			return writeResult(stdout,
				"accepted: %d rejected: %d\nbundle: %s\nmanifest: %s\n",
				result.Accepted, result.Rejected, result.Bundle, result.Manifest)
		},
	}
	command.Flags().StringArrayVarP(&request.Inputs, "input", "i", nil, "input log path or - (repeatable)")
	command.Flags().StringVarP(&format, "format", "f", "", "raw input format")
	command.Flags().StringVarP(&request.OutputDir, "output", "o", "", "new evidence directory")
	command.Flags().StringVar(&request.RobotsPath, "robots", "", "local robots.txt")
	command.Flags().StringVar(&request.KeyFilePath, "key-file", "", "32-byte HMAC key file")
	return command
}
