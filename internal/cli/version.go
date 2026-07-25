package cli

import (
	"encoding/json"
	"io"

	"github.com/balyakin/crawlledger/internal/apperr"
	"github.com/balyakin/crawlledger/internal/version"
	"github.com/spf13/cobra"
)

func newVersionCommand(info version.Info, stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print build version as JSON",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := cmd.Context().Err(); err != nil {
				return err
			}
			encoder := json.NewEncoder(stdout)
			encoder.SetEscapeHTML(false)
			if err := encoder.Encode(info); err != nil {
				return apperr.New(apperr.CodeOutput, "version", "cannot write version", err)
			}
			return nil
		},
	}
}
