package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/balyakin/crawlledger/internal/apperr"
	"github.com/balyakin/crawlledger/internal/version"
	"github.com/spf13/cobra"
)

func Execute(ctx context.Context, info version.Info, stdout, stderr io.Writer) int {
	root := newRootCommand(info, stdout, stderr)
	root.SetContext(ctx)
	return executeCommand(root, stderr)
}

func executeCommand(root *cobra.Command, stderr io.Writer) int {
	if err := root.Execute(); err != nil {
		if _, writeErr := fmt.Fprintf(stderr, "crawlledger: %s\n", apperr.UserMessage(err)); writeErr != nil {
			return apperr.ExitCode(apperr.New(apperr.CodeOutput, "stderr", "cannot write error", writeErr))
		}
		return apperr.ExitCode(err)
	}
	return 0
}

func newRootCommand(info version.Info, stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "crawlledger",
		Short:         "Audit crawler traffic from local Nginx and Caddy logs",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := cmd.Help(); err != nil {
				return apperr.New(apperr.CodeOutput, "help", "cannot write help", err)
			}
			return nil
		},
	}
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	cmd.CompletionOptions.DisableDefaultCmd = true
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return apperr.New(apperr.CodeUsage, "cli", err.Error(), err)
	})
	cmd.AddCommand(
		newAnalyzeCommand(stdout, stderr),
		newSanitizeCommand(stdout, stderr),
		newPolicyCommand(stdout, stderr),
		newProtectCommand(stdout, stderr),
		newVersionCommand(info, stdout),
	)
	return cmd
}
