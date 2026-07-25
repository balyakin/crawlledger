package cli

import (
	"fmt"
	"io"

	"github.com/balyakin/crawlledger/internal/app"
	"github.com/balyakin/crawlledger/internal/apperr"
	"github.com/balyakin/crawlledger/internal/parser"
	"github.com/spf13/cobra"
)

func newAnalyzeCommand(stdout, stderr io.Writer) *cobra.Command {
	var request app.AnalyzeRequest
	var format string
	command := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze local access logs into an immutable workspace",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			request.Format = parser.Format(format)
			if err := validateInputs(request.Inputs, request.Format, true); err != nil ||
				request.OutputDir == "" {
				return usage("analyze", "input, format and output are required", err)
			}
			if err := cmd.Context().Err(); err != nil {
				return err
			}
			result, err := app.NewCLI(stderr).Analyze(cmd.Context(), request)
			if err != nil {
				return err
			}
			return writeResult(stdout,
				"analysis_id: %s\naccepted: %d rejected: %d\nreport_json: %s\nreport_html: %s\n",
				result.AnalysisID, result.Accepted, result.Rejected, result.ReportJSON, result.ReportHTML)
		},
	}
	command.Flags().StringArrayVarP(&request.Inputs, "input", "i", nil, "input log path or - (repeatable)")
	command.Flags().StringVarP(&format, "format", "f", "", "input format")
	command.Flags().StringVarP(&request.OutputDir, "output", "o", "", "new workspace directory")
	command.Flags().StringVar(&request.ConfigPath, "config", "", "configuration JSON")
	command.Flags().StringVar(&request.RobotsPath, "robots", "", "local robots.txt")
	command.Flags().StringVar(&request.KeyFilePath, "key-file", "", "32-byte HMAC key file")
	return command
}

func validateInputs(inputs []string, format parser.Format, canonical bool) error {
	if len(inputs) < 1 || len(inputs) > 64 || !format.Valid() {
		return fmt.Errorf("invalid input count or format")
	}
	stdin := 0
	for _, input := range inputs {
		if input == "-" {
			stdin++
		}
	}
	if stdin > 1 {
		return fmt.Errorf("stdin may be used once")
	}
	if !canonical && format == parser.FormatCrawlLedgerJSON {
		return fmt.Errorf("crawlledger-json is not accepted")
	}
	return nil
}

func noArgs(_ *cobra.Command, args []string) error {
	if len(args) != 0 {
		return apperr.New(apperr.CodeUsage, "cli", "positional arguments are not accepted", nil)
	}
	return nil
}

func usage(op, message string, err error) error {
	return apperr.New(apperr.CodeUsage, op, message, err)
}

func writeResult(writer io.Writer, format string, values ...any) error {
	if _, err := fmt.Fprintf(writer, format, values...); err != nil {
		return apperr.New(apperr.CodeOutput, "cli", "cannot write command result", err)
	}
	return nil
}
