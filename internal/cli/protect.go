package cli

import (
	"io"

	"github.com/balyakin/crawlledger/internal/app"
	"github.com/spf13/cobra"
)

func newProtectCommand(stdout, stderr io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   "protect",
		Short: "Detect and optionally mitigate emergency Nginx request floods",
		Args:  noArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return command.Help()
		},
	}
	command.AddCommand(
		newProtectSetupCommand(stdout, stderr),
		newProtectRunCommand(stdout, stderr),
		newProtectClearCommand(stdout, stderr),
		newProtectApplyCommand(stdout, stderr),
	)
	return command
}

func newProtectSetupCommand(stdout, stderr io.Writer) *cobra.Command {
	var request app.ProtectSetupRequest
	command := &cobra.Command{
		Use:   "setup",
		Short: "Install and validate managed Nginx protection fragments",
		Args:  noArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if request.ConfigPath == "" {
				return usage("protect setup", "config is required", nil)
			}
			result, err := app.NewCLI(stderr).ProtectSetup(command.Context(), request)
			if err != nil {
				return err
			}
			return writeResult(
				stdout,
				"http_include: %s\nserver_include: %s\nservice_user: %s\nservice_group: %s\n"+
					"includes_active: %t\nnginx_http: include \"%s\";\nnginx_server: include \"%s\";\n"+
					"sudoers: %s ALL=(root) NOPASSWD: %s protect apply --config %s\n",
				result.HTTPInclude,
				result.ServerInclude,
				result.ServiceUser,
				result.ServiceGroup,
				result.IncludesActive,
				result.HTTPInclude,
				result.ServerInclude,
				result.ServiceUser,
				result.Executable,
				result.ConfigPath,
			)
		},
	}
	command.Flags().StringVar(&request.ConfigPath, "config", "", "protection configuration JSON")
	return command
}

func newProtectRunCommand(stdout, stderr io.Writer) *cobra.Command {
	var request app.ProtectRunRequest
	command := &cobra.Command{
		Use:   "run",
		Short: "Watch the dedicated log in dry-run mode unless --apply is set",
		Args:  noArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if request.ConfigPath == "" {
				return usage("protect run", "config is required", nil)
			}
			result, err := app.NewCLI(stderr).ProtectRun(command.Context(), request)
			if err != nil {
				return err
			}
			return writeResult(
				stdout,
				"mode: %s\ncomplete_minutes: %d\nbaseline_eligible: %t\n",
				result.Mode,
				result.CompleteMinutes,
				result.BaselineEligible,
			)
		},
	}
	command.Flags().StringVar(&request.ConfigPath, "config", "", "protection configuration JSON")
	command.Flags().BoolVar(&request.Apply, "apply", false, "apply temporary Nginx 429 rules (default is dry-run)")
	return command
}

func newProtectClearCommand(stdout, stderr io.Writer) *cobra.Command {
	var request app.ProtectClearRequest
	command := &cobra.Command{
		Use:   "clear",
		Short: "Remove every temporary Nginx 429 rule",
		Args:  noArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if request.ConfigPath == "" {
				return usage("protect clear", "config is required", nil)
			}
			if err := app.NewCLI(stderr).ProtectClear(command.Context(), request); err != nil {
				return err
			}
			return writeResult(stdout, "cleared: true\n")
		},
	}
	command.Flags().StringVar(&request.ConfigPath, "config", "", "protection configuration JSON")
	return command
}

func newProtectApplyCommand(stdout, stderr io.Writer) *cobra.Command {
	var request app.ProtectApplyRequest
	command := &cobra.Command{
		Use:   "apply",
		Short: "Apply the coordinator-locked desired map as root",
		Args:  noArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if request.ConfigPath == "" {
				return usage("protect apply", "config is required", nil)
			}
			if err := app.NewCLI(stderr).ProtectApply(command.Context(), request); err != nil {
				return err
			}
			return writeResult(stdout, "applied: true\n")
		},
	}
	command.Flags().StringVar(&request.ConfigPath, "config", "", "protection configuration JSON")
	return command
}
