package cli

import (
	"io"

	"github.com/balyakin/crawlledger/internal/app"
	"github.com/spf13/cobra"
)

func newPolicyCommand(stdout, stderr io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   "policy",
		Short: "Simulate and render crawler policies",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := cmd.Help(); err != nil {
				return err
			}
			return nil
		},
	}
	command.AddCommand(newSimulateCommand(stdout, stderr), newRenderCommand(stdout, stderr))
	return command
}

func newSimulateCommand(stdout, stderr io.Writer) *cobra.Command {
	var request app.SimulateRequest
	command := &cobra.Command{
		Use:   "simulate",
		Short: "Simulate a policy against a completed workspace",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if request.Workspace == "" || request.Policy == "" || request.Output == "" {
				return usage("policy simulate", "workspace, policy and output are required", nil)
			}
			if err := cmd.Context().Err(); err != nil {
				return err
			}
			result, err := app.NewCLI(stderr).Simulate(cmd.Context(), request)
			if err != nil {
				return err
			}
			return writeResult(stdout, "run_id: %s\nstatus: %s\nrisks: %d\noutput: %s\n",
				result.RunID, result.Status, result.Risks, result.Output)
		},
	}
	command.Flags().StringVar(&request.Workspace, "workspace", "", "completed workspace")
	command.Flags().StringVar(&request.Policy, "policy", "", "policy JSON")
	command.Flags().StringVarP(&request.Output, "output", "o", "", "new simulation JSON")
	return command
}

func newRenderCommand(stdout, stderr io.Writer) *cobra.Command {
	var request app.RenderRequest
	command := &cobra.Command{
		Use:   "render",
		Short: "Render a verified policy for Nginx or Caddy",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if request.Workspace == "" || request.Policy == "" || request.Simulation == "" ||
				request.OutputDir == "" || request.Target != "nginx" && request.Target != "caddy" {
				return usage("policy render", "workspace, policy, simulation, target and output are required", nil)
			}
			if err := cmd.Context().Err(); err != nil {
				return err
			}
			result, err := app.NewCLI(stderr).Render(cmd.Context(), request)
			if err != nil {
				return err
			}
			return writeResult(stdout, "target: %s\noutput: %s\nfiles: %d\n",
				result.Target, result.Output, result.Files)
		},
	}
	command.Flags().StringVar(&request.Workspace, "workspace", "", "completed workspace")
	command.Flags().StringVar(&request.Policy, "policy", "", "policy JSON")
	command.Flags().StringVar(&request.Simulation, "simulation", "", "canonical simulation JSON")
	command.Flags().StringVar(&request.Target, "target", "", "nginx or caddy")
	command.Flags().StringVarP(&request.OutputDir, "output", "o", "", "new render directory")
	command.Flags().StringArrayVar(&request.Acks, "ack", nil, "acknowledge risk ID (repeatable)")
	return command
}
