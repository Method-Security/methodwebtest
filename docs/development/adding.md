# Adding a new capability

By design, methodwebtest breaks every unique network scan into its own top level command. If you are looking to add a brand new capability to the tool, you can take the following steps.

1. Add a file to `cmd/` that corresponds to the sub-command name you'd like to add to the `methodwebtest` CLI
2. You can use `cmd/general.go` as a template
3. Your file needs to be a member function of the `methodwebtest` struct and should be of the form `Init<cmd>Command`
4. Add a new member to the `methodwebtest` struct in `cmd/root.go` that corresponsds to your command name. Remember, the first letter must be capitalized.
5. Call your `Init` function from `main.go`
6. Add logic to your commands runtime and put it in its own package within `internal` (e.g., `internal/apache/path/traversal.go`)
