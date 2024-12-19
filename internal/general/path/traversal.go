package general

import (
	"context"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

func PerformGeneralPathTraversal(ctx context.Context, config *methodwebtest.PathTraversalConfig) *methodwebtest.Report {
	engineConfig := methodwebtest.PathTraversalEngineConfig{
		Targets:           config.Targets,
		Paths:             config.Paths,
		PathFiles:         config.PathLists,
		ResponseCodes:     config.ResponseCodes,
		IgnoreBaseContent: config.IgnoreBaseContent,
		Timeout:           config.Timeout,
		Retries:           config.Retries,
		Sleep:             config.Sleep,
		SuccessfulOnly:    config.SuccessfulOnly,
	}
	if config.QueryParam != nil {
		engineConfig.QueryParam = config.QueryParam
	}
	report := utils.RunPathTraversalEngine(ctx, &engineConfig)
	report.Config = methodwebtest.NewEngineConfigFromPathTraversalEngineConfig(&engineConfig)
	return report
}
