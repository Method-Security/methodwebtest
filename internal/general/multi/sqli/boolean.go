package general

import (
	"context"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

// SQL error-based payloads
var sqliBooleanPayloads = []string{
	`'--`,
	`' OR 'a'='a`,
	`' OR 1=1`,
	`' OR TRUE`,
}

func PerformSqliBooleanInjection(ctx context.Context, config *methodwebtest.MultiInjectionConfig) *methodwebtest.Report {
	generatedInjectionPayloads := utils.GenerateInjectionPayloads(sqliBooleanPayloads, config.VariableData)
	generatedBaselinePayloads := utils.GenerateBaselinePayloads(config.VariableData)

	injectionConfig := methodwebtest.InjectionEngineConfig{
		Targets:           config.Targets,
		Method:            config.Method,
		Paths:             []string{"/"},
		BaselinePayload:   generatedBaselinePayloads,
		InjectedPayloads:  generatedInjectionPayloads,
		InjectionLocation: config.InjectionLocation,
		EventType:         methodwebtest.NewEventTypeFromMultiEvent(methodwebtest.MultiEventSqliboolean),
		Timeout:           config.Timeout,
		Retries:           config.Retries,
		Sleep:             config.Sleep,
	}

	report := utils.RunMultiInjectionsEngine(ctx, &injectionConfig)
	checkForSqliBooleanBased(report)
	return report
}

func checkForSqliBooleanBased(report *methodwebtest.Report) {
	for _, target := range report.Targets {
		bodySize := len(*target.BaselineAttempt.Request.ResponseBody)

		for _, attempt := range target.Attempts {
			finding := false
			if attempt.Request != nil {
				responseBody := *attempt.Request.ResponseBody
				if float64(len(responseBody)) > float64(bodySize)*1.2 {
					finding = true
				}
			}
			attempt.Finding = &finding
		}
	}
}
