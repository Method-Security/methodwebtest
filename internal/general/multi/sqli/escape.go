package general

import (
	"context"
	"strings"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

// Escape character payloads
var escapeCharacterPayloads = []string{
	`'`,
	`;`,
	`\\`,
	`\'`,
	`\"`,
}

var errorPhrases = []string{
	"error",
	"syntax error",
	"unclosed quotation mark",
	"unknown column",
	"near",
	"unexpected token",
	"error in your SQL syntax",
	"missing right parenthesis",
	"quoted string not properly terminated",
	"Internal Server Error",
}

func PerformSqliEscapeCharacterInjection(ctx context.Context, config *methodwebtest.MultiInjectionConfig) *methodwebtest.Report {
	//generate baseline payloads
	generatedBaselinePayloads := utils.GenerateBaselinePayloads(config.VariableData)
	generatedInjectionPayloads := utils.GenerateInjectionPayloads(escapeCharacterPayloads, config.VariableData)

	// Configure the injection engine
	injectionConfig := methodwebtest.InjectionEngineConfig{
		Targets:           config.Targets,
		Method:            config.Method,
		Paths:             []string{"/"},
		BaselinePayload:   generatedBaselinePayloads,
		InjectedPayloads:  generatedInjectionPayloads,
		InjectionLocation: config.InjectionLocation,
		EventType:         methodwebtest.NewEventTypeFromMultiEvent(methodwebtest.MultiEventSqliescape),
		Timeout:           config.Timeout,
		Retries:           config.Retries,
		Sleep:             config.Sleep,
	}

	// Run the injection engine
	report := utils.RunMultiInjectionsEngine(ctx, &injectionConfig)
	checkForEscapeCharacterHandling(report)
	return report
}

func checkForEscapeCharacterHandling(report *methodwebtest.Report) {
	for _, target := range report.Targets {
		baselineError := false

		if target.BaselineAttempt != nil && target.BaselineAttempt.Request.StatusCode != nil && *target.BaselineAttempt.Request.StatusCode > 400 {
			baselineError = true
		} else {
			if target.BaselineAttempt != nil {
				responseBody := *target.BaselineAttempt.Request.ResponseBody
				for _, phrase := range errorPhrases {
					if containsPhrase(responseBody, phrase) {
						baselineError = true
					}
				}
			}
		}

		for _, attempt := range target.Attempts {
			// Check HTTP status codes
			finding := false
			if attempt.Request != nil {
				statusCode := attempt.Request.StatusCode
				if statusCode != nil && *statusCode >= 400 && !baselineError {
					finding = true
				}
			}
			// Check for error phrases in the response body
			if attempt.Request != nil {
				responseBody := *attempt.Request.ResponseBody
				for _, phrase := range errorPhrases {
					if containsPhrase(responseBody, phrase) && !baselineError {
						finding = true
					}
				}
			}
			attempt.Finding = &finding
		}
	}

}

// Helper function to check if a response contains any of the error phrases
func containsPhrase(responseBody string, phrase string) bool {
	return strings.Contains(strings.ToLower(responseBody), strings.ToLower(phrase))
}
