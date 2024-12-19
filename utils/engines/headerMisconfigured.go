package utils

import (
	"context"
	"time"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils"
)

func RunHeaderMisconfigurationEngine(ctx context.Context, config *methodwebtest.HeaderMisconfigurationEngineConfig) *methodwebtest.Report {
	report := methodwebtest.Report{}
	report.Config = methodwebtest.NewEngineConfigFromHeaderMisconfigurationEngineConfig(config)
	var allErrors []string

	var targets []*methodwebtest.TargetInfo
	for targetIndex, target := range config.Targets {
		targetInfo := methodwebtest.TargetInfo{Target: target, StartTimestamp: time.Now()}

		baseURL, parsedPath, err := utils.SplitTarget(target)
		if err != nil {
			allErrors = append(allErrors, err.Error())
			continue
		}
		attempts := []*methodwebtest.AttemptInfo{}
		for _, headerGroup := range config.Payloads[targetIndex] {
			for retry := 0; retry <= config.Retries; retry++ {
				attempt := methodwebtest.AttemptInfo{}
				startTime := time.Now()
				request := utils.PerformRequestScan(baseURL,
					parsedPath,
					config.Method,
					methodwebtest.RequestParams{HeaderParams: headerGroup},
					[]*methodwebtest.EventType{config.EventType},
					config.Timeout)
				endTime := time.Now()

				attempt.TimeSent = startTime
				attempt.TimeReceived = &endTime

				attempt.Request = &request
				attempts = append(attempts, &attempt)
			}
		}
		targetInfo.Attempts = attempts
		targetInfo.RequestCount = len(attempts)
		targetInfo.EndTimestamp = time.Now()
		targets = append(targets, &targetInfo)

	}
	report.Targets = targets
	report.Errors = allErrors
	return &report
}
