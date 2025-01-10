package utils

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	"github.com/Method-Security/methodwebtest/utils"
)

func RunPathTraversalEngine(ctx context.Context, config *methodwebtest.PathTraversalEngineConfig) *methodwebtest.Report {
	// Initialize report
	report := methodwebtest.Report{}
	var allErrors []string

	// Gather all paths
	allPaths, err := gatherPaths(config.Paths, config.PathFiles)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return &report
	}

	// Parse response codes
	validCodes, err := parseResponseCodes(config.ResponseCodes)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return &report
	}

	var targets []*methodwebtest.TargetInfo
	for _, target := range config.Targets {
		targetInfo := methodwebtest.TargetInfo{Target: target, StartTimestamp: time.Now()}

		// Get baseline size and word count
		baselineSize, baselineWords, err := baseLine(target)
		if err != nil {
			allErrors = append(allErrors, err.Error())
			continue
		}

		// Split target
		baseURL, parsedTargetPath, err := utils.SplitTarget(target)
		if err != nil {
			allErrors = append(allErrors, err.Error())
			continue
		}

		var attempts []*methodwebtest.AttemptInfo
		for _, injectionPath := range allPaths {
			for i := 0; i <= config.Retries; i++ {
				attemptInfo := methodwebtest.AttemptInfo{}

				// Path injection location
				requestParams := methodwebtest.RequestParams{}
				requestPath := fmt.Sprintf("%s/%s", parsedTargetPath, strings.Trim(injectionPath, "/"))
				if config.QueryParam != nil {
					requestPath = parsedTargetPath
					requestParams.QueryParams = map[string]string{*config.QueryParam: injectionPath}
				}

				// Send request
				startTime := time.Now()
				request := utils.PerformRequestScan(
					baseURL,
					requestPath,
					methodwebtest.HttpMethodGet,
					requestParams,
					[]*methodwebtest.EventType{methodwebtest.NewEventTypeFromPathEvent(methodwebtest.PathEventTraversal)},
					config.Timeout)
				endTime := time.Now()

				isValid := AnalyzeResponse(request, validCodes, config.IgnoreBaseContent, baselineSize, baselineWords)

				// Marshal data
				if !config.SuccessfulOnly || isValid {
					attemptInfo.TimeSent = startTime
					attemptInfo.TimeReceived = &endTime
					attemptInfo.Request = &request
					attemptInfo.Finding = &isValid
					attempts = append(attempts, &attemptInfo)
				}

				if config.Sleep > 0 {
					time.Sleep(time.Duration(config.Sleep) * time.Second)
				}
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

// AnalyzeResponse checks if the response singifies that file was found based on the response code and the baseline size and word count
func AnalyzeResponse(request methodwebtest.RequestInfo, validCodes map[int]bool, ignoreBaseContent bool, baselineSize, baselineWords int) bool {
	if request.StatusCode == nil || !validCodes[*request.StatusCode] {
		return false
	}

	bodySize := len(*request.ResponseBody)
	wordCount := len(strings.Fields(*request.ResponseBody))
	if ignoreBaseContent {
		if bodySize == baselineSize && wordCount == baselineWords {
			return false
		}
	}
	return true
}

// baseLine gets the baseline size and word count of the target to be used for validation of the response
func baseLine(baseTarget string) (int, int, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Make the HTTP request
	resp, err := client.Get(baseTarget)
	if err != nil {
		return 0, 0, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, err
	}

	bodySize := len(body)
	wordCount := len(strings.Fields(string(body)))

	err = resp.Body.Close()
	if err != nil {
		return 0, 0, err
	}

	return bodySize, wordCount, nil
}

// parseResponseCodes parses a comma-separated or range-based string of response codes
// (e.g., "200,301,404-410") and returns a map of valid codes.
func parseResponseCodes(responseCodes string) (map[int]bool, error) {
	validCodes := make(map[int]bool)
	for _, part := range strings.Split(responseCodes, ",") {
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			start, err1 := strconv.Atoi(rangeParts[0])
			end, err2 := strconv.Atoi(rangeParts[1])
			if err1 != nil || err2 != nil || start > end {
				return nil, errors.New("invalid response code range")
			}
			for i := start; i <= end; i++ {
				validCodes[i] = true
			}
		} else {
			code, err := strconv.Atoi(part)
			if err != nil {
				return nil, errors.New("invalid response code")
			}
			validCodes[code] = true
		}
	}
	return validCodes, nil
}
func gatherPaths(paths []string, pathLists []string) ([]string, error) {
	pathsFromFiles, err := utils.GetEntriesFromFiles(pathLists)
	if err != nil {
		return nil, err
	}
	allPaths := append(paths, pathsFromFiles...)
	return allPaths, nil
}
