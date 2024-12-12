package apache

import (
	"context"

	methodwebtest "github.com/Method-Security/methodwebtest/generated/go"
	utils "github.com/Method-Security/methodwebtest/utils/engines"
)

var commonExposedPaths = []string{
	"/.cgi",
	"/.env",
	"/.git",
	"/.htaccess",
	"/cgi-bin/",
	"/cgi-bin/admin.cgi",
	"/cgi-bin/test.cgi",
	"/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd", //CVE-2021-41773
	"/etc/apache2/apache2.conf",
	"/etc/apache2/sites-available/apache2.conf",
	"/etc/httpd/conf/httpd.conf",
	"/etc/httpd/httpd.conf",
	"/logs/access.log",
	"/logs/error.log",
	"/perl/admin.cgi",
	"/perl/test.cgi",
	"/scripts/admin.cgi",
	"/scripts/test.cgi",
	"/server-status",
	"/test.cgi",
}

func PerformApachePathTraversal(ctx context.Context, config *methodwebtest.PathTraversalConfig) *methodwebtest.Report {
	config.Paths = commonExposedPaths
	engineConfig := methodwebtest.PathTraversalEngineConfig{
		Targets:           config.Targets,
		Paths:             config.Paths,
		PathFiles:         []string{},
		ResponseCodes:     config.ResponseCodes,
		IgnoreBaseContent: config.IgnoreBaseContent,
		Timeout:           config.Timeout,
		Retries:           config.Retries,
		Sleep:             config.Sleep,
		SuccessfulOnly:    config.SuccessfulOnly,
	}
	report := utils.RunPathTraversalEngine(ctx, &engineConfig)
	report.Config = methodwebtest.NewEngineConfigFromPathTraversalEngineConfig(&engineConfig)
	return report
}
