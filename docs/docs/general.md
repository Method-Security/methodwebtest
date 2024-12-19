# General

The `methodwebtest general` command tests a target for general vulnerabilities.

## Usage

```bash
methodwebtest general [command]
```

## Commands

### Header

#### Usage

```bash
methodwebtest general header [command]
```

#### Commands

##### Misconfigured

###### Usage

```bash
methodwebtest general header misconfigured --targets https://example.com --event CORS
```

###### Help Text

```bash
methodwebtest general header misconfigured  -h
Perform header tests to detect misconfigurations such as overly permissive CORS, 
		vulnerable HTTP methods, improper escape charecter handling, and Sensitive value exposure.

Usage:
  methodwebtest general header misconfigured [flags]

Flags:
      --event string   Specifies the header event to run: CORS, HTTP, ESCAPE, SENSITIVEEXPOSE
  -h, --help           help for misconfigured

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --retries int          Number of attempts per credential pair
      --sleep int            Sleep time between requests (seconds)
      --targets strings      The URL of target
      --timeout int          Timeout per request (seconds) (default 30)
  -v, --verbose              Verbose output
```


##### Serveroverload

###### Usage

```bash
methodwebtest general header serveroverload --targets https://example.com --headernames x-test-overload --headersize 10000
```

###### Help Text

```bash
methodwebtest general header serveroverload  -h
Define the Header name and value length for server overload requests.

Usage:
  methodwebtest general header serveroverload [flags]

Flags:
      --headernames strings   Specifies Header keys to use in request. (default [test])
      --headersize int        Specifies the length of header values to include in requests. (default 100)
  -h, --help                  help for serveroverload

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --retries int          Number of attempts per credential pair
      --sleep int            Sleep time between requests (seconds)
      --targets strings      The URL of target
      --timeout int          Timeout per request (seconds) (default 30)
  -v, --verbose              Verbose output
```

##### Useragent

###### Usage

```bash
methodwebtest general header useragent --targets https://example.com --agentheader python/2.7
```

###### Help Text

```bash
methodwebtest general header useragent  -h     
Preform User-Agent header requests.

Usage:
  methodwebtest general header useragent [flags]

Flags:
      --agentheader string   Value of the User-Agent header to use in request.
  -h, --help                 help for useragent

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --retries int          Number of attempts per credential pair
      --sleep int            Sleep time between requests (seconds)
      --targets strings      The URL of target
      --timeout int          Timeout per request (seconds) (default 30)
  -v, --verbose              Verbose output
```

### Path 

#### Usage

```bash
methodwebtest general path [command]
```

#### Commands

##### Crlf

###### Usage

```bash
methodwebtest general path crlf --targets https://example.com --headername Set-Cookie --headervalue crlf-injection
```

###### Help Text

```bash
methodwebtest general path crlf -h
Perform CRLF injection tests in the path of a target

Usage:
  methodwebtest general path crlf [flags]

Flags:
      --headername string    The name of the header to inject
      --headervalue string   The value of the header to inject
  -h, --help                 help for crlf

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --retries int          Number of attempts per credential pair
      --sleep int            Sleep time between requests (seconds)
      --targets strings      The URL of target
      --timeout int          Timeout per request (seconds) (default 30)
  -v, --verbose              Verbose output
```

##### Traversal

Perform Apache specific path traversal injection tests against a target

###### Usage

```bash
methodwebtest general path traversal --targets https://example.com --ignore-base-content-match false --responsecodes 200-299 --successfulonly
```

###### Help Text

```bash
methodwebtest general path traversal -h
Perform a path traversal against a URL target

Usage:
  methodwebtest general path traversal [flags]

Flags:
  -h, --help                        help for traversal
      --ignore-base-content-match   Ignores valid responses with identical size and word length to the base path, typically signifying a web backend redirect (default true)
      --pathlists strings           Path to a file that contains a new line delimited list of paths to fuzz
      --paths strings               File paths to use in attack
      --queryparam string           Optional query parameter to use in path traversal
      --responsecodes string        Response codes to consider as valid responses (default "200-299")
      --successfulonly              Only show successful attempts

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --retries int          Number of attempts per credential pair
      --sleep int            Sleep time between requests (seconds)
      --targets strings      The URL of target
      --timeout int          Timeout per request (seconds) (default 30)
  -v, --verbose              Verbose output
```


### Multi

Perform injection tests in the multiple locations of a target

#### Usage

```bash
methodwebtest general multi --targets https://example.com --injectionlocation HEADER --method GET --eventtype XSSALERT --variabledata '{"test":"test"}'
```

#### Help Text

```bash
methodwebtest general multi -h            
Perform injection tests in the multiple locations of a target

Usage:
  methodwebtest general multi [flags]

Flags:
      --eventtype string           The event type to test: XSSALERT, SQLIBOOLEAN, SQLIESCAPE, SQLITIMEDELAY
  -h, --help                       help for multi
      --injectionlocation string   The injection location to test: HEADER, PATH, QUERY, BODY, FORM, MULTIPART
      --method string              The HTTP method to use for the request
      --variabledata string        Json string of variable names and base values to add to injects

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --retries int          Number of attempts per credential pair
      --sleep int            Sleep time between requests (seconds)
      --targets strings      The URL of target
      --timeout int          Timeout per request (seconds) (default 30)
  -v, --verbose              Verbose output
```
