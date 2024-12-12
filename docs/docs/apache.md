# Apache

The `methodwebtest apache` command tests a target for Apache specific vulnerabilities.

## Usage

```bash
methodwebtest apache [command]
```

## Commands

### Path 

#### Usage

```bash
methodwebtest apache path [command]
```

#### Commands

##### Modfile

Perform modfile injection tests against a target

###### Usage

```bash
methodwebtest apache path modfile --targets https://example.com
```

###### Help Text

```bash
methodwebtest apache path modfile -h
Perform modfile injection tests in the path of a target

Usage:
  methodwebtest apache path modfile [flags]

Flags:
  -h, --help   help for modfile

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
methodwebtest apache path traversal --targets https://example.com --ignore-base-content-match false --responsecodes 200-299 --successfulonly
```

###### Help Text

```bash
methodwebtest apache path traversal  -h
Perform a Apache specific path traversal for common file locations

Usage:
  methodwebtest apache path traversal [flags]

Flags:
  -h, --help                        help for traversal
      --ignore-base-content-match   Ignores valid responses with identical size and word length to the base path, typically signifying a web backend redirect (default true)
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