# Nginx

The `methodwebtest nginx` command tests a target for Nginx specific vulnerabilities.

## Usage

```bash
methodwebtest nginx [command]
```

## Commands

### Header

#### Usage

```bash
methodwebtest nginx header [command]
```

#### Commands

##### Bufferoverflow

Perform a buffer overflow test using the content header of a target

###### Usage

```bash
methodwebtest nginx header bufferoverflow --targets https://example.com --bodysize 5000 --timeout 30
```

#### Help Text

```bash
% method nginx header bufferoverflow -h
Perform a buffer overflow test in the content header of a target

Usage:
  methodwebtest nginx header bufferoverflow [flags]

Flags:
      --bodysize int   The size of the body to send (default 5000)
  -h, --help           help for bufferoverflow

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
methodwebtest nginx path [command]
```

#### Commands

##### Traversal

Perform Nginx specific path traversal injection tests against a target

###### Usage

```bash
methodwebtest nginx path traversal --targets https://example.com --ignore-base-content-match false --responsecodes 200-299 --successfulonly
```

###### Help Text

```bash
% methodwebtest nginx path traversal  -h
Perform a Nginx specific path traversal for common file locations

Usage:
  methodwebtest nginx path traversal [flags]

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

### Query

#### Usage

```bash
methodwebtest nginx query [command]
```

#### Commands

##### Reverseproxy

Perform Nginx specific reverse proxy injection tests against a target

###### Usage

```bash
methodwebtest nginx query reverseproxy --targets https://example.com --redirectaddress 127.0.0.1
```

###### Help Text

```bash
% method nginx query reverseproxy -h
Perform injection tests in the reverse proxy of a target

Usage:
  methodwebtest nginx query reverseproxy [flags]

Flags:
  -h, --help                     help for reverseproxy
      --redirectaddress string   Specifies the target address for redirection (default "127.0.0.1")

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