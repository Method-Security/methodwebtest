# methodwebtest Documentation

Hello and welcome to the methodwebtest documentation. While we always want to provide the most comprehensive documentation possible, we thought you may find the below sections a helpful place to get started.

- The [Getting Started](./getting-started/basic-usage.md) section provides onboarding material
- The [Development](./development/setup.md) header is the best place to get started on developing on top of and with methodwebtest
- See the [Docs](./docs/index.md) section for a comprehensive rundown of methodwebtest capabilities

# About methodwebtest

methodwebtest is designed as a simple, easy to use web application scanning tool that security teams can use to automate the collection of data about their web applications. Designed with data-modeling and data-integration needs in mind, methodwebtest can be used on its own as an interactive CLI, orchestrated as part of a broader data pipeline, or leveraged from within the Method Platform.

The types of scans that methodwebtest can conduct are constantly growing. For the most up to date listing, please see the documentation [here](./docs/index.md)

To learn more about methodwebtest, please see the [Documentation site](https://method-security.github.io/methodwebtest/) for the most detailed information.

## Quick Start

### Get methodwebtest

For the full list of available installation options, please see the [Installation](./getting-started/installation.md) page. For convenience, here are some of the most commonly used options:

- `docker run methodsecurity/methodwebtest`
- `docker run ghcr.io/method-security/methodwebtest`
- Download the latest binary from the [Github Releases](https://github.com/Method-Security/methodwebtest/releases/latest) page
- [Installation documentation](./getting-started/installation.md)

### Examples

```bash
methodwebtest nginx query reverseproxy --targets https://example.com,https://example.dev --redirectaddress 127.0.0.1
```

```bash
methodwebtest apache path traversal --targets https://example.com
```

## Contributing

Interested in contributing to methodwebtest? Please see our organization wide [Contribution](https://method-security.github.io/community/contribute/discussions.html) page.

## Want More?

If you're looking for an easy way to tie methodwebtest into your broader cybersecurity workflows, or want to leverage some autonomy to improve your overall security posture, you'll love the broader Method Platform.

For more information, visit us [here](https://method.security)

## Community

methodwebtest is a Method Security open source project.

Learn more about Method's open source source work by checking out our other projects [here](https://github.com/Method-Security) or our organization wide documentation [here](https://method-security.github.io).

Have an idea for a Tool to contribute? Open a Discussion [here](https://github.com/Method-Security/Method-Security.github.io/discussions).
