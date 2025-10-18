# go-yara

A lexical analyzer for the YARA language, implemented in Go.

## Overview

This project provides a lexer for the YARA rule language. It tokenizes YARA rule files into a stream of tokens, which can then be used by a parser or other analysis tools.

## Features

*   **YARA Language Support**: Tokenizes the complete YARA language, including all keywords, operators, and literals.
*   **Error Recovery**: Includes mechanisms for recovering from syntax errors.
*   **Performance**: Optimized for performance, using techniques such as memory pooling and string interning.

## Installation

To use go-yara in your project, you can use `go get`:

```bash
go get github.com/cawalch/go-yara
```

## Usage

The following example demonstrates how to use the lexer to tokenize a YARA rule.

```go
package main

import (
	"fmt"
	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

func main() {
	input := `rule ExampleRule {
    meta:
        author = "Example"
    strings:
        $a = "malware"
    condition:
        $a
}`

	l := lexer.New(input)
	for {
		tok := l.NextToken()
		if tok.Type == token.EOF {
			break
		}
		fmt.Println(tok)
	}
}
```

### Lexer Example

This example shows how to create a new lexer and tokenize a simple YARA rule.

```go
l := lexer.New("rule test { condition: true }")

// Get tokens one by one
tok1 := l.NextToken()
tok2 := l.NextToken()
tok3 := l.NextToken()

fmt.Printf("First token: %s\n", tok1.String())
fmt.Printf("Second token: %s\n", tok2.String())
fmt.Printf("Third token: %s\n", tok3.String())
// Output:
// First token: {RULE "rule" @ 1:1}
// Second token: {IDENTIFIER "test" @ 1:6}
// Third token: {LBRACE "{" @ 1:11}
```

## Command-Line Tool

The project includes a command-line tool for lexing YARA files.

To use it, run the following command:

```bash
go run ./cmd/main.go ./examples/phase3_demo.yar
```

## Contributing

Contributions are welcome. Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License.
