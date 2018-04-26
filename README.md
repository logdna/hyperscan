# Node Hyperscan
> The node module provides C bindings for Intel's fast hyperscan library.

[![NPM Version][npm-image]][npm-url]

"Hyperscan is a high-performance multiple regex matching library. [...] Hyperscan uses hybrid automata techniques to allow simultaneous matching of large numbers (up to tens of thousands) of regular expressions and for the matching of regular expressions across streams of data" - [intel/hyperscan](https://github.com/intel/hyperscan)

This module provides performance oriented C bindings for the hyperscan library, and offers access to a subset of hyperscan's features to node developers.

## Installation

OS X & Linux:

```sh
npm install -s hyperscan
```

## Usage Example

_For more examples and usage, please refer to the [Wiki][wiki]._

## Development Setup

Here we should describe installation and how to run tests

```sh
npm test
```

## Release History

* 0.0.1
    * Work in progress

## Contributing

1. Fork it (<https://github.com/intel/hyperscan>)
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -S -am "Add some fooBar"`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Create a new Pull Request

<!-- Markdown link & img dfn's -->
[npm-image]: https://img.shields.io/npm/v/hyperscan.svg?style=flat-square
[npm-url]: https://www.npmjs.com/package/hyperscan
[wiki]: https://github.com/logdna/hyperscan
