#!/usr/bin/env node


"use strict";
// See https://github.com/yargs/yargs/blob/master/docs/advanced.md#commanddirdirectory-opts for info on the structure of command modules

var _yargs = require("yargs");

var _yargs2 = _interopRequireDefault(_yargs);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

_yargs2.default.commandDir("yargs-cmds").demandCommand(1, `Please specify a commamd (see above for details and usage example)`).help("help").wrap(_yargs2.default.terminalWidth()).strict(true).completion("completion", "generate a bash/zsh(/etc.) command completion script. Run `sub-domain-scanner completion >> ~/.bashrc && source ~/.bashrc` (for bash) or `sub-domain-scanner completion >> ~/.zshrc && source ~/.zshrc` (for zsh) to enable it for the current user") // Add a pseudo command named "completion" which generates a bashrc compliant script to enabled CLI command completion for sub-domain-scanner
.argv;