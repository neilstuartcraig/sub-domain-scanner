#!/usr/bin/env node

"use strict";
// See https://github.com/yargs/yargs/blob/master/docs/advanced.md#commanddirdirectory-opts for info on the structure of command modules

import yargs from "yargs";

yargs
.commandDir("yargs-cmds")
.demandCommand(1, `Please specify a commamd (see above for details and usage example)`)
.help("help")
.wrap(yargs.terminalWidth())
.strict(true)
.completion("completion", "generate a bash/zsh(/etc.) command completion script. Run `sub-domain-scanner completion >> ~/.bashrc && source ~/.bashrc` (for bash) or `sub-domain-scanner completion >> ~/.zshrc && source ~/.zshrc` (for zsh) to enable it for the current user") // Add a pseudo command named "completion" which generates a bashrc compliant script to enabled CLI command completion for sub-domain-scanner
.argv;