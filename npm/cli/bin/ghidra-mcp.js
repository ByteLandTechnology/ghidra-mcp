#!/usr/bin/env node
// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

// Starts the native ghidra-mcp executable from the platform package.
// MCP clients use stdio, thus the child process uses the same streams.

'use strict';

const { spawn } = require('node:child_process');

const RELEASES = 'https://github.com/ByteLandTechnology/ghidra-mcp/releases';

// Each key is "<process.platform>-<process.arch>".
// Each value is the npm package that holds the executable for that platform.
const PACKAGES = {
  'darwin-arm64': '@ghidra-mcp/darwin-arm64',
  'darwin-x64': '@ghidra-mcp/darwin-x64',
  'linux-arm64': '@ghidra-mcp/linux-arm64',
  'linux-x64': '@ghidra-mcp/linux-x64',
  'win32-arm64': '@ghidra-mcp/win32-arm64',
  'win32-x64': '@ghidra-mcp/win32-x64',
};

/** Returns the path of the native executable, or stops the process with an error. */
function findExecutable() {
  const key = `${process.platform}-${process.arch}`;
  const name = PACKAGES[key];
  if (!name) {
    fail(`ghidra-mcp has no npm package for ${key}.`);
  }
  const file = process.platform === 'win32' ? 'ghidra-mcp.exe' : 'ghidra-mcp';
  try {
    return require.resolve(`${name}/bin/${file}`);
  } catch {
    fail(
      `The package ${name} is not installed. ` +
        'Do not use --omit=optional or --no-optional when you install @ghidra-mcp/cli.',
    );
  }
}

/** Writes an error message and stops the process. */
function fail(message) {
  process.stderr.write(`${message}\nYou can download an executable from ${RELEASES}\n`);
  process.exit(1);
}

const child = spawn(findExecutable(), process.argv.slice(2), { stdio: 'inherit' });

child.on('error', (error) => {
  fail(`Cannot start ghidra-mcp: ${error.message}`);
});

// Send termination signals to the child. The child decides when to stop.
// A terminal sends SIGINT to the full process group, thus the child can get it two times.
const SIGNALS = ['SIGINT', 'SIGTERM', 'SIGHUP'];
for (const signal of SIGNALS) {
  process.on(signal, () => {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill(signal);
    }
  });
}

// Exit as the child exits, so that the caller gets the same status.
child.on('exit', (code, signal) => {
  if (signal) {
    // Remove the handlers, so that Node.js does the default action for the signal.
    for (const name of SIGNALS) {
      process.removeAllListeners(name);
    }
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 1);
});
