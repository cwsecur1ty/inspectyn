#!/usr/bin/env node
import { main } from '../src/cli.mjs';

process.stdout.on('error', error => { if (error.code === 'EPIPE') process.exit(0); throw error; });
process.exitCode = await main(process.argv.slice(2));
