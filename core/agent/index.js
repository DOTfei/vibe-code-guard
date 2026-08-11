const projectConfig = require('./project-config');
const toolchain = require('./toolchain');
const lifecycle = require('./tool-lifecycle');
const contracts = require('./contracts');

module.exports = { ...projectConfig, ...toolchain, ...lifecycle, ...contracts };
