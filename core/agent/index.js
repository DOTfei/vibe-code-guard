const projectConfig = require('./project-config');
const toolchain = require('./toolchain');
const lifecycle = require('./tool-lifecycle');

module.exports = { ...projectConfig, ...toolchain, ...lifecycle };
