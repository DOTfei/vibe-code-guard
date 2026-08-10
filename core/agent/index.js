const projectConfig = require('./project-config');
const toolchain = require('./toolchain');

module.exports = { ...projectConfig, ...toolchain };
