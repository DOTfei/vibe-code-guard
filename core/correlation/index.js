const confidence = require('./confidence');
const keys = require('./correlation-key');
const lifecycle = require('./lifecycle');
const identity = require('./project-identity');
const correlator = require('./correlator');

module.exports = { ...confidence, ...keys, ...lifecycle, ...identity, ...correlator };
