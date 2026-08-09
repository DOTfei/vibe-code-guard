#!/usr/bin/env node

const fs = require('node:fs');

const [input, output] = process.argv.slice(2);
if (!input || !output) {
  console.error('Usage: node scripts/animate-diagram.js input.svg output.svg');
  process.exit(1);
}

const svg = fs.readFileSync(input, 'utf8');
const motion = `
<style>
  #diagram-1 .flowchart-link {
    stroke-dasharray: 12 8 !important;
    animation: vibe-code-guard-flow 2.4s linear infinite;
  }
  @keyframes vibe-code-guard-flow {
    to { stroke-dashoffset: -40; }
  }
  @media (prefers-reduced-motion: reduce) {
    #diagram-1 .flowchart-link {
      animation: none !important;
      stroke-dasharray: none !important;
    }
  }
</style>`;

if (!svg.includes('<svg') || !svg.includes('</style>')) {
  throw new Error('Input does not look like a rendered SVG diagram.');
}

fs.writeFileSync(output, svg.replace('</style>', `</style>${motion}`));
