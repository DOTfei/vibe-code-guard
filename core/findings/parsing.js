function parseJsonLoose(text) {
  const value = String(text || '').trim();
  if (!value) return null;
  try {
    return JSON.parse(value);
  } catch {
    const firstObject = value.indexOf('{');
    const lastObject = value.lastIndexOf('}');
    if (firstObject >= 0 && lastObject > firstObject) {
      try { return JSON.parse(value.slice(firstObject, lastObject + 1)); } catch { /* continue */ }
    }
    const firstArray = value.indexOf('[');
    const lastArray = value.lastIndexOf(']');
    if (firstArray >= 0 && lastArray > firstArray) {
      try { return JSON.parse(value.slice(firstArray, lastArray + 1)); } catch { /* continue */ }
    }
  }
  return null;
}

function parseJsonLines(text) {
  return String(text || '').split('\n').map((line) => parseJsonLoose(line)).filter(Boolean);
}

module.exports = { parseJsonLoose, parseJsonLines };
