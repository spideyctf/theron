// Original, offline URL controls. Never load or execute target application code.
import assert from 'node:assert/strict';

const base = 'https://app.invalid/';
const vectors = [
  ['//other.invalid/', 'https://other.invalid'],
  ['/\\other.invalid/', 'https://other.invalid'],
  ['/safe/?q=//other.invalid/', 'https://app.invalid'],
  ['/safe/\\other.invalid/', 'https://app.invalid'],
  ['/?//other.invalid/', 'https://app.invalid'],
  ['/#//other.invalid/', 'https://app.invalid'],
  ['https://fixed.invalid/path/\\other.invalid/', 'https://fixed.invalid'],
  ['https://fixed.invalid.other.invalid/', 'https://fixed.invalid.other.invalid'],
];
for (const [input, expected] of vectors) {
  assert.equal(new URL(input, base).origin, expected);
}

// Pure string control matching the operation being assessed, without importing its project.
const input = '/\\other.invalid/';
let start = 0, end = input.length;
while (input[start] === '/') start++;
while (end > start && input[end - 1] === '/') end--;
const rooted = '/' + input.slice(start, end);
assert.equal(new URL(rooted, base).origin, 'https://other.invalid');

const prefixes = ['/safe/', '/?q=', '/#view=', 'https://fixed.invalid/items/'];
const payloads = ['//other.invalid/', '\\other.invalid/', '/\\other.invalid/', '../..//other.invalid/',
  'https://other.invalid/', '@other.invalid/', '?next=//other.invalid/', '#//other.invalid/',
  '\r\n//other.invalid/', '\t\\other.invalid/', '%2F%2Fother.invalid/', '%5Cother.invalid/'];
for (const prefix of prefixes) {
  for (const payload of payloads) {
    assert.equal(new URL(prefix + payload, base).origin, new URL(prefix, base).origin);
  }
}
process.stdout.write(JSON.stringify({node:process.version,explicit_vectors:vectors.length,
  strip_then_root_counterexamples:1,prefix_payload_checks:prefixes.length*payloads.length,
  inputs:input,rooted,rooted_origin:new URL(rooted, base).origin,
  target_code_executed:false,network_requests:0},null,2)+'\n');
