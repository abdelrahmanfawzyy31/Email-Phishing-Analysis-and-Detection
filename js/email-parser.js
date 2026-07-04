/* ============================================================
   X-Ray Analyzer — Email Parser
   js/email-parser.js
   ============================================================ */

'use strict';

/**
 * Parses raw email headers into an object where keys are header names.
 * @param {string} raw - Raw email headers text
 * @returns {Object} - Parsed headers with helper methods
 */
function parseEmailHeaders(raw) {
  const h = {};
  const lines = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const unfolded = lines.replace(/\n[ \t]+/g, ' ');
  unfolded.split('\n').forEach(line => {
    const colon = line.indexOf(':');
    if (colon > 0) {
      const key = line.substring(0, colon).trim().toLowerCase();
      const val = line.substring(colon + 1).trim();
      if (!h[key]) h[key] = [];
      h[key].push(val);
    }
  });
  h._get = (key) => (h[key.toLowerCase()] || [])[0] || '—';
  h._all = (key) => (h[key.toLowerCase()] || []);
  return h;
}

/**
 * Extracts IPs and hop metadata from Received headers.
 * @param {string} raw - Raw email headers text
 * @returns {Array} - Array of hop objects
 */
function extractReceivedHops(raw) {
  const hops = [];
  const lines = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const blocks = [];
  let block = '', inReceived = false;
  lines.split('\n').forEach(line => {
    if (/^received:/i.test(line)) { if (block) blocks.push(block); block = line; inReceived = true; }
    else if (inReceived && /^[ \t]/.test(line)) { block += ' ' + line.trim(); }
    else { if (block) { blocks.push(block); block = ''; } inReceived = false; }
  });
  if (block) blocks.push(block);
  blocks.forEach(line => {
    const fromM = line.match(/from\s+([^\s(]+)/i);
    const byM   = line.match(/by\s+([^\s(]+)/i);
    const ipsM  = line.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g);
    const tsM   = line.match(/;\s*(.+)$/);
    hops.push({
      from: fromM?.[1] || '—',
      by:   byM?.[1]   || '—',
      ips:  ipsM || [],
      time: tsM?.[1]?.trim().substring(0,40) || '—',
    });
  });
  return hops;
}

/**
 * Extracts up to 5 unique URLs from raw header text.
 * @param {string} raw - Raw email headers text
 * @returns {Array} - Array of unique URLs
 */
function extractURLsFromHeaders(raw) {
  const matches = raw.match(/https?:\/\/[^\s<>"'\]\)]+/gi) || [];
  return [...new Set(matches)].slice(0, 5); // max 5 unique URLs
}

// Expose globally for modules.js
window.parseEmailHeaders = parseEmailHeaders;
window.extractReceivedHops = extractReceivedHops;
window.extractURLsFromHeaders = extractURLsFromHeaders;
