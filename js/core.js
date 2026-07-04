/* ============================================================
   X-Ray Analyzer — Core Utilities & API Helpers
   js/core.js
   ============================================================ */

'use strict';

// Brand: Cyber X-Ray

// ═══════════════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════════════
const CONFIG = {
  VT_API_KEY: '7e2ca33ee2cd53947bf74e35b4a261e2cbff594949c33fcf5977a13e0d66b13d',
  SCREENSHOT_KEY: 'key=4baabf',
};

// ═══════════════════════════════════════════════════════════
// NAVIGATION
// ═══════════════════════════════════════════════════════════
const XRay = {
  currentPage: null,
  navigate(page) {
    // Update nav active state
    document.querySelectorAll('.nav-item').forEach(el =>
      el.classList.toggle('active', el.dataset.page === page));
    // Show/hide pages
    document.querySelectorAll('.pg').forEach(el =>
      el.style.display = el.id === 'pg-' + page ? 'block' : 'none');
    this.currentPage = page;
    // Update topbar title
    const titles = {
      dashboard:   'Dashboard',
      url:         'Full Website Scan',
      email:       'Email Header Analyzer',
      whois:       'Who Owns This Domain?',
      dns:         'DNS Records Lookup',
      geo:         'Trace Server Location',
      ssl:         'SSL Certificate Check',
      virustotal:  'Virus & Blacklist Check',
      screenshot:  'Safe Site Preview',
      network:     'Network & Subdomains',
      history:     'Scan History',
    };
    const titleEl = document.getElementById('topbar-title');
    if (titleEl) titleEl.textContent = titles[page] || 'Cyber X-Ray';
    // Update mobile topbar title
    const mobileTitle = document.getElementById('mobile-page-title');
    if (mobileTitle) mobileTitle.textContent = titles[page] || 'Cyber X-Ray';
    // Load data for pages that need a fresh fetch on every visit
    if (page === 'history' && typeof loadHistory === 'function') loadHistory();
    // Auto-close sidebar on mobile
    if (window.innerWidth < 768) {
      const sb  = document.getElementById('sidebar');
      const ov  = document.getElementById('sidebar-overlay');
      if (sb) sb.classList.remove('open');
      if (ov) ov.classList.remove('open');
      document.body.style.overflow = '';
    }
    // Scroll content to top on navigation
    const content = document.querySelector('.content');
    if (content) content.scrollTop = 0;
    window.scrollTo(0, 0);
  }
};

// ═══════════════════════════════════════════════════════════
// RENDER HELPERS
// ═══════════════════════════════════════════════════════════
function renderLoading(msg = 'Analyzing…') {
  return `<div class="loading"><div class="spinner"></div><span>${msg}</span></div>`;
}

function renderError(msg) {
  return `<div class="flags" style="margin-top:8px">${renderFlag('danger', msg)}</div>`;
}

function renderEmpty(msg = 'Enter a value above and click Analyze to see results.') {
  return `<div class="empty-state">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg><div>${msg}</div></div>`;
}

function renderFlag(level, text) {
  const icons = {
    danger:  `<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>`,
    warning: `<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>`,
    safe:    `<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>`,
    info:    `<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>`,
  };
  return `<div class="flag flag-${level}">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
         stroke-linecap="round" stroke-linejoin="round"
         style="width:15px;height:15px;flex-shrink:0;margin-top:2px">
      ${icons[level] || icons.info}
    </svg><span>${text}</span></div>`;
}

function renderVerdictBanner(verdict, summary) {
  const v   = (verdict || '').toUpperCase();
  const cls = v === 'SAFE' ? 'safe' : v === 'DANGEROUS' || v === 'MALICIOUS' ? 'danger' : 'warning';
  const icon = v === 'SAFE'
    ? `<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/>`
    : (v === 'DANGEROUS' || v === 'MALICIOUS')
    ? `<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>`
    : `<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>`;
  const color = v === 'SAFE' ? 'var(--safe)' : (v === 'DANGEROUS' || v === 'MALICIOUS') ? 'var(--danger)' : 'var(--warning)';
  const dispVerdict = v === 'DANGEROUS' ? 'MALICIOUS' : v;
  return `<div class="verdict-banner ${cls} fade-in">
    <svg viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2"
         stroke-linecap="round" stroke-linejoin="round">${icon}</svg>
    <div>
      <div class="verdict-label">${dispVerdict || 'UNKNOWN'}</div>
      <div class="verdict-sub">${summary || ''}</div>
    </div></div>`;
}

function renderTable(rows) {
  const trs = rows.map(([k, v]) =>
    `<tr><td>${k}</td><td>${v ?? '<span class="text-muted">—</span>'}</td></tr>`
  ).join('');
  return `<table class="data-table"><tbody>${trs}</tbody></table>`;
}

function formatDate(val) {
  if (!val || val === '—') return '—';
  try {
    const d = Array.isArray(val) ? new Date(val[0]) : new Date(val);
    if (isNaN(d.getTime())) return String(val);
    return d.toLocaleDateString('en-GB', { year:'numeric', month:'short', day:'2-digit' });
  } catch { return String(val); }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ═══════════════════════════════════════════════════════════
// DOMAIN / IP UTILITIES
// ═══════════════════════════════════════════════════════════
function extractDomain(input) {
  try {
    const u = /^https?:\/\//i.test(input) ? input : 'https://' + input;
    return new URL(u).hostname.replace(/^www\./i, '');
  } catch {
    return input.trim().replace(/^www\./i, '').split('/')[0].split('?')[0];
  }
}

function normalizeURL(input) {
  return /^https?:\/\//i.test(input) ? input : 'https://' + input;
}

function escapeHtml(str) {
  return String(str ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[c]));
}

function getFlagEmoji(code) {
  if (!code || code.length !== 2) return '';
  try {
    return String.fromCodePoint(
      ...[...code.toUpperCase()].map(c => 0x1F1E6 - 65 + c.charCodeAt(0))
    );
  } catch { return ''; }
}
// Expose to window explicitly so modules.js can always access it
window.escapeHtml          = escapeHtml;
window.getFlagEmoji        = getFlagEmoji;
window.renderLoading       = renderLoading;
window.renderError         = renderError;
window.renderEmpty         = renderEmpty;
window.renderFlag          = renderFlag;
window.renderVerdictBanner = renderVerdictBanner;
window.renderTable         = renderTable;
window.formatDate          = formatDate;
window.extractDomain       = extractDomain;
window.normalizeURL        = normalizeURL;
window.sleep               = sleep;


// ═══════════════════════════════════════════════════════════
// API: WHOIS
// ═══════════════════════════════════════════════════════════
async function fetchWHOIS(domain) {
  const requestedDomain = domain;
  const labels = String(domain || '').toLowerCase().replace(/^www\./, '').split('.').filter(Boolean);
  if (labels.length > 2) domain = labels.slice(-2).join('.');

  // ── HELPERS ──
  const getVcard = (arr, key) => {
    if (!Array.isArray(arr)) return '';
    for (const e of arr) {
      if (Array.isArray(e) && e[0] === key) {
        const val = e[3];
        if (!val || val === '') return '';
        if (typeof val === 'object' && val.type) return JSON.stringify(val);
        return String(val);
      }
    }
    return '';
  };

  const getEntities = (entities, role) =>
    (entities || []).filter(e => (e.roles || []).includes(role));

  const getPhone = (vc) => {
    if (!Array.isArray(vc)) return '';
    for (const e of vc) {
      if (Array.isArray(e) && e[0] === 'tel') return e[3] || '';
    }
    return '';
  };

  const getAddress = (vc) => {
    if (!Array.isArray(vc)) return '';
    for (const e of vc) {
      if (Array.isArray(e) && e[0] === 'adr') {
        const parts = e[3];
        if (Array.isArray(parts)) return parts.filter(Boolean).join(', ');
        return String(parts || '');
      }
    }
    return '';
  };

  const getCountry = (vc) => {
    if (!Array.isArray(vc)) return '';
    for (const e of vc) {
      if (Array.isArray(e) && e[0] === 'adr') {
        const v = e[3];
        if (Array.isArray(v)) return v[6] || v[5] || '';
      }
    }
    return '';
  };

  const compact = (value) => {
    if (value === undefined || value === null || value === '') return '';
    if (Array.isArray(value)) return value.filter(v => v !== undefined && v !== null && v !== '').join(', ') || '';
    if (typeof value === 'object') return JSON.stringify(value);
    return String(value);
  };

  // Mark a field: if empty → '—', if redacted → '🔒 REDACTED'
  const isRedacted = (v) => /redacted|privacy|protect|withheld|not disclosed|data protected/i.test(String(v));
  const labelField = (v) => {
    if (!v || v === '' || v === '—') return '—';
    if (isRedacted(v)) return `🔒 ${v}`;
    return v;
  };

  // ── Recursively flatten all entities ──
  const flattenAllEntities = (entities) => {
    const result = [];
    for (const e of (entities || [])) {
      result.push(e);
      if (e.entities && e.entities.length) {
        result.push(...flattenAllEntities(e.entities));
      }
    }
    return result;
  };

  // ── Extract full vcard entries as readable object ──
  const getVcardEntries = (vc) => {
    const out = {};
    if (!Array.isArray(vc)) return out;
    for (const e of vc) {
      if (!Array.isArray(e) || !e[0]) continue;
      const key = e[0];
      const value = e[3];
      if (!out[key]) out[key] = [];
      if (key === 'adr' && Array.isArray(value)) out[key].push(value.filter(Boolean).join(', '));
      else out[key].push(compact(value));
    }
    return out;
  };

  // ── Summarize a single entity for the All Contacts table ──
  const summarizeEntity = (entity) => {
    const vc = entity?.vcardArray?.[1] || [];
    const card = getVcardEntries(vc);
    const nameFromPubIds = (entity?.publicIds || []).map(p => p.identifier).filter(Boolean).join(', ');
    const rawName = compact(card.fn || card.org) || nameFromPubIds || entity?.handle || '';
    return {
      handle: entity?.handle || '—',
      roles: compact(entity?.roles) || '—',
      name: labelField(rawName),
      email: labelField(compact(card.email)),
      phone: labelField(compact(card.tel)),
      address: labelField(compact(card.adr)),
      contactUri: compact(card['contact-uri']),
      publicIds: compact((entity?.publicIds || []).map(p => `${p.type || 'ID'}: ${p.identifier || '—'}`)),
      links: compact((entity?.links || []).map(l => l.href).filter(Boolean)),
      remarks: compact((entity?.remarks || []).map(r => `${r.title || 'Remark'}: ${(r.description || []).join(' ')}`)),
    };
  };

  // ── Build the full summarized RDAP object ──
  const summarizeRdap = (d) => {
    const allEntities = flattenAllEntities(d.entities);
    return {
      objectClassName: d.objectClassName || '—',
      handle: d.handle || '—',
      ldhName: d.ldhName || '—',
      unicodeName: d.unicodeName || d.ldhName || '—',
      rdapConformance: compact(d.rdapConformance),
      port43: d.port43 || '—',
      events: (d.events || []).map(e => ({ action: e.eventAction || '—', date: e.eventDate || '—', actor: e.eventActor || '—' })),
      links: (d.links || []).map(l => ({ rel: l.rel || '—', href: l.href || '—', type: l.type || '—', title: l.title || '—' })),
      notices: (d.notices || []).map(n => ({ title: n.title || 'Notice', description: compact(n.description), links: compact((n.links || []).map(l => l.href)) })),
      remarks: (d.remarks || []).map(r => ({ title: r.title || 'Remark', description: compact(r.description), links: compact((r.links || []).map(l => l.href)) })),
      publicIds: (d.publicIds || []).map(p => ({ type: p.type || 'ID', identifier: p.identifier || '—' })),
      nameservers: (d.nameservers || []).map(n => ({
        name: n.ldhName || n.unicodeName || '—',
        handle: n.handle || '—',
        status: compact(n.status) || '—',
        ipAddresses: compact([...(n.ipAddresses?.v4 || []), ...(n.ipAddresses?.v6 || [])]) || '—',
      })),
      entities: allEntities.map(summarizeEntity),
      secureDNS: {
        delegationSigned: d.secureDNS?.delegationSigned === true ? 'Yes' : d.secureDNS?.delegationSigned === false ? 'No' : '—',
        zoneSigned: d.secureDNS?.zoneSigned === true ? 'Yes' : d.secureDNS?.zoneSigned === false ? 'No' : '—',
        maxSigLife: d.secureDNS?.maxSigLife || '—',
        dsData: compact((d.secureDNS?.dsData || []).map(ds => `keyTag ${ds.keyTag}, alg ${ds.algorithm}, digest ${ds.digest}`)) || '—',
        keyData: compact((d.secureDNS?.keyData || []).map(k => `flags ${k.flags}, alg ${k.algorithm}, publicKey ${k.publicKey}`)) || '—',
      },
    };
  };

  // ── Build the full result object from a raw RDAP response ──
  const buildResult = (d, source) => {
    const allEntities = flattenAllEntities(d.entities);

    // Registrar
    const registrar = getEntities(allEntities, 'registrar')[0];
    const registrarVc = registrar?.vcardArray?.[1] || [];
    const registrarVcName = getVcard(registrarVc, 'fn');
    const registrarPubName = (registrar?.publicIds || []).map(p => p.identifier).filter(Boolean)[0] || '';
    const registrarName = registrarVcName || registrarPubName || registrar?.handle || '—';
    const registrarUrl = (registrar?.links || []).find(l => l.rel === 'about' || l.rel === 'self' || l.type === 'text/html')?.href || '—';
    const registrarIANA = registrar?.publicIds?.find(p => p.type === 'IANA Registrar ID')?.identifier || registrar?.publicIds?.[0]?.identifier || '—';

    // Abuse
    const abuseEnt = getEntities(allEntities, 'abuse')[0];
    const abuseVc = abuseEnt?.vcardArray?.[1] || [];
    const abuseEmail = getVcard(abuseVc, 'email');
    const abusePhone = getPhone(abuseVc);

    // Registrant
    const registrantEnt = getEntities(allEntities, 'registrant')[0];
    const registrantVc = registrantEnt?.vcardArray?.[1] || [];
    const registrantName = getVcard(registrantVc, 'fn');
    const registrantOrg = getVcard(registrantVc, 'org');
    const registrantEmail = getVcard(registrantVc, 'email');
    const registrantPhone = getPhone(registrantVc);
    const registrantAddress = getAddress(registrantVc);
    const registrantCountry = getCountry(registrantVc);

    // Tech / Admin
    const techEnt = getEntities(allEntities, 'technical')[0];
    const adminEnt = getEntities(allEntities, 'administrative')[0];
    const techVc = techEnt?.vcardArray?.[1] || [];
    const adminVc = adminEnt?.vcardArray?.[1] || [];

    // Detect privacy
    const isPrivacyProtected = !registrantEnt
      || isRedacted(registrantName)
      || isRedacted(registrantEmail)
      || (!registrantName && !registrantOrg && !registrantEmail);

    return {
      domain: d.ldhName || domain,
      // Registrar
      registrarName: labelField(registrarName),
      registrarUrl,
      registrarIANA,
      registrarAbuseEmail: labelField(abuseEmail),
      registrarAbusePhone: labelField(abusePhone),
      // Dates
      created: (d.events || []).find(e => e.eventAction === 'registration')?.eventDate || '—',
      expires: (d.events || []).find(e => e.eventAction === 'expiration')?.eventDate || '—',
      updated: (d.events || []).find(e => e.eventAction === 'last changed')?.eventDate
        || (d.events || []).find(e => e.eventAction === 'last update of RDAP database')?.eventDate || '—',
      // Registrant
      registrantName: labelField(registrantName),
      registrantOrg: labelField(registrantOrg),
      registrantEmail: labelField(registrantEmail),
      registrantPhone: labelField(registrantPhone),
      registrantAddress: labelField(registrantAddress),
      registrantCountry: labelField(registrantCountry),
      isPrivacyProtected,
      // Tech / Admin
      techName: labelField(getVcard(techVc, 'fn')),
      techEmail: labelField(getVcard(techVc, 'email')),
      techPhone: labelField(getPhone(techVc)),
      adminName: labelField(getVcard(adminVc, 'fn')),
      adminEmail: labelField(getVcard(adminVc, 'email')),
      adminPhone: labelField(getPhone(adminVc)),
      // Domain info
      nameservers: (d.nameservers || []).map(n => n.ldhName || n.unicodeName).filter(Boolean).join('\n') || '—',
      status: (Array.isArray(d.status) ? d.status : [d.status || '—']).filter(Boolean).join(', '),
      dnssec: d.secureDNS?.delegationSigned ? 'Signed' : 'Unsigned',
      source,
      rdap: summarizeRdap(d),
      rawRdap: d,
      // Legacy compat
      registrar: labelField(registrarName),
      owner: labelField(registrantName),
      email: labelField(registrantEmail),
      country: labelField(registrantCountry),
    };
  };

  // ── FETCH STRATEGY ──
  // Step 1: Fetch from rdap.org (Verisign registry — basic data)
  let registryData = null;
  let registrarRdapUrl = null;

  try {
    const r = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`,
      { signal: AbortSignal.timeout(12000) });
    if (r.ok) {
      registryData = await r.json();
      // Extract registrar's own RDAP URL from the 'related' link
      registrarRdapUrl = (registryData.links || []).find(l => l.rel === 'related')?.href || null;
    }
  } catch (_) {}

  // Step 2: Follow the registrar's RDAP link to get FULL data (registrant, tech, admin)
  if (registrarRdapUrl) {
    try {
      const r2 = await fetch(registrarRdapUrl, { signal: AbortSignal.timeout(10000) });
      if (r2.ok) {
        const registrarData = await r2.json();
        // Merge: registrar response has more entities, but registry has nameservers/status
        const merged = { ...registrarData };
        if (!merged.nameservers?.length && registryData.nameservers?.length) {
          merged.nameservers = registryData.nameservers;
        }
        if (!merged.status?.length && registryData.status?.length) {
          merged.status = registryData.status;
        }
        if (!merged.secureDNS && registryData.secureDNS) {
          merged.secureDNS = registryData.secureDNS;
        }
        if ((merged.events || []).length < (registryData.events || []).length) {
          merged.events = registryData.events;
        }
        // Merge entities from both sources (deduplicate by role)
        const mergedEntities = [...(merged.entities || [])];
        const existingRoles = new Set(mergedEntities.flatMap(e => e.roles || []));
        for (const re of (registryData.entities || [])) {
          const roles = re.roles || [];
          if (!roles.some(r => existingRoles.has(r))) {
            mergedEntities.push(re);
          }
        }
        merged.entities = mergedEntities;
        merged.notices = [...(merged.notices || []), ...(registryData.notices || [])];
        return buildResult(merged, `RDAP (${new URL(registrarRdapUrl).hostname})`);
      }
    } catch (_) {}
  }

  // Step 3: If registrar RDAP failed, use the registry data we already have
  if (registryData) {
    return buildResult(registryData, 'RDAP (rdap.org)');
  }

  // Step 4: IANA bootstrap fallback
  try {
    const bootstrap = await fetch('https://data.iana.org/rdap/dns.json',
      { signal: AbortSignal.timeout(8000) }).then(res => res.ok ? res.json() : null);
    const tld = domain.split('.').pop();
    const entry = (bootstrap?.services || []).find(svc => (svc[0] || []).includes(tld));
    let base = entry?.[1]?.[0];
    if (base) {
      if (!base.endsWith('/')) base += '/';
      const r = await fetch(`${base}domain/${encodeURIComponent(domain)}`,
        { signal: AbortSignal.timeout(10000) });
      if (r.ok) {
        const d = await r.json();
        return buildResult(d, `RDAP (${new URL(base).hostname})`);
      }
    }
  } catch (_) {}

  throw new Error(`WHOIS lookup failed for "${requestedDomain}". Tried registered domain "${domain}". Try again in 30 seconds.`);
}

// ═══════════════════════════════════════════════════════════
// API: DNS
// ═══════════════════════════════════════════════════════════
async function fetchDNS(domain, type = 'A') {
  const res = await fetch(
    `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}`,
    { headers: { Accept: 'application/dns-json' }, signal: AbortSignal.timeout(8000) }
  );
  if (!res.ok) throw new Error(`DNS query failed (HTTP ${res.status})`);
  return res.json();
}

// ═══════════════════════════════════════════════════════════
// API: IP GEOLOCATION
// ═══════════════════════════════════════════════════════════
async function fetchGeo(ip) {
  try {
    const r = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`,
      { signal: AbortSignal.timeout(8000) });
    if (r.ok) {
      const d = await r.json();
      if (!d.error && d.latitude) {
        return {
          status: 'success', query: d.ip || ip,
          country: d.country_name || '—', countryCode: d.country_code || '',
          regionName: d.region || '—', city: d.city || '—',
          lat: d.latitude, lon: d.longitude,
          isp: d.org || '—', org: d.org || '—', as: d.asn || '—',
          proxy: false, hosting: false
        };
      }
    }
  } catch(_) {}

  try {
    const r = await fetch(`https://freeipapi.com/api/json/${encodeURIComponent(ip)}`,
      { signal: AbortSignal.timeout(8000) });
    if (r.ok) {
      const d = await r.json();
      if (d.latitude) {
        return {
          status: 'success', query: d.ipAddress || ip,
          country: d.countryName || '—', countryCode: d.countryCode || '',
          regionName: d.regionName || '—', city: d.cityName || '—',
          lat: d.latitude, lon: d.longitude,
          isp: d.isp || '—', org: d.isp || '—', as: '—',
          proxy: false, hosting: false
        };
      }
    }
  } catch(_) {}

  throw new Error(`Could not geolocate IP "${ip}". The IP may be private or the service is rate-limited.`);
}

// ═══════════════════════════════════════════════════════════


// ═══════════════════════════════════════════════════════════
// API: VIRUSTOTAL (hardcoded key)
// ═══════════════════════════════════════════════════════════
async function fetchVirusTotal(urlOrDomain) {
  const apiKey = CONFIG.VT_API_KEY;
  if (!apiKey || apiKey.includes('PUT_')) throw new Error('VirusTotal API key is missing.');

  const normalized = normalizeURL(urlOrDomain);
  const id = btoa(normalized)
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  const getUrlReport = async () => {
    const res = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
      headers: { 'x-apikey': apiKey },
      signal: AbortSignal.timeout(20000)
    });
    if (res.ok) return res.json();
    if (res.status === 401) throw new Error('VirusTotal API key is invalid.');
    if (res.status === 429) throw new Error('VirusTotal rate limit reached. Wait 60 seconds.');
    return null;
  };

  const existing = await getUrlReport();
  const existingStats = existing?.data?.attributes?.last_analysis_stats;
  if (existingStats && Object.values(existingStats).some(Number)) return existing;

  const form = new FormData();
  form.append('url', normalized);
  const subRes = await fetch('https://www.virustotal.com/api/v3/urls', {
    method: 'POST',
    headers: { 'x-apikey': apiKey },
    body: form,
    signal: AbortSignal.timeout(20000)
  });
  if (!subRes.ok) {
    const err = await subRes.json().catch(() => ({}));
    throw new Error(err?.error?.message || `VirusTotal submission failed (HTTP ${subRes.status})`);
  }

  const subJson = await subRes.json();
  const analysisId = subJson?.data?.id;
  if (!analysisId) throw new Error('VirusTotal did not return an analysis ID.');

  for (let i = 0; i < 18; i++) {
    await sleep(3000);
    const anRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: { 'x-apikey': apiKey },
      signal: AbortSignal.timeout(15000)
    });
    if (anRes.ok) {
      const anData = await anRes.json();
      if (anData?.data?.attributes?.status === 'completed') return anData;
    }
    if (anRes.status === 429) throw new Error('VirusTotal rate limit reached. Wait 60 seconds.');
  }

  const finalReport = await getUrlReport();
  if (finalReport?.data?.attributes?.last_analysis_stats) return finalReport;
  throw new Error('VirusTotal scan is still processing. Wait a minute and export again.');
}

// ═══════════════════════════════════════════════════════════
// API: VIRUSTOTAL — IP Reputation
// ═══════════════════════════════════════════════════════════
async function fetchVTIP(ip) {
  const apiKey = CONFIG.VT_API_KEY;
  if (!ip || !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) throw new Error('Invalid IP address');
  // Skip private/loopback IPs
  if (/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.)/.test(ip)) throw new Error('Private IP — not checked');
  const res = await fetch(
    `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`,
    { headers: { 'x-apikey': apiKey }, signal: AbortSignal.timeout(12000) }
  );
  if (!res.ok) {
    if (res.status === 401) throw new Error('VT API key invalid');
    if (res.status === 429) throw new Error('VT rate limit — wait 60s');
    throw new Error(`VT IP check failed (HTTP ${res.status})`);
  }
  return res.json();
}

// ═══════════════════════════════════════════════════════════
// API: SCREENSHOT (ScreenshotMachine with key)
// ═══════════════════════════════════════════════════════════
function getScreenshotUrls(url) {
  const encoded = encodeURIComponent(normalizeURL(url));
  return [
    `https://api.screenshotmachine.com/?${CONFIG.SCREENSHOT_KEY}&url=${encoded}&dimension=1280x800&format=png&cacheLimit=0`,
    `https://image.thum.io/get/width/1280/crop/800/noanimate/${normalizeURL(url)}`,
    `https://mini.s-shot.ru/1280x800/PNG/1280/Z100/?${normalizeURL(url)}`,
  ];
}



// ═══════════════════════════════════════════════════════════
// MAP RENDERER
// ═══════════════════════════════════════════════════════════
function renderLeafletMap(elId, lat, lon, label, ip) {
  const el = document.getElementById(elId);
  if (!el || typeof L === 'undefined') return;
  try {
    const map = L.map(elId, { zoomControl: true }).setView([lat, lon], 8);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      attribution: '© OpenStreetMap © CARTO', maxZoom: 18
    }).addTo(map);
    const icon = L.divIcon({
      html: `<div style="background:#f75a5a;width:14px;height:14px;border-radius:50%;border:2px solid #fff;box-shadow:0 0 12px rgba(247,90,90,0.9)"></div>`,
      iconSize: [14,14], iconAnchor: [7,7], className: ''
    });
    L.marker([lat, lon], { icon }).addTo(map)
      .bindPopup(`<b style="color:#111">${ip}</b><br><span style="color:#444">${label}</span>`, { maxWidth: 200 })
      .openPopup();
  } catch(e) { console.warn('Map render error:', e); }
}
window.renderLeafletMap = renderLeafletMap;
