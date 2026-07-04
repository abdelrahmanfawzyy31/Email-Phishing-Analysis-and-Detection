/* ============================================================
   X-Ray Analyzer — Analysis Modules
   js/modules.js
   ============================================================ */

'use strict';

// ── Fallback: define escapeHtml if core.js hasn't loaded it yet ──
if (typeof escapeHtml !== 'function') {
  window.escapeHtml = function escapeHtml(str) {
    return String(str ?? '').replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
  };
}

// ═══════════════════════════════════════════════════════════


// ═══════════════════════════════════════════════════════════
// WHOIS
// ═══════════════════════════════════════════════════════════
async function runWHOIS() {
  const input = (document.getElementById('whois-input')?.value || '').trim();
  if (!input) return;
  const domain = extractDomain(input);
  const out = document.getElementById('whois-result');
  out.innerHTML = renderLoading(`Looking up WHOIS for <b>${domain}</b>…`);

  try {
    const w = await fetchWHOIS(domain);

    // ── Domain age calculation ──
    const createdRaw = w.created || '—';
    const createdDate = Array.isArray(createdRaw) ? createdRaw[0] : createdRaw;
    let ageDays = null, ageFlag = '';
    if (createdDate && createdDate !== '—') {
      ageDays = Math.floor((Date.now() - new Date(createdDate)) / 86400000);
      if (!isNaN(ageDays)) {
        if (ageDays < 30)
          ageFlag = renderFlag('danger', `Domain registered only ${ageDays} day(s) ago — newly registered domains are frequently used in phishing attacks.`);
        else if (ageDays < 180)
          ageFlag = renderFlag('warning', `Domain is ${ageDays} days old (${Math.floor(ageDays/30)} months) — relatively young, proceed with caution.`);
        else
          ageFlag = renderFlag('safe', `Domain age: ${Math.floor(ageDays/365)} year(s) ${Math.floor((ageDays%365)/30)} month(s) — established domain.`);
      }
    }

    // ── Privacy / redacted check ──
    const isPrivate = (v) => !v || v === '—' || /privacy|redacted|protect|withheld|not disclosed/i.test(String(v));
    const privacyFlag = isPrivate(w.registrantName)
      ? renderFlag('warning', 'Registrant identity is hidden behind a privacy protection service — common with newly-registered phishing domains.')
      : '';

    // ── DNSSEC flag ──
    const dnssecFlag = w.dnssec === 'Signed'
      ? renderFlag('safe', 'DNSSEC is signed — DNS responses for this domain are cryptographically authenticated.')
      : renderFlag('info', 'DNSSEC is unsigned — DNS responses are not cryptographically verified.');

    // ── Format nameservers as list ──
    const nsLines = (w.nameservers || '—').split('\n').filter(Boolean);
    const nsHtml  = nsLines.length > 1
      ? nsLines.map(ns => `<span class="font-mono" style="display:block;font-size:11px">${ns}</span>`).join('')
      : `<span class="font-mono" style="font-size:11px">${nsLines[0] || '—'}</span>`;

    // ── Status badges ──
    const statusList = (w.status || '—').split(',').map(s => s.trim()).filter(Boolean);
    const statusHtml = statusList.map(s =>
      `<span class="pill" style="margin-right:4px;margin-bottom:4px;font-size:10px">${s}</span>`
    ).join('');

    const apiJson = escapeHtml(JSON.stringify(w.rawRdap || w.rdap || {}, null, 2));
    const rdap = w.rdap || {};
    const rdapEvents = (rdap.events || []).map(e => [e.action || '—', formatDate(e.date || '—'), e.actor || '—']);
    const rdapEntities = (rdap.entities || []).map(e => [
      e.roles || '—', e.name || '—', e.email || '—', e.phone || '—', e.address || '—', e.handle || '—'
    ]);
    const rdapNameservers = (rdap.nameservers || []).map(n => [n.name || '—', n.handle || '—', n.status || '—', n.ipAddresses || '—']);
    const rdapLinks = (rdap.links || []).map(l => [l.rel || '—', l.type || '—', l.href || '—']);
    const rdapNotices = [...(rdap.notices || []), ...(rdap.remarks || [])].map(n => [n.title || '—', n.description || '—', n.links || '—']);

    const renderRows = (rows, emptyText = 'No data returned by API') => rows.length
      ? rows.map(row => `<tr>${row.map(cell => `<td>${String(cell || '—').startsWith('http') ? `<a href="${escapeHtml(cell)}" target="_blank" style="color:var(--accent);word-break:break-all">${escapeHtml(cell)}</a>` : escapeHtml(cell)}</td>`).join('')}</tr>`).join('')
      : `<tr><td colspan="6" class="text-muted">${emptyText}</td></tr>`;

    const allApiHtml = '';

    out.innerHTML = `<div class="fade-in">

      <!-- Overview Stats -->
      <div class="result-grid" style="margin-bottom:20px">
        <div class="stat-card">
          <div class="stat-card-label">Domain</div>
          <div class="stat-card-value font-mono" style="font-size:13px">${w.domain || domain}</div>
        </div>
        <div class="stat-card">
          <div class="stat-card-label">Domain Age</div>
          <div class="stat-card-value" style="font-size:13px;color:${ageDays !== null ? (ageDays < 30 ? 'var(--danger)' : ageDays < 180 ? 'var(--warning)' : 'var(--safe)') : 'var(--text)'}">
            ${ageDays !== null ? (ageDays < 365 ? `${ageDays}d` : `${Math.floor(ageDays/365)}y ${Math.floor((ageDays%365)/30)}m`) : '—'}
          </div>
        </div>
        <div class="stat-card">
          <div class="stat-card-label">Registered</div>
          <div class="stat-card-value" style="font-size:13px">${formatDate(createdDate)}</div>
        </div>
        <div class="stat-card">
          <div class="stat-card-label">Expires</div>
          <div class="stat-card-value" style="font-size:13px">${formatDate(w.expires || '—')}</div>
        </div>
      </div>

      <!-- ── REGISTRAR INFORMATION ── -->
      <div style="margin-bottom:18px">
        <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--accent);margin-bottom:10px;display:flex;align-items:center;gap:8px">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:14px;height:14px"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/></svg>
          Registrar Information
        </div>
        ${renderTable([
          ['Registrar Name',   w.registrarName  || '—'],
          ['IANA ID',          w.registrarIANA  || '—'],
          ['Registrar URL',    w.registrarUrl && w.registrarUrl !== '—' ? `<a href="${w.registrarUrl}" target="_blank" style="color:var(--accent);font-size:12px">${w.registrarUrl}</a>` : '—'],
          ['Abuse Email',      w.registrarAbuseEmail || '—'],
          ['Abuse Phone',      w.registrarAbusePhone || '—'],
          ...(w.registrarAbuseLink ? [['Abuse Report', `<a href="${w.registrarAbuseLink}" target="_blank" style="color:var(--danger);font-size:12px">${w.registrarAbuseLink}</a>`]] : []),
        ])}
      </div>

      <hr class="divider"/>

      <!-- ── REGISTRANT CONTACT ── -->
      <div style="margin-bottom:18px">
        <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--accent2);margin-bottom:10px;display:flex;align-items:center;gap:8px">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:14px;height:14px"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
          Registrant Contact ${w.isPrivacyProtected ? '<span style="color:var(--warning);font-size:10px;margin-left:8px">🔒 PRIVACY PROTECTED</span>' : ''}
        </div>
        ${renderTable([
          ['Name',         w.registrantName    || '—'],
          ['Organization', w.registrantOrg     || '—'],
          ['Email',        w.registrantEmail   || '—'],
          ['Phone',        w.registrantPhone   || '—'],
          ['Address',      w.registrantAddress || '—'],
          ['Country',      w.registrantCountry || '—'],
        ])}
        ${w.isPrivacyProtected ? `<div class="flag flag-warning" style="margin-top:8px"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:14px;height:14px;flex-shrink:0"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg><span>Registrant details are privacy-protected or redacted by the registrar. Fields marked with 🔒 are intentionally hidden.</span></div>` : ''}
      </div>

      <hr class="divider"/>

      <!-- ── TECHNICAL CONTACT ── -->
      <div style="margin-bottom:18px">
        <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--info);margin-bottom:10px;display:flex;align-items:center;gap:8px">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:14px;height:14px"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
          Technical Contact
        </div>
        ${renderTable([
          ['Name',  w.techName  || '—'],
          ['Email', w.techEmail || '—'],
          ['Phone', w.techPhone || '—'],
        ])}
      </div>

      <hr class="divider"/>

      <!-- ── ADMIN CONTACT ── -->
      <div style="margin-bottom:18px">
        <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--warning);margin-bottom:10px;display:flex;align-items:center;gap:8px">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:14px;height:14px"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          Administrative Contact
        </div>
        ${renderTable([
          ['Name',  w.adminName  || '—'],
          ['Email', w.adminEmail || '—'],
          ['Phone', w.adminPhone || '—'],
        ])}
      </div>

      <hr class="divider"/>

      <!-- ── DOMAIN DATES ── -->
      <div style="margin-bottom:18px">
        <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--info);margin-bottom:10px;display:flex;align-items:center;gap:8px">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:14px;height:14px"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
          Important Dates
        </div>
        ${renderTable([
          ['Registration Date', formatDate(createdDate)],
          ['Last Updated',      formatDate(w.updated || '—')],
          ['Expiration Date',   formatDate(w.expires || '—')],
        ])}
      </div>

      <hr class="divider"/>

      <!-- ── TECHNICAL DETAILS ── -->
      <div style="margin-bottom:18px">
        <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:10px;display:flex;align-items:center;gap:8px">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:14px;height:14px"><path d="M9 17H7A5 5 0 0 1 7 7h2"/><path d="M15 7h2a5 5 0 0 1 0 10h-2"/><line x1="8" y1="12" x2="16" y2="12"/></svg>
          Technical Details
        </div>
        <table class="data-table">
          <tbody>
            <tr><td>Name Servers</td><td>${nsHtml}</td></tr>
            <tr><td>Domain Status</td><td>${statusHtml || '—'}</td></tr>
            <tr><td>DNSSEC</td><td>${w.dnssec || '—'}</td></tr>
            <tr><td>Source</td><td><span class="font-mono" style="font-size:11px">${w.source || 'RDAP'}</span></td></tr>
          </tbody>
        </table>
      </div>

      ${allApiHtml}

      <!-- FLAGS -->
      <div class="flags">${ageFlag}${privacyFlag}${dnssecFlag}</div>

    </div>`;

  } catch(e) {
    out.innerHTML = renderError(e.message);
  }
}


async function runDNS() {
  const input = (document.getElementById('dns-input')?.value || '').trim();
  const type  = document.getElementById('dns-type')?.value || 'A';
  if (!input) return;
  const domain = extractDomain(input);
  const out    = document.getElementById('dns-result');
  out.innerHTML = renderLoading(`Querying ${type} records for <b>${domain}</b>…`);

  try {
    const data    = await fetchDNS(domain, type);
    const answers = data.Answer || [];
    const rcode   = data.Status;

    if (rcode === 3 || answers.length === 0) {
      out.innerHTML = `<div class="fade-in"><div class="flags">${
        renderFlag('warning', `No ${type} records found for <b>${domain}</b>. The domain may not exist or this record type is not configured.`)
      }</div></div>`;
      return;
    }

    const typeMap = {1:'A',28:'AAAA',15:'MX',16:'TXT',5:'CNAME',2:'NS',6:'SOA',33:'SRV'};
    const rows = answers.map(a => [
      `<span class="pill">${typeMap[a.type] || type}</span>`,
      `<span class="font-mono" style="word-break:break-all">${a.data}</span>`,
      `${a.TTL}s`
    ]);

    const ips = answers.filter(a => a.type === 1).map(a => a.data);
    let ipFlag = ips.length
      ? renderFlag('info', `Resolved IPs: ${ips.join(', ')} — use the IP Geolocation tool to trace the server location.`)
      : '';

    const txts = answers.filter(a => a.type === 16).map(a => a.data);
    let spfFlag = '';
    if (type === 'TXT' && txts.length) {
      const spf = txts.find(t => t.includes('v=spf1'));
      const dmarc = txts.find(t => t.includes('v=DMARC1'));
      spfFlag = spf
        ? renderFlag('safe', 'SPF record found — domain has email sender policy configured.')
        : renderFlag('warning', 'No SPF record in TXT records — this domain may be spoofable in phishing emails.');
      if (dmarc) spfFlag += renderFlag('safe', 'DMARC record found — domain has email authentication policy.');
    }

    out.innerHTML = `<div class="fade-in">
      <table class="data-table">
        <thead><tr><th>Type</th><th>Value</th><th>TTL</th></tr></thead>
        <tbody>${rows.map(r=>`<tr>${r.map(c=>`<td>${c}</td>`).join('')}</tr>`).join('')}</tbody>
      </table>
      <div class="flags" style="margin-top:12px">${ipFlag}${spfFlag}</div>
    </div>`;
  } catch(e) {
    out.innerHTML = renderError(e.message);
  }
}

// ═══════════════════════════════════════════════════════════
// IP GEOLOCATION
// ═══════════════════════════════════════════════════════════
async function runGeo() {
  const input = (document.getElementById('geo-input')?.value || '').trim();
  if (!input) return;
  const out = document.getElementById('geo-result');
  const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(input);
  out.innerHTML = renderLoading(isIP ? `Locating IP <b>${input}</b>…` : `Resolving <b>${input}</b> and locating server…`);

  try {
    let target = input;
    if (!isIP) {
      const domain = extractDomain(input);
      const dns = await fetchDNS(domain, 'A');
      const aRecord = (dns.Answer || []).find(r => r.type === 1);
      if (!aRecord) throw new Error(`Could not resolve "${domain}" to an IP address.`);
      target = aRecord.data;
    }

    const data = await fetchGeo(target);
    if (data.status === 'fail') throw new Error(data.message || 'Geolocation lookup failed');

    const isProxy  = data.proxy || data.hosting;
    const proxyFlag = isProxy
      ? renderFlag('danger', 'This IP is flagged as a proxy, VPN, or hosting server — attackers commonly use these to mask their real location.')
      : renderFlag('safe', 'IP does not appear to be a known proxy or VPN.');

    out.innerHTML = `<div class="fade-in">
      <div class="result-grid">
        <div class="stat-card"><div class="stat-card-label">IP Address</div>
          <div class="stat-card-value font-mono" style="font-size:14px">${data.query || target}</div></div>
        <div class="stat-card"><div class="stat-card-label">Country</div>
          <div class="stat-card-value">${data.country || '—'} ${getFlagEmoji(data.countryCode)}</div></div>
        <div class="stat-card"><div class="stat-card-label">City / Region</div>
          <div class="stat-card-value" style="font-size:14px">${data.city || '—'}, ${data.regionName || '—'}</div></div>
        <div class="stat-card"><div class="stat-card-label">Proxy / Hosting</div>
          <div class="stat-card-value ${isProxy?'text-danger':'text-safe'}">${isProxy?'Yes ⚠':'No ✓'}</div></div>
      </div>
      ${renderTable([
        ['ISP', data.isp || '—'],
        ['Organization', data.org || '—'],
        ['AS Number', data.as || '—'],
        ['Coordinates', (data.lat && data.lon) ? `${data.lat}, ${data.lon}` : '—'],
        ['Hosting', data.hosting ? 'Yes' : 'No'],
      ])}
      <div class="flags" style="margin-top:12px">${proxyFlag}</div>
      <div id="geo-map" style="width:100%;height:300px;border-radius:10px;border:1px solid var(--border);margin-top:14px;background:var(--surface2)"></div>
    </div>`;

    if (data.lat && data.lon) {
      setTimeout(() => renderLeafletMap('geo-map', data.lat, data.lon, `${data.city||''}, ${data.country||''}`, data.query || target), 150);
    }
  } catch(e) {
    out.innerHTML = renderError(e.message);
  }
}

// ═══════════════════════════════════════════════════════════
// SSL CERTIFICATE
// ═══════════════════════════════════════════════════════════


// ═══════════════════════════════════════════════════════════
// VIRUSTOTAL (no API key input needed — hardcoded)
// ═══════════════════════════════════════════════════════════
async function runVT() {
  const input = (document.getElementById('vt-input')?.value || '').trim();
  if (!input) return;

  const out = document.getElementById('vt-result');
  out.innerHTML = renderLoading('Submitting to VirusTotal — checking 90+ security engines…');

  try {
    const data  = await fetchVirusTotal(input);
    const attrs = data?.data?.attributes || {};
    const stats = attrs.last_analysis_stats || attrs.stats || {};
    const results = attrs.last_analysis_results || attrs.results || {};

    const malicious  = stats.malicious  || 0;
    const suspicious = stats.suspicious || 0;
    const harmless   = stats.harmless   || 0;
    const undetected = stats.undetected || 0;
    const total      = malicious + suspicious + harmless + undetected + (stats.timeout || 0);

    const verdict = malicious > 5 ? 'MALICIOUS' : malicious > 0 || suspicious > 3 ? 'SUSPICIOUS' : 'SAFE';
    const summary = `${malicious} of ${total} security vendors flagged this URL as malicious.`;

    const flagged = Object.entries(results)
      .filter(([,v]) => v.category === 'malicious' || v.category === 'suspicious')
      .slice(0, 10);

    const flaggedRows = flagged.map(([engine, v]) =>
      `<tr>
        <td>${engine}</td>
        <td><span class="pill ${v.category === 'malicious' ? 'danger' : 'warning'}">${v.category}</span></td>
        <td class="font-mono" style="font-size:11px">${v.result || '—'}</td>
      </tr>`
    ).join('');

    out.innerHTML = `<div class="fade-in">
      ${renderVerdictBanner(verdict, summary)}
      <div class="result-grid" style="margin-bottom:18px">
        <div class="stat-card"><div class="stat-card-label">Malicious</div>
          <div class="stat-card-value text-danger" style="font-size:28px">${malicious}</div></div>
        <div class="stat-card"><div class="stat-card-label">Suspicious</div>
          <div class="stat-card-value text-warn" style="font-size:28px">${suspicious}</div></div>
        <div class="stat-card"><div class="stat-card-label">Clean / Safe</div>
          <div class="stat-card-value text-safe" style="font-size:28px">${harmless}</div></div>
        <div class="stat-card"><div class="stat-card-label">Total Engines</div>
          <div class="stat-card-value" style="font-size:28px">${total}</div></div>
      </div>
      ${flaggedRows
        ? `<div class="text-xs text-muted" style="margin-bottom:10px">Flagged by these engines:</div>
           <table class="data-table">
             <thead><tr><th>Engine</th><th>Category</th><th>Detection</th></tr></thead>
             <tbody>${flaggedRows}</tbody>
           </table>`
        : `<div class="flags">${renderFlag('safe','No security vendors flagged this URL as malicious.')}</div>`
      }
    </div>`;
  } catch(e) {
    out.innerHTML = renderError(e.message);
  }
}

// ═══════════════════════════════════════════════════════════
// NETWORK INTELLIGENCE (replaces SSH)
// Identifies related domains, subdomains, subnet/network info
// ═══════════════════════════════════════════════════════════
async function runNetwork() {
  const input = (document.getElementById('network-input')?.value || '').trim();
  if (!input) return;
  const domain = extractDomain(input);
  const out = document.getElementById('network-result');
  out.innerHTML = renderLoading(`Running network intelligence on <b>${domain}</b>…`);

  try {
    // Run all queries in parallel
    const [dnsA, dnsMX, dnsNS, dnsTXT, dnsCNAME, geoData] = await Promise.allSettled([
      fetchDNS(domain, 'A'),
      fetchDNS(domain, 'MX'),
      fetchDNS(domain, 'NS'),
      fetchDNS(domain, 'TXT'),
      fetchDNS(domain, 'CNAME'),
      (async () => {
        const aRes = await fetchDNS(domain, 'A');
        const ip = (aRes.Answer || []).find(r => r.type === 1)?.data;
        if (ip) return fetchGeo(ip);
        return null;
      })()
    ]);

    // --- IP & Subnet ---
    const aAnswers = dnsA.status === 'fulfilled' ? (dnsA.value.Answer || []) : [];
    const ips = aAnswers.filter(a => a.type === 1).map(a => a.data);

    let subnetHtml = '';
    if (ips.length) {
      const subnetRows = ips.map(ip => {
        const parts = ip.split('.').map(Number);
        const classA = `${parts[0]}.0.0.0/8`;
        const classB = `${parts[0]}.${parts[1]}.0.0/16`;
        const classC = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
        return `<tr>
          <td class="font-mono">${ip}</td>
          <td class="font-mono" style="font-size:11px">${classC}</td>
          <td class="font-mono" style="font-size:11px">${classB}</td>
        </tr>`;
      }).join('');
      subnetHtml = `
        <div style="margin-bottom:20px">
          <div class="section-badge">🌐 IP & Network Range</div>
          <table class="data-table">
            <thead><tr><th>IP Address</th><th>Class C Subnet (/24)</th><th>Class B Subnet (/16)</th></tr></thead>
            <tbody>${subnetRows}</tbody>
          </table>
          ${renderFlag('info', `Found ${ips.length} IP address(es) for this domain. The /24 subnet contains up to 254 hosts. If multiple malicious sites share a subnet, it may indicate a hosting provider used for phishing.`)}
        </div>`;
    }

    // --- Nameservers (related infra) ---
    const nsAnswers = dnsNS.status === 'fulfilled' ? (dnsNS.value.Answer || []) : [];
    const nameservers = nsAnswers.filter(a => a.type === 2).map(a => a.data.replace(/\.$/, ''));

    let nsHtml = '';
    if (nameservers.length) {
      const nsList = nameservers.map(ns => `<tr><td class="font-mono" style="font-size:12px">${ns}</td>
        <td style="font-size:12px;color:var(--muted)">${inferNsProvider(ns)}</td></tr>`).join('');
      nsHtml = `
        <div style="margin-bottom:20px">
          <div class="section-badge">🔧 Name Servers (DNS Infrastructure)</div>
          <table class="data-table">
            <thead><tr><th>Nameserver</th><th>Provider (inferred)</th></tr></thead>
            <tbody>${nsList}</tbody>
          </table>
          ${renderFlag('info', 'Nameservers reveal who manages DNS for this domain. Shared nameservers can link related domains from the same operator.')}
        </div>`;
    }

    // --- MX Records (mail servers) ---
    const mxAnswers = dnsMX.status === 'fulfilled' ? (dnsMX.value.Answer || []) : [];
    const mxRecords = mxAnswers.filter(a => a.type === 15).map(a => a.data);

    let mxHtml = '';
    if (mxRecords.length) {
      const mxList = mxRecords.map(mx => `<tr><td class="font-mono" style="font-size:12px">${mx}</td>
        <td style="font-size:12px;color:var(--muted)">${inferMailProvider(mx)}</td></tr>`).join('');
      mxHtml = `
        <div style="margin-bottom:20px">
          <div class="section-badge">📧 Mail Servers (MX Records)</div>
          <table class="data-table">
            <thead><tr><th>Mail Server</th><th>Provider (inferred)</th></tr></thead>
            <tbody>${mxList}</tbody>
          </table>
          ${mxRecords.length === 0 ? renderFlag('warning', 'No mail servers found — this domain cannot send or receive email legitimately.') : ''}
        </div>`;
    } else {
      mxHtml = `<div style="margin-bottom:20px">
        <div class="section-badge">📧 Mail Servers (MX Records)</div>
        ${renderFlag('warning', 'No MX records found. This domain has no legitimate mail infrastructure — suspicious if it claims to send emails.')}
      </div>`;
    }

    // --- Common Subdomains Probe ---
    const commonSubs = ['www', 'mail', 'webmail', 'login', 'secure', 'portal', 'admin', 'cpanel', 'ftp', 'api'];
    out.innerHTML = renderLoading(`Probing common subdomains for <b>${domain}</b>…`);

    const subResults = await Promise.allSettled(
      commonSubs.map(async (sub) => {
        const fullDomain = `${sub}.${domain}`;
        const res = await fetchDNS(fullDomain, 'A');
        const answers = res.Answer || [];
        const resolvedIps = answers.filter(a => a.type === 1).map(a => a.data);
        return { sub: fullDomain, ips: resolvedIps, found: resolvedIps.length > 0 };
      })
    );

    const foundSubs = subResults
      .filter(r => r.status === 'fulfilled' && r.value.found)
      .map(r => r.value);
    const notFoundCount = commonSubs.length - foundSubs.length;

    let subsHtml = '';
    if (foundSubs.length) {
      const subRows = foundSubs.map(s => `<tr>
        <td class="font-mono" style="font-size:12px">${s.sub}</td>
        <td class="font-mono" style="font-size:11px">${s.ips.join(', ')}</td>
        <td><span class="pill safe" style="font-size:10px">Active</span></td>
      </tr>`).join('');
      subsHtml = `
        <div style="margin-bottom:20px">
          <div class="section-badge">🔍 Associated Subdomains</div>
          <table class="data-table">
            <thead><tr><th>Subdomain</th><th>Resolves To</th><th>Status</th></tr></thead>
            <tbody>${subRows}</tbody>
          </table>
          ${renderFlag('info', `Found ${foundSubs.length} active subdomains out of ${commonSubs.length} probed. Active subdomains expand the attack surface of a domain.`)}
          ${foundSubs.some(s => /login|secure|portal|admin/.test(s.sub))
            ? renderFlag('warning', 'Subdomains like "login", "secure", or "portal" exist — these are commonly used to host phishing login pages.')
            : ''}
        </div>`;
    } else {
      subsHtml = `<div style="margin-bottom:20px">
        <div class="section-badge">🔍 Associated Subdomains</div>
        ${renderFlag('info', `None of the ${commonSubs.length} common subdomains (www, mail, login, etc.) are active.`)}
      </div>`;
    }

    // --- Geo summary ---
    let geoHtml = '';
    const geo = geoData.status === 'fulfilled' && geoData.value;
    if (geo && geo.status !== 'fail') {
      geoHtml = `
        <div style="margin-bottom:20px">
          <div class="section-badge">📍 Server Location</div>
          ${renderTable([
            ['IP', `<span class="font-mono">${geo.query || ips[0] || '—'}</span>`],
            ['Location', `${geo.city||'—'}, ${geo.regionName||'—'}, ${geo.country||'—'} ${getFlagEmoji(geo.countryCode)}`],
            ['ISP / Org', geo.isp || '—'],
            ['AS Number', geo.as || '—'],
          ])}
        </div>`;
    }

    // --- TXT / SPF summary ---
    const txtAnswers = dnsTXT.status === 'fulfilled' ? (dnsTXT.value.Answer || []) : [];
    const txts = txtAnswers.filter(a => a.type === 16).map(a => a.data);
    const hasSPF = txts.some(t => t.includes('v=spf1'));
    const hasDMARC = txts.some(t => t.includes('v=DMARC1'));
    let emailSecHtml = `
      <div style="margin-bottom:20px">
        <div class="section-badge">🛡️ Email Security Configuration</div>
        <div class="flags">
          ${hasSPF ? renderFlag('safe', 'SPF record found — domain has an email sender policy.') : renderFlag('danger', 'No SPF record — this domain can be easily spoofed in phishing emails.')}
          ${hasDMARC ? renderFlag('safe', 'DMARC record found — domain has an email authentication policy.') : renderFlag('warning', 'No DMARC record — emails from this domain may not be properly authenticated.')}
        </div>
      </div>`;

    out.innerHTML = `<div class="fade-in">
      ${subnetHtml}
      ${subsHtml}
      ${nsHtml}
      ${mxHtml}
      ${emailSecHtml}
      ${geoHtml}
    </div>`;

  } catch(e) {
    out.innerHTML = renderError(e.message);
  }
}

function inferNsProvider(ns) {
  if (/cloudflare/i.test(ns)) return 'Cloudflare';
  if (/awsdns/i.test(ns)) return 'Amazon AWS Route53';
  if (/google/i.test(ns)) return 'Google Cloud DNS';
  if (/azure/i.test(ns)) return 'Microsoft Azure';
  if (/domaincontrol/i.test(ns)) return 'GoDaddy';
  if (/registrar-servers/i.test(ns)) return 'Namecheap';
  if (/parkingcrew|sedoparking/i.test(ns)) return 'Parked Domain';
  return 'Unknown provider';
}

function inferMailProvider(mx) {
  if (/google|gmail/i.test(mx)) return 'Google Workspace';
  if (/outlook|microsoft|office365/i.test(mx)) return 'Microsoft 365';
  if (/yahoo/i.test(mx)) return 'Yahoo Mail';
  if (/protonmail/i.test(mx)) return 'ProtonMail';
  if (/mailgun/i.test(mx)) return 'Mailgun';
  if (/sendgrid/i.test(mx)) return 'SendGrid';
  if (/amazonses/i.test(mx)) return 'Amazon SES';
  return 'Custom mail server';
}

// ═══════════════════════════════════════════════════════════
// URL FULL SCAN
// ═══════════════════════════════════════════════════════════
async function runFullScan() {
  const input = (document.getElementById('url-scan-input')?.value || '').trim();
  if (!input) return;
  const domain = extractDomain(input);

  const btn = document.getElementById('full-scan-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Scanning…'; }

  try {
  const set = (id, html) => { const el = document.getElementById(id); if (el) el.innerHTML = html; };

  set('scan-vt',     renderLoading('Checking 90+ virus & blacklist engines…'));
  set('scan-whois',  renderLoading('WHOIS lookup…'));
  set('scan-dns',    renderLoading('DNS query…'));
  set('scan-geo',    renderLoading('IP Geolocation…'));
  set('scan-iprep',  renderLoading('IP reputation check…'));

  await Promise.allSettled([

    // ── VirusTotal (first result — full width) ──
    fetchVirusTotal(input).then(vt => {
      const attrs = vt?.data?.attributes || vt?.meta?.url_info || {};
      // handle both URL report and analysis report
      const stats = attrs.last_analysis_stats || attrs.stats || {};
      const malicious  = (stats.malicious  || 0);
      const suspicious = (stats.suspicious || 0);
      const harmless   = (stats.harmless   || 0);
      const undetected = (stats.undetected || 0);
      const total      = malicious + suspicious + harmless + undetected;

      const verdict = malicious >= 3 ? 'MALICIOUS' : malicious >= 1 || suspicious >= 3 ? 'SUSPICIOUS' : 'SAFE';
      const summary = malicious >= 3
        ? `Flagged as malicious by ${malicious} security engines out of ${total}.`
        : malicious >= 1 || suspicious >= 3
        ? `Detected as suspicious by ${malicious + suspicious} engine(s) — treat with caution.`
        : `Clean — no engines flagged this URL as malicious (${total} engines checked).`;

      const scoreColor = malicious >= 3 ? 'var(--danger)' : malicious >= 1 || suspicious >= 3 ? 'var(--warning)' : 'var(--safe)';

      // Build engine list (top flagging ones)
      const engines = attrs.last_analysis_results || {};
      const flagged = Object.entries(engines)
        .filter(([,v]) => v.category === 'malicious' || v.category === 'suspicious')
        .slice(0, 8)
        .map(([name, v]) => `<span class="pill ${v.category === 'malicious' ? 'danger' : 'warning'}" style="margin:2px;font-size:11px">${name}: ${v.result || v.category}</span>`)
        .join('');

      set('scan-vt', `<div class="fade-in">
        ${renderVerdictBanner(verdict, summary)}
        <div class="result-grid" style="margin-bottom:14px;grid-template-columns:repeat(4,1fr)">
          <div class="stat-card" style="border-top:3px solid var(--danger)">
            <div class="stat-card-label">Malicious</div>
            <div class="stat-card-value" style="font-size:28px;color:var(--danger)">${malicious}</div>
          </div>
          <div class="stat-card" style="border-top:3px solid var(--warning)">
            <div class="stat-card-label">Suspicious</div>
            <div class="stat-card-value" style="font-size:28px;color:var(--warning)">${suspicious}</div>
          </div>
          <div class="stat-card" style="border-top:3px solid var(--safe)">
            <div class="stat-card-label">Clean</div>
            <div class="stat-card-value" style="font-size:28px;color:var(--safe)">${harmless}</div>
          </div>
          <div class="stat-card">
            <div class="stat-card-label">Total Engines</div>
            <div class="stat-card-value" style="font-size:28px">${total}</div>
          </div>
        </div>
        ${flagged ? `<div style="margin-top:6px"><div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:8px">Flagged By</div><div style="display:flex;flex-wrap:wrap;gap:4px">${flagged}</div></div>` : ''}
      </div>`);

      if (window.__currentUser) {
        saveScanToHistory(window.__currentUser.uid, {
          type: 'url', input: input.substring(0,200),
          verdict, riskScore: Math.round((malicious/Math.max(total,1))*100), summary
        });
      }
    }).catch(e => set('scan-vt', renderError('VirusTotal: ' + e.message))),

    // ── WHOIS ──
    fetchWHOIS(domain).then(w => {
      const created   = w.created || w.creation_date || null;
      const owner     = w.owner || w.registrant_name || w.org || 'Hidden';
      const registrar = w.registrar || '—';
      let ageFlag = '';
      if (created) {
        const days = Math.floor((Date.now() - new Date(created)) / 86400000);
        if (!isNaN(days)) {
          ageFlag = days < 60
            ? renderFlag('danger',  `Domain only ${days} days old — high risk`)
            : renderFlag('safe', `Domain age: ${Math.floor(days/365)}y ${Math.floor((days%365)/30)}m`);
        }
      }
      set('scan-whois', `<div class="fade-in">
        ${renderTable([['Registrar', registrar], ['Owner', owner], ['Created', formatDate(created)]])}
        <div class="flags" style="margin-top:10px">${ageFlag}</div>
      </div>`);
    }).catch(e => set('scan-whois', renderError(e.message))),

    // ── DNS + Geo + IP Reputation (chained on resolved IP) ──
    fetchDNS(domain, 'A').then(async dns => {
      const answers = dns.Answer || [];
      const ips = answers.filter(a => a.type === 1).map(a => a.data);
      const rows = answers.slice(0,5).map(a => [
        `<span class="pill">${a.type===1?'A':a.type===5?'CNAME':a.type===2?'NS':'?'}</span>`,
        `<span class="font-mono" style="font-size:12px">${a.data}</span>`
      ]);
      set('scan-dns', `<div class="fade-in">${
        rows.length
          ? `<table class="data-table"><thead><tr><th>Type</th><th>Value</th></tr></thead>
             <tbody>${rows.map(r=>`<tr>${r.map(c=>`<td>${c}</td>`).join('')}</tr>`).join('')}</tbody></table>`
          : renderFlag('warning','No A records found')
      }</div>`);

      if (!ips.length) {
        set('scan-geo',   renderError('No IP resolved — cannot geolocate'));
        set('scan-iprep', renderError('No IP resolved'));
        return;
      }

      // Geo + IP reputation in parallel
      await Promise.allSettled([
        fetchGeo(ips[0]).then(geo => {
          if (geo.status === 'fail') throw new Error(geo.message || 'Geolocation failed');
          const isProxy = geo.proxy || geo.hosting;
          set('scan-geo', `<div class="fade-in">
            ${renderTable([
              ['IP', `<span class="font-mono">${geo.query || ips[0]}</span>`],
              ['Location', `${geo.city||'—'}, ${geo.regionName||'—'}, ${geo.country||'—'} ${getFlagEmoji(geo.countryCode)}`],
              ['ISP', geo.isp || '—'],
              ['Proxy/Hosting', isProxy ? '<span class="pill danger">Yes</span>' : '<span class="pill safe">No</span>'],
            ])}
            <div class="flags" style="margin-top:10px">
              ${isProxy ? renderFlag('danger','Proxy or hosting IP detected') : renderFlag('safe','Not a known proxy')}
            </div>
            <div id="geo-map-scan" style="width:100%;height:180px;border-radius:10px;border:1px solid var(--border);margin-top:12px;background:var(--surface2)"></div>
          </div>`);
          if (geo.lat && geo.lon)
            setTimeout(() => renderLeafletMap('geo-map-scan', geo.lat, geo.lon, `${geo.city||''}, ${geo.country||''}`, geo.query || ips[0]), 200);
        }).catch(e => set('scan-geo', renderError(e.message))),

        // IP Reputation via VirusTotal IP endpoint
        fetchVTIP(ips[0]).then(vtip => {
          const attrs = vtip?.data?.attributes || {};
          const stats = attrs.last_analysis_stats || {};
          const mal   = stats.malicious  || 0;
          const sus   = stats.suspicious || 0;
          const total = (stats.malicious||0)+(stats.suspicious||0)+(stats.harmless||0)+(stats.undetected||0);
          const rep   = attrs.reputation || 0;
          const country = attrs.country || '—';
          const asOwner = attrs.as_owner || '—';
          const cls = mal >= 3 ? 'danger' : mal >= 1 || sus >= 2 ? 'warning' : 'safe';
          const label = mal >= 3 ? 'Malicious IP' : mal >= 1 || sus >= 2 ? 'Suspicious IP' : 'Clean IP';
          set('scan-iprep', `<div class="fade-in">
            <div class="flags" style="margin-bottom:12px">${renderFlag(cls, `<b>${label}</b> — ${mal} engine(s) flagged this IP`)}</div>
            ${renderTable([
              ['IP Address',  `<span class="font-mono">${ips[0]}</span>`],
              ['Country',     country],
              ['AS Owner',    asOwner],
              ['VT Reputation', `<span style="color:${rep<0?'var(--danger)':rep>0?'var(--safe)':'var(--muted)'}">${rep}</span>`],
              ['Malicious',   `<span class="pill ${mal>0?'danger':'safe'}">${mal}/${total}</span>`],
            ])}
          </div>`);
        }).catch(e => set('scan-iprep', renderError('IP reputation: ' + e.message))),
      ]);
    }).catch(e => {
      set('scan-dns',   renderError(e.message));
      set('scan-geo',   renderError('DNS failed — cannot geolocate'));
      set('scan-iprep', renderError('DNS failed'));
    }),
  ]);

  } catch(e) {
    console.error('Full scan error:', e);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Scan Now'; }
  }
}

// ═══════════════════════════════════════════════════════════
// SCAN HISTORY
// ═══════════════════════════════════════════════════════════
async function loadHistory() {
  const out = document.getElementById('history-list');
  if (!out || !window.__currentUser) return;
  out.innerHTML = renderLoading('Loading your scan history…');
  try {
    const { getUserScans } = await import('./firebase.js');
    const scans = await getUserScans(window.__currentUser.uid, 30);
    if (!scans.length) {
      out.innerHTML = renderEmpty('No scans yet. Run your first analysis above.');
      return;
    }
    const rows = scans.map(s => {
      const dotColor = s.verdict === 'MALICIOUS' || s.verdict === 'DANGEROUS' ? 'var(--danger)' : s.verdict === 'SAFE' ? 'var(--safe)' : 'var(--warning)';
      const date = s.createdAt?.toDate
        ? s.createdAt.toDate().toLocaleString('en-GB',{dateStyle:'short',timeStyle:'short'})
        : '—';
      const v = s.verdict === 'DANGEROUS' ? 'MALICIOUS' : (s.verdict || '—');
      return `<tr>
        <td><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${dotColor};margin-right:8px"></span>
            <span class="font-mono" style="font-size:12px">${(s.input||'—').substring(0,60)}</span></td>
        <td><span class="pill ${v==='MALICIOUS'?'danger':v==='SAFE'?'safe':'warning'}">${v}</span></td>
        <td><span class="pill">${(s.type||'scan').toUpperCase()}</span></td>
        <td style="font-size:12px;color:var(--muted)">${s.riskScore != null ? s.riskScore+'/100' : '—'}</td>
        <td style="font-size:12px;color:var(--muted)">${date}</td>
      </tr>`;
    }).join('');
    out.innerHTML = `<table class="data-table">
      <thead><tr><th>Input</th><th>Verdict</th><th>Type</th><th>Risk</th><th>Date</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
  } catch(e) {
    out.innerHTML = renderError('Could not load history: ' + e.message);
  }
}

async function saveScanToHistory(uid, scanData) {
  try {
    const { saveScan } = await import('./firebase.js');
    await saveScan(uid, scanData);
  } catch(e) { console.warn('Could not save scan:', e.message); }
}

// ═══════════════════════════════════════════════════════════
// SCREENSHOT
// ═══════════════════════════════════════════════════════════
async function runScreenshot() {
  const input = (document.getElementById('ss-input')?.value || '').trim();
  if (!input) { document.getElementById('ss-input')?.focus(); return; }

  const url  = normalizeURL(input);
  const out  = document.getElementById('ss-result');
  const btn  = document.getElementById('ss-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Capturing…'; }

  out.innerHTML = `
    <div style="text-align:center;padding:40px 20px">
      <div class="spinner" style="width:32px;height:32px;border-width:3px;margin:0 auto 16px"></div>
      <div style="font-size:14px;color:var(--text);margin-bottom:6px">Capturing screenshot…</div>
      <div style="font-size:12px;color:var(--muted)">Rendering ${url} safely without opening it</div>
    </div>`;

  try {
    const ssUrls = getScreenshotUrls(url);
    const encodedUrl = encodeURIComponent(url);
    const domain = extractDomain(url);

    out.innerHTML = `<div class="fade-in">
      <div class="result-grid" style="margin-bottom:18px">
        <div class="stat-card">
          <div class="stat-card-label">Target URL</div>
          <div class="stat-card-value font-mono" style="font-size:12px;word-break:break-all">${url.substring(0,60)}${url.length>60?'…':''}</div>
        </div>
        <div class="stat-card">
          <div class="stat-card-label">Domain</div>
          <div class="stat-card-value font-mono" style="font-size:14px">${domain}</div>
        </div>
        <div class="stat-card">
          <div class="stat-card-label">Captured At</div>
          <div class="stat-card-value" style="font-size:13px">${new Date().toLocaleTimeString('en-GB')}</div>
        </div>
        <div class="stat-card">
          <div class="stat-card-label">Safe Preview</div>
          <div class="stat-card-value text-safe">No click needed ✓</div>
        </div>
      </div>

      <div class="flags" style="margin-bottom:18px">
        ${renderFlag('info', 'This is a remote screenshot — your browser never connects to the suspicious site.')}
        ${renderFlag('warning', 'Screenshots may be cached. Use timestamp to verify freshness.')}
      </div>

      <div style="background:var(--surface2);border:1px solid var(--border2);border-radius:12px;overflow:hidden">
        <div style="background:var(--surface3);padding:10px 14px;display:flex;align-items:center;gap:10px;border-bottom:1px solid var(--border)">
          <div style="display:flex;gap:6px">
            <div style="width:11px;height:11px;border-radius:50%;background:#f75a5a"></div>
            <div style="width:11px;height:11px;border-radius:50%;background:#f7a84f"></div>
            <div style="width:11px;height:11px;border-radius:50%;background:#4fca8b"></div>
          </div>
          <div style="flex:1;background:var(--surface2);border:1px solid var(--border2);border-radius:6px;padding:5px 12px;font-family:var(--mono);font-size:11px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
            🔍 ${url}
          </div>
          <a href="${url}" target="_blank" rel="noopener noreferrer"
             style="font-size:11px;color:var(--accent);text-decoration:none;flex-shrink:0;padding:4px 10px;border:1px solid rgba(79,142,247,.3);border-radius:5px"
             onclick="return confirm('You are about to visit a potentially malicious site. Proceed?')">
            Open (risky)
          </a>
        </div>

        <div style="position:relative;background:#1a1a2a;min-height:400px;display:flex;align-items:center;justify-content:center" id="ss-frame">
          <div id="ss-loading-inner" style="text-align:center;color:var(--muted);font-size:13px">
            <div class="spinner" style="width:24px;height:24px;margin:0 auto 10px"></div>
            Loading screenshot…
          </div>
          <img id="ss-img-0" src="${ssUrls[0]}"
               style="display:none;width:100%;max-height:600px;object-fit:contain"
               onload="ssLoaded(0)" onerror="ssFallback(0)"/>
          <img id="ss-img-1" src="" style="display:none;width:100%;max-height:600px;object-fit:contain"
               onload="ssLoaded(1)" onerror="ssFallback(1)"/>
          <img id="ss-img-2" src="" style="display:none;width:100%;max-height:600px;object-fit:contain"
               onload="ssLoaded(2)" onerror="ssAllFailed()"/>
        </div>

        <div style="padding:10px 14px;display:flex;align-items:center;border-top:1px solid var(--border)">
          <span style="font-size:11px;color:var(--muted)" id="ss-provider-label">Loading…</span>
          <div style="margin-left:auto;display:flex;gap:8px">
            <button onclick="document.getElementById('ss-img-0').src='${ssUrls[0]}?r='+Date.now()"
              style="font-size:11px;padding:4px 12px;border-radius:6px;border:1px solid var(--border2);background:var(--surface3);color:var(--muted);cursor:pointer">
              ↻ Refresh
            </button>
          </div>
        </div>
      </div>

      <div style="margin-top:18px" id="ss-ai-section">

      </div>
    </div>`;

    window._ssFallbackUrls = ssUrls;

  } catch(e) {
    out.innerHTML = renderError(e.message);
  }

  if (btn) { btn.disabled = false; btn.textContent = '📸 Capture Screenshot'; }
}

window.ssLoaded = function(idx) {
  document.getElementById('ss-loading-inner')?.remove();
  const img = document.getElementById(`ss-img-${idx}`);
  if (img) img.style.display = 'block';
  const labels = ['Screenshot Machine','Thum.io','Mini S-Shot'];
  const lbl = document.getElementById('ss-provider-label');
  if (lbl) lbl.textContent = `Screenshot by ${labels[idx] || 'provider ' + (idx+1)}`;
};

window.ssFallback = function(idx) {
  const next = idx + 1;
  const urls = window._ssFallbackUrls || [];
  const lbl  = document.getElementById('ss-loading-inner');
  if (lbl) lbl.innerHTML = `<div class="spinner" style="width:20px;height:20px;margin:0 auto 8px"></div>Trying provider ${next + 1}…`;
  const nextImg = document.getElementById(`ss-img-${next}`);
  if (nextImg && urls[next]) { nextImg.src = urls[next]; }
};

window.ssAllFailed = function() {
  const frame = document.getElementById('ss-loading-inner');
  if (frame) frame.innerHTML = `
    <div style="padding:32px;text-align:center">
      <div style="font-size:32px;margin-bottom:12px">🚫</div>
      <div style="font-size:14px;color:var(--text);margin-bottom:8px">Screenshot unavailable</div>
      <div style="font-size:12px;color:var(--muted);max-width:280px;margin:0 auto;line-height:1.6">
        All screenshot providers failed. The site may be blocking crawlers or is offline.
      </div>
    </div>`;
};



async function exportPDF() {
  const btn = document.getElementById('export-pdf-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Generating…'; }

  try {
    const sections = [
      { id: 'scan-vt',            title: 'Virus & Blacklist Check'  },
      { id: 'scan-whois',         title: 'Domain Owner (WHOIS)'     },
      { id: 'scan-dns',           title: 'DNS Records'              },
      { id: 'scan-iprep',         title: 'IP Reputation'            },
      { id: 'whois-result',       title: 'WHOIS Lookup'             },
      { id: 'dns-result',         title: 'DNS Records'              },
      { id: 'ssl-result',         title: 'SSL Certificate'          },
      { id: 'vt-result',          title: 'Virus & Blacklist Check'  },
      { id: 'network-result',     title: 'Network Intelligence'     },
      { id: 'email-auth-result',  title: 'Email Auth Checks'        },
      { id: 'email-ip-result',    title: 'Sender IP Reputation'     },
      { id: 'email-domain-result',title: 'Sender Domain WHOIS'      },
      { id: 'email-url-result',   title: 'Email URL Scan'           },
      { id: 'email-routing-result',title:'Email Routing Path'       },
    ];

    const target = document.getElementById('url-scan-input')?.value?.trim()
      || document.getElementById('whois-input')?.value?.trim()
      || document.getElementById('email-header-input')?.value?.split('\n')?.[0]?.substring(0,80)
      || 'Unknown Target';

    let verdict = 'UNKNOWN', vColor = '#64748b', vBg = '#f8fafc', vBorder = '#e2e8f0';
    const verdictPriority = { UNKNOWN: 0, SAFE: 1, SUSPICIOUS: 2, MALICIOUS: 3 };

    const sectionVerdict = (el) => {
      if (!el) return 'UNKNOWN';
      if (el.querySelector('.loading,.empty-state')) return 'UNKNOWN';
      const text = (el.textContent || '').replace(/\s+/g, ' ').trim();
      if (/error|failed|timed out|try again|rate limit|not checked/i.test(text)) return 'UNKNOWN';

      const label = el.querySelector('.verdict-label')?.textContent?.trim().toUpperCase();
      if (label === 'MALICIOUS' || label === 'DANGEROUS') return 'MALICIOUS';
      if (label === 'SUSPICIOUS') return 'SUSPICIOUS';
      if (label === 'SAFE' || label === 'CLEAN') return 'SAFE';

      const maliciousMatch = text.match(/Malicious\s*(\d+)\s*\/\s*(\d+)/i)
        || text.match(/(\d+)\s*engine\(s\) flagged this IP/i)
        || text.match(/(\d+)\s+malicious\s*\/\s*(\d+)\s+engines/i);
      if (maliciousMatch) {
        const count = Number(maliciousMatch[1] || 0);
        if (count >= 3) return 'MALICIOUS';
        if (count > 0) return 'SUSPICIOUS';
        return 'SAFE';
      }

      if (/Clean\s*IP|Clean\s*[—-]|no engines flagged|0\s+engines? flagged|Not a known proxy/i.test(text)) return 'SAFE';
      return 'UNKNOWN';
    };

    for (const s of sections) {
      const candidate = sectionVerdict(document.getElementById(s.id));
      if (verdictPriority[candidate] > verdictPriority[verdict]) verdict = candidate;
    }

    if      (verdict === 'MALICIOUS')  { vColor='#111827'; vBg='#fff'; vBorder='#111827'; }
    else if (verdict === 'SUSPICIOUS') { vColor='#111827'; vBg='#fff'; vBorder='#111827'; }
    else if (verdict === 'SAFE')       { vColor='#111827'; vBg='#fff'; vBorder='#111827'; }

    // ── Build content sections ──
    let contentSections = '';
    for (const s of sections) {
      const el = document.getElementById(s.id);
      if (!el) continue;
      const raw = el.innerHTML || '';
      if (!raw.trim() || raw.includes('class="empty-state"') || raw.includes('class="loading"')) continue;

      const cleaned = raw
        .replace(/<div class="loading"[^>]*>[\s\S]*?<\/div>/gi, '')
        .replace(/<div class="spinner[^>]*>[\s\S]*?<\/div>/gi, '')
        .replace(/<div class="empty-state[^>]*>[\s\S]*?<\/div>/gi, '')
        .replace(/<button[^>]*>[\s\S]*?<\/button>/gi, '')
        .replace(/<div[^>]*id="geo-map[^"]*"[^>]*>[\s\S]*?<\/div>/gi, '')
        .replace(/<div class="section-badge">[^<]*<\/div>/gi, '');

      contentSections += `<div class="rs"><div class="rsh">${s.title}</div><div class="rsb">${cleaned}</div></div>`;
    }

    if (!contentSections) {
      alert('Run at least one analysis before exporting.');
      if (btn) { btn.disabled=false; btn.textContent='⬇ Export PDF'; }
      return;
    }

    const now     = new Date();
    const dateStr = now.toLocaleDateString('en-GB', {year:'numeric', month:'long', day:'2-digit'});
    const timeStr = now.toLocaleTimeString('en-GB', {hour:'2-digit', minute:'2-digit'});
    const user    = window.__currentUser;
    const analyst = user ? (`${user.firstName||''} ${user.lastName||''}`.trim() || user.email) : 'Unknown';
    const org     = user?.org || 'Cyber X-Ray Platform';
    const vIcon   = verdict==='SAFE' ? '✓' : verdict==='MALICIOUS' ? '✕' : '⚠';
    const vLabel  = verdict==='UNKNOWN' ? 'INCONCLUSIVE' : verdict;

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>Cyber X-Ray — Security Report</title>
<style>
*,*::before,*::after{box-sizing:border-box}
html{background:#f3f4f6;color:#111827}
body{margin:0;font-family:"Times New Roman",Georgia,serif;font-size:11.5pt;color:#111827;background:#f3f4f6;line-height:1.55}
@page{margin:18mm 16mm;size:A4}
.toolbar{position:sticky;top:0;z-index:10;display:flex;justify-content:space-between;align-items:center;gap:16px;padding:12px 18px;background:#111827!important;color:#fff!important;font-family:"Segoe UI",Arial,sans-serif;box-shadow:0 2px 10px rgba(0,0,0,.18)}
.toolbar strong,.toolbar span{color:#fff!important;background:transparent!important}
.toolbar span{font-size:12px;opacity:.78}
.toolbar-actions{display:flex;gap:8px;background:transparent!important}
.toolbar button{border:1px solid rgba(255,255,255,.35);background:#fff!important;color:#111827!important;border-radius:6px;padding:8px 12px;font:700 12px "Segoe UI",Arial,sans-serif;cursor:pointer}
.toolbar button.secondary{background:transparent!important;color:#fff!important}
.report{max-width:210mm;margin:22px auto;background:#fff;padding:20mm 18mm;box-shadow:0 16px 50px rgba(15,23,42,.16)}
.cover{border-bottom:2px solid #111827;padding-bottom:16px;margin-bottom:18px;page-break-after:auto;min-height:auto;background:#fff!important;color:#111827!important}
.cover-eyebrow{font:700 9pt "Segoe UI",Arial,sans-serif;letter-spacing:1.6px;text-transform:uppercase;color:#374151!important;margin-bottom:8px}
.cover-title{font-size:25pt;font-weight:700;line-height:1.1;margin:0 0 6px;color:#111827!important}
.cover-sub{font-size:11pt;color:#374151!important;margin-bottom:16px}
.cover-meta{display:grid;grid-template-columns:repeat(4,1fr);border:1px solid #9ca3af;border-radius:0;overflow:hidden}
.cm{padding:9px 10px;border-right:1px solid #d1d5db;background:#fff!important}
.cm:last-child{border-right:none}
.cm-label{font:700 7.5pt "Segoe UI",Arial,sans-serif;text-transform:uppercase;letter-spacing:.8px;color:#4b5563!important;margin-bottom:3px}
.cm-value{font-size:9.5pt;font-weight:700;color:#111827!important;word-break:break-word}
.vh{margin:0 0 18px;border:1px solid #111827;border-left:5px solid #111827;border-radius:0;padding:14px 16px;display:flex;align-items:flex-start;gap:14px;page-break-inside:avoid;background:#fff!important;color:#111827!important}
.vh-icon{width:34px;height:34px;border-radius:50%;border:1px solid #111827;background:#fff!important;color:#111827!important;display:flex;align-items:center;justify-content:center;font:700 16pt Arial,sans-serif;flex-shrink:0;line-height:1}
.vh-label{font:800 15pt "Segoe UI",Arial,sans-serif;color:#111827!important}
.vh-desc{font-size:10pt;color:#374151!important;margin-top:3px;line-height:1.45}
.body{padding:0}
.rs{margin:0 0 18px;page-break-inside:avoid}
.rsh{font:800 10pt "Segoe UI",Arial,sans-serif;text-transform:uppercase;letter-spacing:.7px;color:#111827!important;padding:0 0 5px;border-bottom:1px solid #111827;margin-bottom:9px;background:#fff!important}
.rsb{padding:0}
table{width:100%;border-collapse:collapse;font-size:10pt;margin:8px 0 10px;page-break-inside:auto}
thead{display:table-header-group}
tr{page-break-inside:avoid;page-break-after:auto}
th{text-align:left;padding:6px 8px;font:700 8.5pt "Segoe UI",Arial,sans-serif;text-transform:uppercase;color:#111827!important;border:1px solid #9ca3af;background:#f9fafb!important}
td{padding:7px 8px;border:1px solid #d1d5db;vertical-align:top;color:#111827!important;background:#fff!important;word-break:break-word}
td:first-child{width:165px;font-weight:700;color:#374151!important}
.flag,.verdict-banner,.stat-card,.pill{border:1px solid #9ca3af!important;background:#fff!important;color:#111827!important;border-radius:0!important;box-shadow:none!important}
.flag{display:flex;align-items:flex-start;gap:8px;padding:7px 9px;margin-bottom:6px;font-size:10pt;line-height:1.45;page-break-inside:avoid}
.flag svg,.verdict-banner svg{display:none!important}
.verdict-banner{display:block;padding:10px 12px;margin-bottom:10px}
.verdict-label{font:800 12pt "Segoe UI",Arial,sans-serif;color:#111827!important}
.verdict-sub{font-size:10pt;color:#374151!important;margin-top:2px}
.result-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:8px 0 12px;page-break-inside:avoid}
.stat-card{padding:8px 10px}
.stat-card-label{font:700 7.5pt "Segoe UI",Arial,sans-serif;text-transform:uppercase;color:#4b5563!important;margin-bottom:3px}
.stat-card-value{font-size:14pt;font-weight:800;color:#111827!important}
.pill{display:inline-block;padding:1px 6px;font-size:8.5pt;font-weight:700;color:#111827!important}
.font-mono,code,pre{font-family:"Courier New",Consolas,monospace!important;font-size:9.5pt;color:#111827!important;background:#fff!important;white-space:pre-wrap;word-break:break-word}
a{color:#111827!important;text-decoration:underline!important}
hr,.divider{border:none;border-top:1px solid #d1d5db;margin:12px 0}
.section-badge,.spinner,.loading,.empty-state,.btn,button,[id^="geo-map"]{display:none!important}
.footer{border-top:1px solid #111827;padding-top:10px;margin-top:24px;display:flex;justify-content:space-between;gap:18px;align-items:flex-start;font-size:8.8pt;color:#374151!important;background:#fff!important}
.footer-brand{font-weight:800;color:#111827!important;font-family:"Segoe UI",Arial,sans-serif}
@media print{html,body{background:#fff!important}.toolbar{display:none!important}.report{max-width:none;margin:0;padding:0;box-shadow:none}.cover{break-inside:avoid}.rs{break-inside:avoid}}
@media(max-width:760px){.report{margin:0;padding:18px}.cover-meta,.result-grid{grid-template-columns:1fr}.toolbar{align-items:flex-start;flex-direction:column}.footer{display:block}.footer>div:last-child{text-align:left!important;margin-top:8px}}
</style>
</head>
<body>
<div class="toolbar"><div><strong>Cyber X-Ray Report</strong><span> Review the report, then print or save as PDF.</span></div><div class="toolbar-actions"><button onclick="window.print()">Print / Save PDF</button><button class="secondary" onclick="window.close()">Close</button></div></div>
<div class="report">

<div class="cover">
  <div class="cover-eyebrow">Cyber X-Ray</div>
  <div class="cover-title">Security Analysis<br>Report</div>
  <div class="cover-sub">Threat Intelligence &amp; Domain Investigation</div>
  <div class="cover-meta">
    <div class="cm"><div class="cm-label">Target</div><div class="cm-value">${target.substring(0,50)}${target.length>50?'…':''}</div></div>
    <div class="cm"><div class="cm-label">Date</div><div class="cm-value">${dateStr}</div></div>
    <div class="cm"><div class="cm-label">Time</div><div class="cm-value">${timeStr}</div></div>
    <div class="cm"><div class="cm-label">Analyst</div><div class="cm-value">${analyst}</div></div>
  </div>
</div>

<div class="vh">
  <div class="vh-icon">${vIcon}</div>
  <div>
    <div class="vh-label">${vLabel}</div>
    <div class="vh-desc">${
      verdict==='SAFE'       ? 'No significant threats detected. The target appears legitimate based on all analyses performed.' :
      verdict==='MALICIOUS'  ? 'Multiple threat indicators confirmed. This target is malicious. Do not interact with it.' :
      verdict==='SUSPICIOUS' ? 'Suspicious characteristics detected. Treat with extreme caution.' :
      'Analysis inconclusive. Manual review recommended.'
    }</div>
  </div>
</div>

<div class="body">
  ${contentSections}
</div>

<div class="footer">
  <div>
    <div class="footer-brand">Cyber X-Ray</div>
    <div>Security Intelligence Platform — ${org}</div>
  </div>
  <div style="text-align:right">
    Generated ${dateStr} at ${timeStr}<br>
    Confidential — For authorized use only
  </div>
</div>
</div>
<script>window.addEventListener("load",()=>setTimeout(()=>window.print(),700));</script>
</body>
</html>`;

    const win = window.open('', '_blank');
    if (!win) throw new Error('Popup blocked. Allow popups and try again.');
    win.document.open();
    win.document.write(html);
    win.document.close();

  } catch(e) {
    alert('Export failed: ' + e.message);
  }

  if (btn) { btn.disabled=false; btn.textContent='⬇ Export PDF'; }
}

// ═══════════════════════════════════════════════════════════
// analyzeURLRules — used by runFullScan threat panel
// ═══════════════════════════════════════════════════════════
function analyzeURLRules(input) {
  const findings = [];
  const urlInput = input.trim();

  const checks = [
    {
      key: 'httpNotHttps', label: 'No HTTPS (Unencrypted)', weight: 15,
      check: () => /^http:\/\//i.test(urlInput),
      description: 'Uses plain HTTP — legitimate login and banking sites always use HTTPS.',
      level: 'warning'
    },
    {
      key: 'ipAddress', label: 'Raw IP Address Used', weight: 22,
      check: () => /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(urlInput),
      description: 'Links directly to an IP address — real websites use domain names.',
      level: 'danger'
    },
    {
      key: 'urlShortener', label: 'URL Shortener Detected', weight: 14,
      check: () => /bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|rb\.gy|cutt\.ly|is\.gd/i.test(urlInput),
      description: 'URL shorteners hide the real destination — commonly used in phishing.',
      level: 'warning'
    },
    {
      key: 'brandInSubdomain', label: 'Trusted Brand Used as Subdomain', weight: 26,
      check: () => {
        try {
          const h = new URL(/^https?:\/\//i.test(urlInput) ? urlInput : 'https://' + urlInput).hostname;
          const parts = h.split('.');
          if (parts.length < 3) return false;
          return /paypal|amazon|apple|google|microsoft|netflix|facebook|instagram|bank|ebay|dhl|fedex/i.test(parts.slice(0,-2).join('.'));
        } catch { return false; }
      },
      description: 'A trusted brand name appears as a subdomain on a different domain (e.g., paypal.fake-site.xyz).',
      level: 'danger'
    },
    {
      key: 'suspiciousTLD', label: 'Suspicious Domain Extension', weight: 18,
      check: () => /\.(xyz|top|click|live|online|site|tk|ml|ga|cf|gq|pw|icu|vip|monster|fun|work|surf|space|uno)([/?#]|$)/i.test(urlInput),
      description: 'Domain extension (.xyz, .top, .click, etc.) commonly used for phishing sites.',
      level: 'danger'
    },
    {
      key: 'manySubdomains', label: 'Too Many Subdomain Levels', weight: 14,
      check: () => {
        try {
          return new URL(/^https?:\/\//i.test(urlInput) ? urlInput : 'https://' + urlInput).hostname.split('.').length > 4;
        } catch { return false; }
      },
      description: 'Excessive subdomain levels — used to make fake URLs look like real sites.',
      level: 'warning'
    },
    {
      key: 'credentialKeywords', label: 'Login / Verify Keywords in URL', weight: 20,
      check: () => /verify|login|secure|account|update|confirm|banking|signin|credential/i.test(urlInput),
      description: 'URL contains words like "verify", "login", "secure" — designed to look trustworthy.',
      level: 'warning'
    },
    {
      key: 'longURL', label: 'Abnormally Long URL', weight: 8,
      check: () => urlInput.length > 100,
      description: 'Very long URLs are often used to hide the real destination or confuse users.',
      level: 'info'
    },
  ];

  for (const c of checks) {
    if (c.check()) {
      findings.push({ key: c.key, label: c.label, weight: c.weight, description: c.description, level: c.level });
    }
  }

  const totalWeight = findings.reduce((s, f) => s + f.weight, 0);
  const riskScore = Math.min(100, Math.round((totalWeight / 70) * 100));
  const dangerCount = findings.filter(f => f.level === 'danger').length;
  const verdict = riskScore >= 65 || dangerCount >= 2 ? 'MALICIOUS'
    : riskScore >= 25 || findings.length >= 2 ? 'SUSPICIOUS'
    : 'SAFE';

  const summaryMap = {
    MALICIOUS: `${findings.length} threat signal${findings.length!==1?'s':''} detected — this link shows strong signs of being malicious.`,
    SUSPICIOUS: `${findings.length} warning sign${findings.length!==1?'s':''} found — this link has suspicious characteristics.`,
    SAFE: 'No obvious threat signals found in this link.',
  };

  return { findings, riskScore, verdict, summary: summaryMap[verdict] };
}


// ═══════════════════════════════════════════════════════════
// EMAIL SOC ANALYZER — VirusTotal + DNS live checks
// ═══════════════════════════════════════════════════════════

// ── Parse raw headers into key→value map ─────────────────


// ── Main SOC Email Analysis ───────────────────────────────
async function runEmailSOCAnalysis() {
  const raw = (document.getElementById('email-header-input')?.value || '').trim();
  if (!raw) { document.getElementById('email-header-input')?.focus(); return; }

  const resultsDiv = document.getElementById('email-soc-results');
  if (resultsDiv) resultsDiv.style.display = 'block';

  const set = (id, html) => { const el = document.getElementById(id); if (el) el.innerHTML = html; };

  set('email-auth-result',    renderLoading('Parsing headers & running DNS checks…'));
  set('email-ip-result',      renderLoading('Checking sender IP via VirusTotal…'));
  set('email-domain-result',  renderLoading('WHOIS lookup on sender domain…'));
  set('email-url-result',     renderLoading('Extracting & scanning links…'));
  set('email-routing-result', renderLoading('Tracing email routing path…'));

  const headers = parseEmailHeaders(raw);

  // ── Extract key fields ──
  const fromVal    = headers._get('from');
  const replyTo    = headers._get('reply-to');
  const returnPath = headers._get('return-path');
  const subject    = headers._get('subject');
  const date       = headers._get('date');
  const msgId      = headers._get('message-id');

  const extractEmail = s => { const m = s.match(/<([^>]+)>/) || s.match(/[\w.+\-]+@[\w.\-]+\.\w+/); return m ? (m[1]||m[0]).toLowerCase() : s.toLowerCase(); };
  const extractDom   = email => email.split('@')[1] || '';

  const fromEmail  = extractEmail(fromVal);
  const fromDomain = extractDom(fromEmail);
  const replyEmail = replyTo !== '—' ? extractEmail(replyTo) : null;

  // ── Extract originating IP from Received headers ──
  const hops = extractReceivedHops(raw);
  const originIP = hops.length ? (hops[hops.length - 1].ips[0] || null) : null;

  // ── Extract URLs from full raw header text ──
  const urls = extractURLsFromHeaders(raw);

  // ── Auth string parsing ──
  let authStr = headers._all('authentication-results').join(' ') + ' ' + headers._all('received-spf').join(' ');
  // Fallback: If copy-paste stripped leading whitespace, the headers parser will miss these. Search raw text instead.
  if (!authStr.includes('spf=') && !authStr.includes('dkim=') && !authStr.includes('dmarc=')) {
    authStr = raw;
  }
  const spfResult  = authStr.match(/spf=(pass|fail|neutral|softfail|none|temperror|permerror)/i)?.[1]?.toLowerCase() || 'unknown';
  const dkimResult = authStr.match(/dkim=(pass|fail|neutral|none|temperror|permerror)/i)?.[1]?.toLowerCase() || 'unknown';
  const dmarcResult= authStr.match(/dmarc=(pass|fail|bestguesspass|none)/i)?.[1]?.toLowerCase() || 'unknown';
  const arcResult  = authStr.match(/arc=(pass|fail|neutral|none)/i)?.[1]?.toLowerCase() || 'unknown';

  await Promise.allSettled([

    // ── 1. Auth + DNS verification ──
    (async () => {
      const findings = [];
      let dangerCount = 0;
      let warningCount = 0;

      // FROM / Reply-To mismatch
      if (replyEmail && extractDom(replyEmail) && extractDom(replyEmail) !== fromDomain) {
        findings.push({ level:'danger', text:`<b>From/Reply-To Mismatch</b> — From: <code>${fromDomain}</code> → Reply-To: <code>${extractDom(replyEmail)}</code>. Replies go to a different address — classic phishing.` });
        dangerCount++;
      }
      // Return-path mismatch
      const rpEmail = returnPath !== '—' ? extractEmail(returnPath) : null;
      if (rpEmail && extractDom(rpEmail) && extractDom(rpEmail) !== fromDomain) {
        findings.push({ level:'warning', text:`<b>Return-Path Mismatch</b> — Return-Path domain differs from From domain.` });
        warningCount++;
      }
      // Brand impersonation
      const displayName = (fromVal.match(/^"?([^"<]+)"?\s*</)?.[1] || '').trim();
      const brandRx = /paypal|amazon|apple|google|microsoft|netflix|facebook|instagram|bank|ebay|dhl|fedex|irs|visa|mastercard|github/i;
      if (brandRx.test(displayName) && !brandRx.test(fromDomain)) {
        findings.push({ level:'danger', text:`<b>Brand Impersonation</b> — Display name "<b>${displayName}</b>" but actual sender domain is <code>${fromDomain}</code>.` });
        dangerCount++;
      }
      // Free provider for brand
      if (brandRx.test(displayName) && /gmail\.com|yahoo\.com|hotmail\.com|outlook\.com/i.test(fromEmail)) {
        findings.push({ level:'danger', text:`<b>Brand Using Free Email</b> — Claimed brand sent from free provider <code>${fromEmail}</code>.` });
        dangerCount++;
      }
      
      const allAuthPass = (spfResult==='pass' && dkimResult==='pass' && dmarcResult==='pass');
      
      // Urgency subject (Only flag if authentication isn't perfectly clean, to avoid false positives on legit verify emails)
      if (/urgent|suspended|verify|confirm|action required|expire|blocked|compromised/i.test(subject)) {
        if (!allAuthPass || dangerCount > 0) {
          findings.push({ level:'warning', text:`<b>Urgency Language in Subject</b> — "<i>${subject.substring(0,80)}</i>" uses pressure tactics.` });
          warningCount++;
        }
      }
      
      // Missing headers
      const missing = [];
      if (!headers['message-id']) missing.push('Message-ID');
      if (!headers['date'])       missing.push('Date');
      if (missing.length) {
        findings.push({ level:'warning', text:`<b>Missing Headers: ${missing.join(', ')}</b> — Legitimate mail clients always include these.` });
        warningCount++;
      }

      // Check auth failures for verdict
      if (spfResult==='fail'||spfResult==='softfail'||dkimResult==='fail'||dmarcResult==='fail') {
         dangerCount++;
      }

      // Live DNS check: MX record for sender domain (proves domain is real mail domain)
      let dnsFlag = '';
      try {
        if (fromDomain && fromDomain !== '—') {
          const mxRes = await fetchDNS(fromDomain, 'MX');
          const hasMX = (mxRes.Answer || []).some(a => a.type === 15);
          dnsFlag = hasMX
            ? renderFlag('safe', `Sender domain <code>${fromDomain}</code> has valid MX records`)
            : renderFlag('warning', `Sender domain <code>${fromDomain}</code> has NO MX records — cannot receive email`);
          if (!hasMX) warningCount++;
        }
      } catch(e) { dnsFlag = renderFlag('info', 'DNS MX check failed: ' + e.message); }

      // ── VERDICT CALCULATION ──
      let verdict = 'SAFE';
      let verdictColor = 'safe';
      let verdictIcon = '<circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/>';
      let verdictDesc = 'This email passed authentication and shows no obvious signs of spoofing.';
      
      if (dangerCount > 0) {
        verdict = 'MALICIOUS (PHISHING)';
        verdictColor = 'danger';
        verdictIcon = '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>';
        verdictDesc = 'Strong indicators of spoofing or phishing detected. DO NOT click links or reply.';
      } else if (warningCount > 0 || (!allAuthPass && spfResult !== 'unknown')) {
        verdict = 'SUSPICIOUS';
        verdictColor = 'warning';
        verdictIcon = '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>';
        verdictDesc = 'Email has missing authentication or suspicious characteristics. Proceed with caution.';
      }

      // Overall auth score badges
      const authBadge = (label, res) => {
        const cls = res==='pass'?'safe':res==='fail'||res==='softfail'?'danger':'warning';
        return `<div class="stat-card" style="border-top:3px solid var(--${cls})"><div class="stat-card-label">${label}</div><div class="stat-card-value" style="font-size:15px;color:var(--${cls});text-transform:uppercase">${res}</div></div>`;
      };

      const authFindings = [];
      if (spfResult==='fail'||spfResult==='softfail') authFindings.push(renderFlag('danger', `<b>SPF ${spfResult.toUpperCase()}</b> — Sending server not authorized for <code>${fromDomain}</code>`));
      else if (spfResult==='pass') authFindings.push(renderFlag('safe', `<b>SPF PASS</b> — Server authorized to send for <code>${fromDomain}</code>`));
      else authFindings.push(renderFlag('info', `<b>SPF ${spfResult.toUpperCase()}</b>`));

      if (dkimResult==='fail') authFindings.push(renderFlag('danger', '<b>DKIM FAIL</b> — Signature invalid or forged'));
      else if (dkimResult==='pass') authFindings.push(renderFlag('safe', '<b>DKIM PASS</b> — Email not tampered in transit'));
      else authFindings.push(renderFlag('info', `<b>DKIM ${dkimResult.toUpperCase()}</b>`));

      if (dmarcResult==='fail') authFindings.push(renderFlag('danger', '<b>DMARC FAIL</b> — Policy violation by domain owner'));
      else if (dmarcResult==='pass') authFindings.push(renderFlag('safe', '<b>DMARC PASS</b> — Aligns with domain policy'));
      else if (dmarcResult!=='unknown') authFindings.push(renderFlag('info', `<b>DMARC ${dmarcResult.toUpperCase()}</b>`));

      if (arcResult==='fail') authFindings.push(renderFlag('danger', '<b>ARC FAIL</b> — Chain of trust broken'));
      else if (arcResult==='pass') authFindings.push(renderFlag('safe', '<b>ARC PASS</b> — Authenticated Received Chain verified'));
      else if (arcResult!=='unknown') authFindings.push(renderFlag('info', `<b>ARC ${arcResult.toUpperCase()}</b>`));

      const verdictHtml = `
        <div style="background:rgba(var(--${verdictColor}-rgb, ${verdictColor==='safe'?'16,185,129':verdictColor==='danger'?'239,68,68':'245,158,11'}), 0.1); border:1px solid var(--${verdictColor}); border-radius:8px; padding:16px; margin-bottom:20px; display:flex; align-items:flex-start; gap:16px">
          <div style="color:var(--${verdictColor}); margin-top:2px">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="width:28px;height:28px">${verdictIcon}</svg>
          </div>
          <div>
            <div style="font-size:16px; font-weight:800; color:var(--${verdictColor}); text-transform:uppercase; letter-spacing:1px; margin-bottom:4px">DETECTION: ${verdict}</div>
            <div style="font-size:13px; color:var(--text2)">${verdictDesc}</div>
          </div>
        </div>
      `;

      set('email-auth-result', `<div class="fade-in">
        <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:10px">Authentication Protocols</div>
        <div class="result-grid" style="grid-template-columns:repeat(4,1fr);margin-bottom:18px">
          ${authBadge('SPF', spfResult)} ${authBadge('DKIM', dkimResult)} ${authBadge('DMARC', dmarcResult)} ${authBadge('ARC', arcResult)}
        </div>
        
        ${verdictHtml}
        
        <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:10px;margin-top:20px">Key Header Fields</div>
        ${renderTable([
          ['From',        `<code style="font-size:12px">${fromEmail || '—'}</code>`],
          ['Reply-To',    `<code style="font-size:12px">${replyEmail || '—'}</code>`],
          ['Subject',     subject.substring(0,100)],
        ])}
        
        <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:10px;margin-top:20px">Detailed Findings</div>
        <div class="flags">
          ${authFindings.join('')}
          ${dnsFlag}
          ${findings.map(f => renderFlag(f.level, f.text)).join('')}
        </div>
      </div>`);
    })().catch(e => set('email-auth-result', renderError(e.message))),


    // ── 2. Sender IP Reputation via VirusTotal ──
    (async () => {
      if (!originIP) { set('email-ip-result', renderFlag('info', 'No originating IP found in Received headers')); return; }
      const vtip = await fetchVTIP(originIP);
      const attrs = vtip?.data?.attributes || {};
      const stats = attrs.last_analysis_stats || {};
      const mal   = stats.malicious  || 0;
      const sus   = stats.suspicious || 0;
      const tot   = (stats.malicious||0)+(stats.suspicious||0)+(stats.harmless||0)+(stats.undetected||0);
      const rep   = attrs.reputation || 0;
      const cls   = mal >= 3 ? 'danger' : mal >= 1 || sus >= 2 ? 'warning' : 'safe';
      const lbl   = mal >= 3 ? 'Malicious IP' : mal >= 1 || sus >= 2 ? 'Suspicious IP' : 'Clean IP';
      set('email-ip-result', `<div class="fade-in">
        <div class="flags" style="margin-bottom:12px">${renderFlag(cls, `<b>${lbl}</b> — ${mal} engine(s) flagged this IP`)}</div>
        ${renderTable([
          ['Originating IP',  `<code>${originIP}</code>`],
          ['Country',         attrs.country || '—'],
          ['AS Owner',        attrs.as_owner || '—'],
          ['VT Reputation',   `<span style="color:${rep<0?'var(--danger)':rep>0?'var(--safe)':'var(--muted)'}">${rep}</span>`],
          ['Malicious Flags', `<span class="pill ${mal>0?'danger':'safe'}">${mal} / ${tot}</span>`],
        ])}
      </div>`);
    })().catch(e => set('email-ip-result', renderError('IP reputation: ' + e.message))),

    // ── 3. Sender Domain WHOIS ──
    (async () => {
      if (!fromDomain || fromDomain === '—') { set('email-domain-result', renderFlag('info', 'Could not extract sender domain')); return; }
      const w = await fetchWHOIS(fromDomain);
      const created   = w.created || w.creation_date || null;
      const registrar = w.registrar || '—';
      const owner     = w.owner || w.registrant_name || w.org || 'Hidden / Private';
      let ageFlag = '';
      if (created) {
        const days = Math.floor((Date.now() - new Date(created)) / 86400000);
        if (!isNaN(days)) ageFlag = days < 90
          ? renderFlag('danger',  `Domain only ${days} days old — high risk`)
          : renderFlag('safe', `Domain age: ${Math.floor(days/365)}y ${Math.floor((days%365)/30)}m`);
      }
      set('email-domain-result', `<div class="fade-in">
        ${renderTable([['Domain', `<code>${fromDomain}</code>`], ['Registrar', registrar], ['Owner', owner], ['Created', formatDate(created)]])}
        <div class="flags" style="margin-top:10px">${ageFlag}</div>
      </div>`);
    })().catch(e => set('email-domain-result', renderError('WHOIS: ' + e.message))),

    // ── 4. URL scan via VirusTotal ──
    (async () => {
      if (!urls.length) { set('email-url-result', renderFlag('info', 'No URLs found in email headers')); return; }
      const results = await Promise.allSettled(urls.map(u => fetchVirusTotal(u)));
      let html = '<div class="fade-in">';
      results.forEach((r, i) => {
        const url = urls[i];
        const shortUrl = url.length > 60 ? url.substring(0,57) + '…' : url;
        if (r.status === 'fulfilled') {
          const attrs = r.value?.data?.attributes || {};
          const stats = attrs.last_analysis_stats || {};
          const mal   = stats.malicious  || 0;
          const sus   = stats.suspicious || 0;
          const tot   = (stats.malicious||0)+(stats.suspicious||0)+(stats.harmless||0)+(stats.undetected||0);
          const cls   = mal >= 3 ? 'danger' : mal >= 1 || sus >= 2 ? 'warning' : 'safe';
          const lbl   = mal >= 3 ? '🔴 MALICIOUS' : mal >= 1 || sus >= 2 ? '🟡 SUSPICIOUS' : '🟢 CLEAN';
          html += `<div style="padding:10px;border:1px solid var(--border);border-radius:8px;margin-bottom:10px;border-left:4px solid var(--${cls})">
            <div style="font-family:var(--mono);font-size:11px;color:var(--muted);word-break:break-all;margin-bottom:6px">${shortUrl}</div>
            <div style="display:flex;gap:10px;align-items:center">
              <span style="font-weight:700;color:var(--${cls})">${lbl}</span>
              <span class="pill" style="font-size:11px">${mal} malicious / ${tot} engines</span>
            </div>
          </div>`;
        } else {
          html += `<div style="padding:10px;border:1px solid var(--border);border-radius:8px;margin-bottom:8px">
            <div style="font-family:var(--mono);font-size:11px;color:var(--muted);margin-bottom:4px">${shortUrl}</div>
            ${renderFlag('warning', 'VT scan failed: ' + r.reason?.message)}
          </div>`;
        }
      });
      html += '</div>';
      set('email-url-result', html);
    })(),

    // ── 5. Routing path ──
    Promise.resolve().then(() => {
      if (!hops.length) { set('email-routing-result', renderFlag('info', 'No Received headers found — routing path unavailable')); return; }
      const rows = hops.map((h, i) => `<tr>
        <td style="color:var(--muted);font-size:11px;width:28px">${i+1}</td>
        <td class="font-mono" style="font-size:11px;word-break:break-all">${h.from}</td>
        <td class="font-mono" style="font-size:11px;color:var(--accent)">${h.ips.join(', ') || '—'}</td>
        <td class="font-mono" style="font-size:11px;color:var(--muted)">${h.by}</td>
        <td style="font-size:11px;color:var(--muted)">${h.time}</td>
      </tr>`).join('');
      set('email-routing-result', `<div class="fade-in" style="overflow-x:auto">
        <table class="data-table" style="min-width:480px">
          <thead><tr><th>#</th><th>From</th><th>IP</th><th>By</th><th>Time</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
        <div style="font-size:11px;color:var(--muted);margin-top:8px">📍 Hop ${hops.length} is the originating server — IP used for reputation check above.</div>
      </div>`);
    }),
  ]);
}

