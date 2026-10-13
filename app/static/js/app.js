document.addEventListener('DOMContentLoaded', () => {
  // Navigation Tabs
  const navButtons = document.querySelectorAll('.nav-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  navButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      navButtons.forEach(b => b.classList.remove('active'));
      tabContents.forEach(t => t.classList.remove('active'));

      btn.classList.add('active');
      const activeContent = document.getElementById(targetTab);
      if (activeContent) activeContent.classList.add('active');

      if (targetTab === 'tab-analytics') loadAnalytics();
      if (targetTab === 'tab-blacklist') loadBlacklist();
      if (targetTab === 'tab-settings') loadSettings();
    });
  });

  // Global State
  let adminKey = localStorage.getItem('ti_admin_key') || 'adminkey-threat-intel-2026-secure';

  // -------------------------------------------------------------
  // 1. Live Stats & Health Polling
  // -------------------------------------------------------------
  async function updateHealthAndStats() {
    try {
      const [healthRes, statsRes] = await Promise.all([
        fetch('/api/health'),
        fetch('/api/stats')
      ]);

      if (healthRes.ok) {
        const health = await healthRes.json();
        const redisDot = document.getElementById('redis-status-dot');
        const redisText = document.getElementById('redis-status-text');
        if (health.redis.connected) {
          redisDot.className = 'status-dot active';
          const modeLabel = health.redis.mode === 'in_memory_simulation' ? 'Simulation' : 'Server';
          redisText.textContent = `Redis: Connected (${modeLabel})`;
        } else {
          redisDot.className = 'status-dot danger';
          redisText.textContent = 'Redis: Disconnected';
        }

        const providerText = document.getElementById('provider-status-text');
        providerText.textContent = `CTI: ${health.cti_provider.active === 'virustotal' ? 'VirusTotal v3' : 'Local Demo'}`;
      }

      if (statsRes.ok) {
        const stats = await statsRes.json();
        document.getElementById('metric-total-lookups').textContent = stats.total_lookups.toLocaleString();
        document.getElementById('metric-hit-rate').textContent = `${stats.cache_hit_rate_pct}%`;
        document.getElementById('metric-hits-count').textContent = stats.cache_hits.toLocaleString();
        document.getElementById('metric-misses-count').textContent = stats.cache_misses.toLocaleString();
        document.getElementById('metric-avoided').textContent = stats.avoided_requests.toLocaleString();
        document.getElementById('metric-threats').textContent = stats.threats_detected.toLocaleString();
        document.getElementById('metric-blacklist').textContent = stats.blacklist_count.toLocaleString();
        document.getElementById('metric-hit-latency').textContent = `${stats.avg_hit_latency_ms} ms`;
        document.getElementById('metric-miss-latency').textContent = `${stats.avg_miss_latency_ms} ms`;
      }
    } catch (err) {
      console.warn('Error fetching stats:', err);
    }
  }

  setInterval(updateHealthAndStats, 4000);
  updateHealthAndStats();

  // -------------------------------------------------------------
  // 2. Indicator Lookup
  // -------------------------------------------------------------
  const lookupForm = document.getElementById('lookup-form');
  const lookupInput = document.getElementById('lookup-input');
  const btnSubmitLookup = document.getElementById('btn-submit-lookup');
  const btnForceRefresh = document.getElementById('btn-force-refresh');

  async function performLookup(indicator, forceRefresh = false) {
    if (!indicator || !indicator.trim()) return;

    btnSubmitLookup.disabled = true;
    btnSubmitLookup.textContent = 'Analyzing...';

    const url = forceRefresh 
      ? `/api/refresh/${encodeURIComponent(indicator.trim())}`
      : '/api/check';

    const options = forceRefresh
      ? { method: 'POST' }
      : {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ indicator: indicator.trim() })
        };

    try {
      const res = await fetch(url, options);
      const data = await res.json();

      if (!res.ok) {
        alert(`Lookup error: ${data.detail || 'Validation error'}`);
        return;
      }

      renderLookupResult(data);
      updateHealthAndStats();
    } catch (err) {
      alert(`Network failure: ${err.message}`);
    } finally {
      btnSubmitLookup.disabled = false;
      btnSubmitLookup.textContent = 'Check Indicator';
    }
  }

  lookupForm.addEventListener('submit', (e) => {
    e.preventDefault();
    performLookup(lookupInput.value, false);
  });

  btnForceRefresh.addEventListener('click', () => {
    performLookup(lookupInput.value, true);
  });

  // Quick Chips
  document.querySelectorAll('.chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const val = chip.getAttribute('data-val');
      lookupInput.value = val;
      performLookup(val, false);
    });
  });

  function renderLookupResult(data) {
    document.getElementById('lookup-result-placeholder').style.display = 'none';
    const card = document.getElementById('lookup-result-card');
    card.style.display = 'block';

    const badge = document.getElementById('res-verdict-badge');
    badge.textContent = data.verdict.toUpperCase();
    badge.className = `verdict-badge ${data.verdict.toLowerCase()}`;

    document.getElementById('res-indicator-title').textContent = data.indicator;

    // Cache status
    const cacheBadge = document.getElementById('res-cache-badge');
    if (data.cache_status === 'hit') {
      cacheBadge.textContent = 'Cache Hit (Redis Hash)';
      cacheBadge.style.borderColor = 'var(--color-emerald)';
      cacheBadge.style.color = 'var(--color-emerald)';
    } else {
      cacheBadge.textContent = 'Cache Miss (Live Query)';
      cacheBadge.style.borderColor = 'var(--color-cyan)';
      cacheBadge.style.color = 'var(--color-cyan)';
    }

    // Score Bar
    const score = data.threat_score;
    const scoreBar = document.getElementById('res-score-bar');
    const scoreText = document.getElementById('res-score-text');
    scoreText.textContent = `${score} / 100`;
    scoreBar.style.width = `${score}%`;
    if (score >= 75) {
      scoreBar.style.backgroundColor = 'var(--color-crimson)';
    } else if (score >= 40) {
      scoreBar.style.backgroundColor = 'var(--color-amber)';
    } else {
      scoreBar.style.backgroundColor = 'var(--color-emerald)';
    }

    // Metadata
    document.getElementById('res-type').textContent = data.indicator_type.toUpperCase();
    document.getElementById('res-source').textContent = data.source;
    document.getElementById('res-latency').textContent = `${data.latency_ms} ms`;
    document.getElementById('res-ttl').textContent = data.ttl_remaining !== null 
      ? `${data.ttl_remaining}s remaining (Policy: ${data.ttl_policy}s)` 
      : 'Blacklist Intercept';
    document.getElementById('res-confidence').textContent = `${Math.round(data.confidence * 100)}%`;
    document.getElementById('res-redis-key').textContent = data.redis_key;

    // Categories
    const catContainer = document.getElementById('res-categories');
    catContainer.innerHTML = '';
    if (data.categories && data.categories.length > 0) {
      data.categories.forEach(c => {
        const span = document.createElement('span');
        span.className = 'tag';
        span.textContent = c;
        catContainer.appendChild(span);
      });
    } else {
      catContainer.innerHTML = '<span class="tag">none</span>';
    }

    // Description
    document.getElementById('res-description').textContent = data.description || 'No additional threat context provided.';

    // Raw JSON Box
    const rawBox = document.getElementById('res-raw-json');
    rawBox.textContent = JSON.stringify(data, null, 2);
  }

  // Raw JSON Toggle
  document.getElementById('btn-toggle-json').addEventListener('click', () => {
    const box = document.getElementById('res-raw-json');
    box.style.display = box.style.display === 'none' ? 'block' : 'none';
  });

  // -------------------------------------------------------------
  // 3. Operational Analytics
  // -------------------------------------------------------------
  async function loadAnalytics() {
    try {
      const [topRes, histRes] = await Promise.all([
        fetch('/api/top-threats?limit=10'),
        fetch('/api/history?limit=25')
      ]);

      if (topRes.ok) {
        const topData = await topRes.json();
        const tbody = document.getElementById('top-threats-tbody');
        tbody.innerHTML = '';
        if (topData.length === 0) {
          tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No indicator rankings stored in Redis Sorted Set yet.</td></tr>';
        } else {
          topData.forEach((item, idx) => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
              <td>#${idx + 1}</td>
              <td class="mono-cell">${escapeHtml(item.indicator)}</td>
              <td>${item.count} lookups</td>
              <td>
                <button class="btn btn-primary" style="padding: 2px 8px; font-size: 11px;" onclick="searchIndicator('${escapeHtml(item.indicator)}')">Inspect</button>
              </td>
            `;
            tbody.appendChild(tr);
          });
        }
      }

      if (histRes.ok) {
        const histData = await histRes.json();
        const tbody = document.getElementById('history-tbody');
        tbody.innerHTML = '';
        if (histData.length === 0) {
          tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted);">No lookups recorded in history trail yet.</td></tr>';
        } else {
          histData.forEach(item => {
            const tr = document.createElement('tr');
            const timeStr = item.checked_at ? new Date(item.checked_at).toLocaleTimeString() : '-';
            tr.innerHTML = `
              <td class="mono-cell">${timeStr}</td>
              <td class="mono-cell">${escapeHtml(item.indicator)}</td>
              <td>${item.indicator_type.toUpperCase()}</td>
              <td><span class="verdict-badge ${item.verdict.toLowerCase()}" style="font-size: 11px; padding: 2px 8px;">${item.verdict.toUpperCase()}</span></td>
              <td>${escapeHtml(item.source)}</td>
              <td>${item.cache_status === 'hit' ? '<span style="color: var(--color-emerald);">Hit</span>' : '<span style="color: var(--color-cyan);">Miss</span>'}</td>
              <td class="mono-cell">${item.latency_ms} ms</td>
            `;
            tbody.appendChild(tr);
          });
        }
      }
    } catch (err) {
      console.error('Error loading analytics:', err);
    }
  }

  window.searchIndicator = (val) => {
    document.getElementById('nav-lookup').click();
    lookupInput.value = val;
    performLookup(val, false);
  };

  // -------------------------------------------------------------
  // 4. Blacklist Management
  // -------------------------------------------------------------
  async function loadBlacklist() {
    try {
      const res = await fetch('/api/blacklist');
      if (!res.ok) return;
      const data = await res.json();
      const tbody = document.getElementById('blacklist-tbody');
      tbody.innerHTML = '';

      if (data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No administrative blacklisted indicators.</td></tr>';
        return;
      }

      data.forEach(entry => {
        const tr = document.createElement('tr');
        const timeStr = entry.added_at ? new Date(entry.added_at).toLocaleString() : '-';
        tr.innerHTML = `
          <td class="mono-cell"><strong>${escapeHtml(entry.indicator)}</strong></td>
          <td>${entry.indicator_type.toUpperCase()}</td>
          <td>${escapeHtml(entry.reason)}</td>
          <td>${escapeHtml(entry.source)}</td>
          <td class="mono-cell">${timeStr}</td>
          <td>
            <button class="btn btn-danger" style="padding: 2px 8px; font-size: 11px;" onclick="removeBlacklistEntry('${escapeHtml(entry.indicator)}')">Remove</button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    } catch (err) {
      console.error('Error loading blacklist:', err);
    }
  }

  // Blacklist Modal
  const modalBl = document.getElementById('modal-blacklist');
  document.getElementById('btn-open-add-blacklist').addEventListener('click', () => {
    modalBl.classList.add('active');
    document.getElementById('bl-input-admin-key').value = adminKey;
  });
  document.getElementById('btn-close-modal').addEventListener('click', () => {
    modalBl.classList.remove('active');
  });

  document.getElementById('form-add-blacklist').addEventListener('submit', async (e) => {
    e.preventDefault();
    const ind = document.getElementById('bl-input-indicator').value.trim();
    const reason = document.getElementById('bl-input-reason').value.trim();
    const key = document.getElementById('bl-input-admin-key').value.trim();
    adminKey = key;
    localStorage.setItem('ti_admin_key', key);

    try {
      const res = await fetch('/api/blacklist', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Admin-Key': key
        },
        body: JSON.stringify({ indicator: ind, reason: reason })
      });

      const data = await res.json();
      if (!res.ok) {
        alert(`Failed to add: ${data.detail || 'Authorization failed'}`);
        return;
      }

      modalBl.classList.remove('active');
      document.getElementById('form-add-blacklist').reset();
      loadBlacklist();
      updateHealthAndStats();
    } catch (err) {
      alert(`Error: ${err.message}`);
    }
  });

  window.removeBlacklistEntry = async (ind) => {
    const key = prompt('Enter Administrative API Key to confirm deletion:', adminKey);
    if (!key) return;
    adminKey = key;
    localStorage.setItem('ti_admin_key', key);

    try {
      const res = await fetch(`/api/blacklist/${encodeURIComponent(ind)}`, {
        method: 'DELETE',
        headers: { 'X-Admin-Key': key }
      });
      const data = await res.json();
      if (!res.ok) {
        alert(`Failed to remove: ${data.detail || 'Error'}`);
        return;
      }
      loadBlacklist();
      updateHealthAndStats();
    } catch (err) {
      alert(`Error: ${err.message}`);
    }
  };

  // -------------------------------------------------------------
  // 5. Performance Benchmark
  // -------------------------------------------------------------
  const btnRunBenchmark = document.getElementById('btn-run-benchmark');
  const bmStatus = document.getElementById('benchmark-status');
  const bmResults = document.getElementById('benchmark-results-container');

  btnRunBenchmark.addEventListener('click', async () => {
    btnRunBenchmark.disabled = true;
    bmStatus.style.display = 'block';
    bmResults.style.display = 'none';

    try {
      const res = await fetch('/api/benchmark/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sample_size: 24, include_direct: true })
      });

      const data = await res.json();
      if (!res.ok) {
        alert(`Benchmark failure: ${data.detail || 'Error'}`);
        return;
      }

      // Populate results
      document.getElementById('bm-cold-samples').textContent = data.cold_cache.sample_count;
      document.getElementById('bm-cold-avg').textContent = `${data.cold_cache.avg_latency_ms} ms`;
      document.getElementById('bm-cold-p50').textContent = `${data.cold_cache.p50_latency_ms} ms`;
      document.getElementById('bm-cold-p95').textContent = `${data.cold_cache.p95_latency_ms} ms`;
      document.getElementById('bm-cold-p99').textContent = `${data.cold_cache.p99_latency_ms} ms`;
      document.getElementById('bm-cold-hitrate').textContent = `${data.cold_cache.cache_hit_rate_pct}%`;

      document.getElementById('bm-warm-samples').textContent = data.warm_cache.sample_count;
      document.getElementById('bm-warm-avg').textContent = `${data.warm_cache.avg_latency_ms} ms`;
      document.getElementById('bm-warm-p50').textContent = `${data.warm_cache.p50_latency_ms} ms`;
      document.getElementById('bm-warm-p95').textContent = `${data.warm_cache.p95_latency_ms} ms`;
      document.getElementById('bm-warm-p99').textContent = `${data.warm_cache.p99_latency_ms} ms`;
      document.getElementById('bm-warm-hitrate').textContent = `${data.warm_cache.cache_hit_rate_pct}%`;
      document.getElementById('bm-warm-throughput').textContent = `${data.warm_cache.throughput_req_sec} req/s`;

      document.getElementById('bm-comp-speedup').textContent = `${data.comparison.latency_reduction_factor}x`;
      document.getElementById('bm-comp-reduction').textContent = `${data.comparison.latency_reduction_pct}%`;
      document.getElementById('bm-comp-avoided').textContent = data.comparison.requests_avoided_count;
      document.getElementById('bm-comp-mode').textContent = data.dataset_mode;

      bmStatus.style.display = 'none';
      bmResults.style.display = 'grid';
      updateHealthAndStats();
    } catch (err) {
      alert(`Benchmark error: ${err.message}`);
      bmStatus.style.display = 'none';
    } finally {
      btnRunBenchmark.disabled = false;
    }
  });

  // -------------------------------------------------------------
  // 6. Settings Management
  // -------------------------------------------------------------
  async function loadSettings() {
    try {
      const res = await fetch('/api/settings');
      if (!res.ok) return;
      const data = await res.json();
      document.getElementById('cfg-ttl-malicious').value = data.ttl_malicious_seconds;
      document.getElementById('cfg-ttl-benign').value = data.ttl_benign_seconds;
      document.getElementById('cfg-ttl-unknown').value = data.ttl_unknown_seconds;
      document.getElementById('cfg-alert-threshold').value = data.alert_risk_threshold;
      document.getElementById('cfg-provider').value = data.cti_provider;
      document.getElementById('cfg-admin-key').value = adminKey;
    } catch (err) {
      console.error('Error loading settings:', err);
    }
  }

  document.getElementById('settings-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const key = document.getElementById('cfg-admin-key').value.trim();
    adminKey = key;
    localStorage.setItem('ti_admin_key', key);

    const payload = {
      ttl_malicious_seconds: parseInt(document.getElementById('cfg-ttl-malicious').value),
      ttl_benign_seconds: parseInt(document.getElementById('cfg-ttl-benign').value),
      ttl_unknown_seconds: parseInt(document.getElementById('cfg-ttl-unknown').value),
      alert_risk_threshold: parseInt(document.getElementById('cfg-alert-threshold').value),
      cti_provider: document.getElementById('cfg-provider').value
    };

    try {
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Admin-Key': key
        },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (!res.ok) {
        alert(`Settings update failed: ${data.detail || 'Authorization failed'}`);
        return;
      }
      const msg = document.getElementById('settings-save-msg');
      msg.style.display = 'inline';
      setTimeout(() => { msg.style.display = 'none'; }, 3000);
      updateHealthAndStats();
    } catch (err) {
      alert(`Error updating settings: ${err.message}`);
    }
  });

  // -------------------------------------------------------------
  // 7. Real-Time WebSocket Alerts Feed (Redis Pub/Sub)
  // -------------------------------------------------------------
  const alertsFeed = document.getElementById('alerts-feed');
  const wsDot = document.getElementById('ws-status-dot');
  const wsText = document.getElementById('ws-status-text');

  // Load alert history first
  async function loadAlertHistory() {
    try {
      const res = await fetch('/api/alerts/history?limit=10');
      if (res.ok) {
        const historyAlerts = await res.json();
        if (historyAlerts.length > 0) {
          alertsFeed.innerHTML = '';
          historyAlerts.forEach(appendAlertCard);
        }
      }
    } catch (err) {
      console.warn('Error loading alert history:', err);
    }
  }
  loadAlertHistory();

  function appendAlertCard(alert) {
    // If empty placeholder is present, clear it
    if (alertsFeed.children.length === 1 && alertsFeed.children[0].textContent.includes('Listening')) {
      alertsFeed.innerHTML = '';
    }

    const card = document.createElement('div');
    card.className = `alert-item severity-${alert.severity}`;
    const timeStr = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();

    card.innerHTML = `
      <div>
        <div style="display: flex; align-items: center; gap: 8px;">
          <span class="verdict-badge malicious" style="font-size: 10px; padding: 2px 6px;">${alert.severity}</span>
          <span class="alert-indicator">${escapeHtml(alert.indicator)}</span>
          <span style="font-size: 11px; color: var(--text-muted);">Score: ${alert.threat_score}/100</span>
        </div>
        <div class="alert-reason">${escapeHtml(alert.reason)} &bull; Source: ${escapeHtml(alert.source)}</div>
      </div>
      <div style="text-align: right;">
        <div class="alert-time">${timeStr}</div>
        <button class="btn btn-primary" style="padding: 2px 8px; font-size: 10px; margin-top: 4px;" onclick="searchIndicator('${escapeHtml(alert.indicator)}')">Inspect</button>
      </div>
    `;

    alertsFeed.prepend(card);
    if (alertsFeed.children.length > 20) {
      alertsFeed.removeChild(alertsFeed.lastChild);
    }
  }

  function initWebSocket() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${location.host}/ws/alerts`;
    let ws = null;

    try {
      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        wsDot.className = 'status-dot active';
        wsText.textContent = 'Pub/Sub: Live';
      };

      ws.onmessage = (event) => {
        try {
          const alert = JSON.parse(event.data);
          if (alert.indicator) {
            appendAlertCard(alert);
            updateHealthAndStats();
          }
        } catch (e) {
          console.warn('Failed to parse WebSocket message:', e);
        }
      };

      ws.onclose = () => {
        wsDot.className = 'status-dot warning';
        wsText.textContent = 'Pub/Sub: Reconnecting...';
        setTimeout(initWebSocket, 3000);
      };

      ws.onerror = () => {
        ws.close();
      };
    } catch (e) {
      setTimeout(initWebSocket, 3000);
    }
  }

  initWebSocket();

  function escapeHtml(str) {
    if (!str) return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
});
