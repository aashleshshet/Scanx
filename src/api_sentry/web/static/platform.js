/* Platform views extend the existing scanner dashboard; no scanner results are fabricated here. */
(() => {
  const key = "onescanx-saved-reports";
  let inventory = [],
    remote = [],
    schedules = [],
    connected = false,
    importedSpec = "",
    importedScenarios = "",
    challenge = null;
  const escape = escapeHTML;
  const platform = async (path, options = {}) => {
    const response = await fetch("/api/platform/" + path, {
      ...options,
      headers: { "Content-Type": "application/json" },
    });
    const body = await response.json();
    if (!response.ok) throw Error(body.detail || "Platform request failed");
    return body;
  };
  const button = (id, text) =>
    `<button class="button secondary" id="${id}">${text}</button>`;
  const notice = () =>
    `<div class="platform-notice"><strong>${connected ? "Platform connected" : "Browser workspace"}</strong><p>${connected ? "Authenticated workspace with persistent storage and worker integration." : "Report analysis works here. Connect the optional backend in Settings for verified scans, scheduling, and AI generation."}</p></div>`;
  const findings = () => state.findings || [];
  const saved = () => {
    try {
      const records = JSON.parse(localStorage.getItem(key) || "[]");
      return Array.isArray(records)
        ? records.filter(
            (r) =>
              r && typeof r.scan_id === "string" && Array.isArray(r.checks),
          )
        : [];
    } catch {
      return [];
    }
  };
  const allReports = () =>
    [...state.history.map((h) => h.report), ...saved()].filter(
      (r, i, a) => a.findIndex((x) => x.scan_id === r.scan_id) === i,
    );
  function saveCurrent() {
    if (!state.report) return;
    const list = saved().filter((r) => r.scan_id !== state.report.scan_id);
    list.unshift(state.report);
    try {
      localStorage.setItem(key, JSON.stringify(list.slice(0, 10)));
      toast(
        "Report saved on this device. Remove it from Settings on shared computers.",
      );
    } catch {
      toast("Device storage unavailable or full. Export JSON instead.");
    }
  }
  function discover(doc) {
    if (!doc || (!doc.openapi && !doc.swagger) || typeof doc.paths !== "object")
      throw Error(
        "Choose an OpenAPI/Swagger JSON document. YAML import is available in the local scanner.",
      );
    const resolve = (obj, depth = 0) => {
      if (!obj?.$ref) return obj;
      if (depth > 15 || !obj.$ref.startsWith("#/"))
        throw Error("Only bounded local references are supported");
      return resolve(
        obj.$ref
          .slice(2)
          .split("/")
          .reduce(
            (a, k) => a?.[k.replace(/~1/g, "/").replace(/~0/g, "~")],
            doc,
          ),
        depth + 1,
      );
    };
    return Object.entries(doc.paths)
      .flatMap(([path, raw]) =>
        Object.entries(resolve(raw) || {})
          .filter(([method]) =>
            [
              "get",
              "post",
              "put",
              "delete",
              "patch",
              "head",
              "options",
              "trace",
            ].includes(method),
          )
          .map(([method, op]) => {
            const security = op.security ?? doc.security ?? [];
            return {
              method: method.toUpperCase(),
              path,
              requires_auth:
                security.length > 0 &&
                security.every((x) => Object.keys(x).length > 0),
            };
          }),
      )
      .slice(0, 2000);
  }
  function renderInventory() {
    const operations = inventory.length
      ? inventory
      : [...new Set(state.report?.checks.map((c) => c.operation) || [])].map(
          (x) => ({
            method: x.split(" ")[0],
            path: x.slice(x.indexOf(" ") + 1),
            requires_auth: null,
          }),
        );
    $("inventory-view").innerHTML =
      notice() +
      `<article class="panel guide-card"><div class="panel-heading"><h2>Endpoint inventory</h2><span>${operations.length} operations</span></div><p>Import an OpenAPI JSON specification to inspect declared authentication. Report-derived routes have unknown declarations.</p><label class="upload-box">Import OpenAPI JSON<input type="file" id="inventory-file" accept=".json"></label><div class="inventory-list">${operations.map((o) => `<div class="inventory-row"><code>${escape(o.method)}</code><code>${escape(o.path)}</code><span>${o.requires_auth === null ? "From report" : o.requires_auth ? "Authentication declared" : "Public / optional auth"}</span></div>`).join("") || "<p>No endpoints yet. Import a specification or report.</p>"}</div></article><article class="panel guide-card"><h2>Approved platform targets</h2><p>Registration requires an operator allowlist entry, followed by a public HTTPS ownership challenge. Nothing is scanned during import.</p><form id="asset-form"><label>API name<input id="asset-name" required maxlength="100"></label><label>Approved API root<input id="asset-target" type="url" required placeholder="https://your-api.example/v1"></label><label>Optional scenario fixtures (JSON or YAML)<input type="file" id="asset-fixtures" accept=".json,.yaml,.yml"></label><p>Reference only ONESCANX_SCAN_ token variables configured on the worker. Never upload tokens.</p><button class="button primary" ${!connected ? "disabled" : ""}>Register imported specification</button></form><div id="asset-challenge"></div><div id="remote-assets">${remote.map((x) => `<div class="history-row"><div><strong>${escape(x.name)}</strong><small>${escape(x.target)}</small><small>${x.verified_until * 1000 > Date.now() ? "Ownership verified" : "Verification required"}</small></div><button class="button secondary" data-verify="${escape(x.id)}">Verify ownership</button></div>`).join("")}</div></article>`;
    $("inventory-file").onchange = async (e) => {
      try {
        const f = e.target.files[0];
        if (!f) return;
        if (f.size > 1_000_000)
          throw Error("Use a specification smaller than 1 MB");
        importedSpec = await f.text();
        inventory = discover(JSON.parse(importedSpec));
        renderInventory();
        toast("Specification inventoried. No requests sent.");
      } catch (err) {
        toast(err.message);
      }
    };
    $("asset-fixtures").onchange = async (e) => {
      try {
        const f = e.target.files[0];
        if (!f) return;
        if (f.size > 500_000) throw Error("Keep fixtures below 500 KB");
        importedScenarios = await f.text();
        toast("Scenario fixtures selected");
      } catch (err) {
        toast(err.message);
      }
    };
    $("asset-form").onsubmit = async (e) => {
      e.preventDefault();
      try {
        if (!importedSpec) throw Error("Import a specification first");
        challenge = await platform("inventory", {
          method: "POST",
          body: JSON.stringify({
            name: $("asset-name").value,
            target: $("asset-target").value,
            spec: importedSpec,
            scenarios: importedScenarios,
          }),
        });
        $("asset-challenge").textContent =
          challenge.instructions + " — token: " + challenge.challenge;
        await refresh(false);
      } catch (err) {
        toast(err.message);
      }
    };
    $("remote-assets").onclick = async (e) => {
      const b = e.target.closest("[data-verify]");
      if (!b) return;
      try {
        await platform(`inventory/${b.dataset.verify}/verify`, {
          method: "POST",
        });
        await refresh();
        toast("Ownership verified for seven days");
      } catch (err) {
        toast(err.message);
      }
    };
  }
  function renderNewScan() {
    $("newscan-view").innerHTML =
      notice() +
      `<div class="guide-grid"><article class="panel guide-card"><h2>Local assessment</h2><p>Use the existing scanner with your specification, approved target, and explicitly provided test accounts.</p>${button("open-local-scan", state.hosted ? "Local setup instructions" : "Configure local scan")}</article><article class="panel guide-card"><h2>Verified worker scan</h2><p>Platform workers run read-only authorization, authentication, header, and CORS checks. Credentials and approved scenarios are configured by the backend operator.</p><label>Verified API<select id="worker-target">${remote
        .filter((x) => x.verified_until * 1000 > Date.now())
        .map(
          (x) => `<option value="${escape(x.id)}">${escape(x.name)}</option>`,
        )
        .join(
          "",
        )}</select></label><button class="button primary" id="queue-scan" ${!connected ? "disabled" : ""}>Queue assessment</button></article></div><article class="panel guide-card"><h2>Scan schedule</h2><p>Requires Redis, one Celery worker, and one Beat scheduler. Expired ownership pauses execution.</p><form id="schedule-form"><label>Interval (hours)<input id="schedule-hours" type="number" min="1" max="8760" value="24" required></label><button class="button secondary" ${!connected ? "disabled" : ""}>Schedule selected API</button></form><div>${schedules.map((x) => `<div class="history-row"><span>Every ${x.interval_hours} hours · ${escape(x.next_run)}</span><button data-cancel-schedule="${escape(x.id)}" class="text-button">Remove</button></div>`).join("")}</div><button class="button secondary" id="refresh-jobs">Refresh worker jobs</button><div id="worker-jobs" aria-live="polite"></div></article>`;
    $("open-local-scan").onclick = newScan;
    $("refresh-jobs").onclick = showJobs;
    $("queue-scan").onclick = async () => {
      try {
        const id = $("worker-target").value;
        if (!id) throw Error("Register and verify an API first");
        const job = await platform(`inventory/${id}/scan`, { method: "POST" });
        toast("Scan queued: " + job.id);
        await showJobs();
      } catch (e) {
        toast(e.message);
      }
    };
    $("schedule-form").onsubmit = async (e) => {
      e.preventDefault();
      try {
        const id = $("worker-target").value;
        if (!id) throw Error("Select a verified API");
        await platform("schedules", {
          method: "POST",
          body: JSON.stringify({
            asset_id: id,
            interval_hours: Number($("schedule-hours").value),
          }),
        });
        await refresh();
        toast("Schedule saved");
      } catch (err) {
        toast(err.message);
      }
    };
    $("newscan-view").onclick = async (e) => {
      const b = e.target.closest("[data-cancel-schedule]");
      if (b) {
        try {
          await platform("schedules/" + b.dataset.cancelSchedule, {
            method: "DELETE",
          });
          await refresh();
        } catch (err) {
          toast(err.message);
        }
      }
    };
    if (connected) showJobs();
  }
  async function showJobs() {
    try {
      const jobs = await platform("jobs");
      if ($("worker-jobs"))
        $("worker-jobs").innerHTML =
          "<h3>Worker jobs</h3>" +
          (jobs.length ? "" : "<p>No worker jobs yet.</p>") +
          jobs
            .slice(0, 10)
            .map(
              (j) =>
                `<div class="history-row"><code>${escape(j.id.slice(0, 8))}</code><span>${escape(j.status)}</span>${j.error ? `<span>${escape(j.error)}</span>` : ""}</div>`,
            )
            .join("");
    } catch (e) {
      toast(e.message);
    }
  }
  function renderAnalytics() {
    const reports = allReports();
    const current = state.report;
    const same = reports.filter(
      (r) => r.target === current?.target && r.scan_id !== current?.scan_id,
    );
    const before = same[0];
    const identity = (f) =>
      JSON.stringify([f.rule_id, f.operation, f.verification]);
    const prior = new Set(
      (before?.checks || []).flatMap((c) => c.findings).map(identity),
    );
    const now = new Set(findings().map(identity));
    $("analytics-view").innerHTML =
      `<article class="panel guide-card"><h2>Finding distribution</h2><p>Computed from the current report. Select a severity to investigate its evidence.</p><div class="analytics-bars">${levels
        .map((l) => {
          const n = findings().filter((f) => f.severity === l).length;
          return `<button data-analytics-level="${l}"><span>${l}</span><meter aria-label="${l} findings" min="0" max="${Math.max(1, findings().length)}" value="${n}">${n}</meter><b>${n}</b></button>`;
        })
        .join(
          "",
        )}</div></article><article class="panel guide-card"><h2>Historical comparison</h2><p>${before ? "Compared with another loaded or saved report for " + escape(current.target) : "Load or save two reports for the same API to compare findings. Comparisons use rule, operation, and verification—not generated finding IDs."}</p>${before ? `<div class="comparison"><span><strong>${[...now].filter((x) => !prior.has(x)).length}</strong> newly observed</span><span><strong>${[...prior].filter((x) => !now.has(x)).length}</strong> no longer observed</span><span><strong>${[...now].filter((x) => prior.has(x)).length}</strong> recurring</span></div><p>No longer observed does not mean remediated; compare coverage and fixtures.</p>` : ""}</article>`;
    $("analytics-view").onclick = (e) => {
      const b = e.target.closest("[data-analytics-level]");
      if (b) {
        changeView("findings");
        $("severity-filter").value = b.dataset.analyticsLevel;
        renderFindings();
      }
    };
  }
  function renderAssistant() {
    $("assistant-view").innerHTML =
      notice() +
      `<article class="panel guide-card"><h2>Ask the evidence</h2><p>Retrieve observations from the current report. Model output is always advisory and cannot modify a finding’s severity or verification.</p><form id="assistant-form"><label>Your question<input id="assistant-question" maxlength="2000" required placeholder="Which confirmed findings should I fix first?"></label><label class="checkbox-label"><input id="assistant-consent" type="checkbox"> Allow the configured AI provider to receive selected finding metadata and this question</label><button class="button primary">Analyze evidence</button></form><div id="assistant-answer" aria-live="polite"></div></article>`;
    $("assistant-form").onsubmit = async (e) => {
      e.preventDefault();
      const out = $("assistant-answer");
      out.textContent = "Retrieving evidence…";
      try {
        const question = $("assistant-question").value;
        if (!state.report) throw Error("Load a report first");
        let result;
        if (connected && $("assistant-consent").checked) {
          const record = await platform("reports", {
            method: "POST",
            body: JSON.stringify(state.report),
          });
          result = await platform(`reports/${record.id}/assistant`, {
            method: "POST",
            body: JSON.stringify({ question, consent: true }),
          });
        } else {
          const terms = question
            .toLowerCase()
            .split(/\W+/)
            .filter((x) => x.length > 2);
          const evidence = [...findings()]
            .sort(
              (a, b) =>
                terms.filter((t) =>
                  (b.title + " " + b.remediation).toLowerCase().includes(t),
                ).length -
                terms.filter((t) =>
                  (a.title + " " + a.remediation).toLowerCase().includes(t),
                ).length,
            )
            .slice(0, 8);
          result = {
            mode: "evidence",
            summary: "Evidence retrieval only. No AI generation was performed.",
            evidence,
          };
        }
        out.innerHTML = `<p class="tag">${result.mode === "llm" ? "AI-GENERATED ADVICE · REVIEW REQUIRED" : "EVIDENCE MODE"}</p><p>${escape(result.summary)}</p>${result.evidence.map((f) => `<article class="evidence-card"><strong>${escape(f.title)}</strong><p>${escape(f.severity)} · ${escape(f.verification)} · ${escape(f.confidence)} confidence</p><code>${escape(f.operation)}</code><p>${escape(f.remediation)}</p><small>Source: ${escape(f.id)}</small></article>`).join("") || "<p>No findings in this report. This does not establish that the API is secure.</p>"}`;
      } catch (err) {
        out.textContent = err.message;
      }
    };
  }
  function csv() {
    const fields = [
      "severity",
      "verification",
      "confidence",
      "title",
      "operation",
      "remediation",
    ];
    const cell = (v) =>
      '"' +
      String(v ?? "")
        .replace(/^[\s]*[=+@-]/, (x) => "'" + x)
        .replace(/"/g, '""') +
      '"';
    download(
      [fields, ...findings().map((f) => fields.map((k) => f[k]))]
        .map((row) => row.map(cell).join(","))
        .join("\r\n"),
      "csv",
      "text/csv",
    );
  }
  function printReport() {
    if (!state.report) return;
    const w = window.open("", "_blank");
    if (!w) {
      toast("Allow the report window to open, then choose Save as PDF.");
      return;
    }
    w.opener = null;
    w.document.write(
      `<!doctype html><html><head><meta charset="utf-8"><title>OnescanX report</title><style>body{font:14px/1.6 system-ui;margin:40px}article{break-inside:avoid;border-top:1px solid #ccc;padding:16px 0}code,p{overflow-wrap:anywhere}</style></head><body><h1>OnescanX security assessment</h1><p>${escape(state.report.target)}</p>${findings()
        .map(
          (f) =>
            `<article><h2>${escape(f.severity)}: ${escape(f.title)}</h2><p>${escape(f.verification)} / ${escape(f.confidence)}</p><code>${escape(f.operation)}</code><p>${escape(f.description)}</p><p>${escape(f.remediation)}</p></article>`,
        )
        .join(
          "",
        )}<h2>Limitations</h2>${state.report.limitations.map((x) => `<p>${escape(x)}</p>`).join("")}</body></html>`,
    );
    w.document.close();
    w.print();
  }
  function renderReports() {
    $("reports-view").innerHTML =
      `<article class="panel guide-card"><h2>Current assessment</h2><p>JSON preserves evidence for reimport. CSV is spreadsheet-safe. Print / Save PDF uses your browser; connected reports also support server-generated PDF.</p><div class="report-actions">${button("report-json", "Export JSON")}${button("report-csv", "Export CSV")}${button("report-pdf", "Print / Save PDF")}${button("save-device", "Save report on this device")}${button("save-server", "Save to platform")}</div><p>Device storage is optional and contains the entire selected report. Use export instead on shared computers.</p></article><article class="panel guide-card"><h2>Saved on this device</h2>${
        saved()
          .map(
            (r, i) =>
              `<div class="history-row"><span>${escape(r.target)} · ${escape(r.finished_at || r.started_at)}</span><button data-open-saved="${i}" class="button secondary">Open</button></div>`,
          )
          .join("") || "<p>No reports saved yet.</p>"
      }<div id="platform-reports"></div></article>`;
    $("report-json").onclick = () =>
      download(
        JSON.stringify(state.report, null, 2),
        "json",
        "application/json",
      );
    $("report-csv").onclick = csv;
    $("report-pdf").onclick = printReport;
    $("save-device").onclick = () => {
      saveCurrent();
      renderReports();
    };
    $("save-server").onclick = async () => {
      try {
        await platform("reports", {
          method: "POST",
          body: JSON.stringify(state.report),
        });
        toast("Report saved to platform");
        loadRemoteReports();
      } catch (e) {
        toast(e.message);
      }
    };
    $("reports-view").onclick = (e) => {
      const b = e.target.closest("[data-open-saved]");
      if (b) {
        selectReport(saved()[+b.dataset.openSaved], "import");
        changeView("overview");
      }
    };
    if (connected) loadRemoteReports();
  }
  async function loadRemoteReports() {
    try {
      const records = await platform("reports");
      $("platform-reports").innerHTML =
        "<h3>Platform reports</h3>" +
        records
          .map(
            (r) =>
              `<div class="history-row"><span>${escape(r.target)}</span><button data-open-remote="${escape(r.id)}" class="text-button">Open</button><a href="/api/platform/reports/${escape(r.id)}/export/pdf">PDF</a></div>`,
          )
          .join("");
      $("platform-reports").onclick = async (e) => {
        const b = e.target.closest("[data-open-remote]");
        if (b) {
          try {
            selectReport(
              await platform("reports/" + b.dataset.openRemote),
              "import",
            );
            changeView("overview");
          } catch (err) {
            toast(err.message);
          }
        }
      };
    } catch (e) {
      toast(e.message);
    }
  }
  function renderIntegrations() {
    $("integrations-view").innerHTML =
      notice() +
      `<article class="panel guide-card"><h2>GitHub specification import</h2><p>Fetch an explicit specification file from a public repository. Importing does not authorize a scan. Private repository OAuth is not configured in this workspace.</p><form id="github-form"><label>Repository<input id="github-repo" placeholder="owner/repository" required></label><label>File path<input id="github-path" placeholder="openapi.json" required></label><label>Branch or commit<input id="github-ref" value="main" required></label><button class="button primary">Import specification</button></form><p id="github-result" role="status"></p></article><article class="panel guide-card"><h2>Backend services</h2><p>PostgreSQL stores inventory, reports, schedules, sessions, and audit events. Redis transports task IDs to Celery. Model credentials remain on the backend.</p><a href="https://github.com/aashleshshet/Scanx/blob/main/docs/platform/INSTALL.md" target="_blank" rel="noopener">Docker and cloud setup guide</a></article>`;
    $("github-form").onsubmit = async (e) => {
      e.preventDefault();
      try {
        const q = new URLSearchParams({
          repo: $("github-repo").value,
          path: $("github-path").value,
          ref: $("github-ref").value,
        });
        const response = await fetch("/api/integrations/github?" + q);
        const data = await response.json();
        if (!response.ok) throw Error(data.detail);
        importedSpec = data.content;
        inventory = discover(JSON.parse(data.content));
        $("github-result").textContent =
          "Imported " +
          inventory.length +
          " operations from commit/blob " +
          data.sha;
        toast("Open API Inventory to review imported endpoints");
      } catch (err) {
        $("github-result").textContent =
          err.message +
          " For YAML, download the file and use the local scanner.";
      }
    };
  }
  function renderSettings() {
    $("settings-view").innerHTML =
      notice() +
      `<article class="panel guide-card"><h2>Platform session</h2><p>Vercel protects this website. The optional backend uses its own eight-hour HttpOnly session for the operator workspace.</p><form id="platform-login"><label>Backend operator password<input id="platform-password" type="password" autocomplete="current-password" required></label><button class="button primary">Connect platform session</button></form>${button("platform-logout", "Sign out of backend")}${button("platform-refresh", "Refresh connection status")}</article><article class="panel guide-card"><h2>Device data</h2><p>${saved().length} reports stored on this device. Appearance is the only preference saved automatically.</p>${button("clear-device", "Remove saved reports")}<p>Use the appearance button in the header to switch light and dark modes.</p></article><article class="panel guide-card"><h2>Audit trail</h2><p>Server-side audit records contain actions, IDs, and timestamps—not passwords or scan tokens.</p>${button("load-audit", "Load recent audit events")}<pre id="audit-events"></pre></article>`;
    $("platform-login").onsubmit = async (e) => {
      e.preventDefault();
      try {
        await platform("session/login", {
          method: "POST",
          body: JSON.stringify({ password: $("platform-password").value }),
        });
        $("platform-password").value = "";
        await refresh();
        toast("Platform session connected");
      } catch (err) {
        $("platform-password").value = "";
        toast(err.message);
      }
    };
    $("platform-logout").onclick = async () => {
      try {
        await platform("session/logout", { method: "POST" });
      } catch {}
      connected = false;
      renderSettings();
    };
    $("platform-refresh").onclick = () => refresh();
    $("clear-device").onclick = () => {
      try {
        localStorage.removeItem(key);
        renderSettings();
        toast("Saved device reports removed");
      } catch {
        toast("Device storage unavailable");
      }
    };
    $("load-audit").onclick = async () => {
      try {
        $("audit-events").textContent = JSON.stringify(
          await platform("audit"),
          null,
          2,
        );
      } catch (err) {
        toast(err.message);
      }
    };
  }
  const renderers = {
    inventory: renderInventory,
    newscan: renderNewScan,
    analytics: renderAnalytics,
    assistant: renderAssistant,
    reports: renderReports,
    integrations: renderIntegrations,
    settings: renderSettings,
  };
  async function refresh(render = true) {
    try {
      const status = await platform("status");
      connected = !!status.connected;
      if (connected)
        [remote, schedules] = await Promise.all([
          platform("inventory"),
          platform("schedules"),
        ]);
    } catch {
      connected = false;
    }
    if (render) renderers[state.view]?.();
  }
  document.addEventListener("onescanx:view", (e) => renderers[e.detail]?.());
  document.addEventListener("onescanx:report", () => renderers[state.view]?.());
  const pages = [...document.querySelectorAll("[data-view]")].map((b) => ({
    view: b.dataset.view,
    label: b.textContent.replace(/\d+$/, "").trim(),
  }));
  function commands() {
    const q = $("command-search").value.toLowerCase();
    $("command-results").innerHTML = pages
      .filter((p) => p.label.toLowerCase().includes(q))
      .map(
        (p) => `<button data-command="${p.view}">${escape(p.label)}</button>`,
      )
      .join("");
  }
  $("command-open").onclick = () => {
    commands();
    $("command-dialog").showModal();
    $("command-search").focus();
  };
  $("mobile-more").onclick = () => $("command-open").click();
  $("command-search").oninput = commands;
  $("command-results").onclick = (e) => {
    const b = e.target.closest("[data-command]");
    if (b) {
      $("command-dialog").close();
      changeView(b.dataset.command);
    }
  };
  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      $("command-open").click();
    }
  });
  refresh(false);
})();
