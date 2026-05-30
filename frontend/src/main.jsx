import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  AlertCircle,
  Calendar,
  ChevronDown,
  ChevronUp,
  Clock3,
  FileText,
  FileWarning,
  Fingerprint,
  HelpCircle,
  Inbox,
  Link,
  MailCheck,
  RefreshCw,
  Route,
  ShieldCheck,
  UploadCloud,
  XCircle
} from "lucide-react";
import "./styles.css";

const EMPTY_ANALYSIS = {
  subject: "",
  from: "",
  to: "",
  date: "",
  message_id: "",
  reply_to: "",
  return_path: "",
  user_agent: "",
  authentication_results: "",
  spf: "",
  dkim_signature: "",
  body: "",
  attachments: [],
  urls: [],
  risk: {
    score: 0,
    severity: "low",
    findings: [],
    signals: {}
  },
  authentication: {
    spf: { name: "SPF", result: "unknown", passed: false, source: "Not found", details: "" },
    dkim: { name: "DKIM", result: "unknown", passed: false, source: "Not found", details: "" },
    dmarc: { name: "DMARC", result: "unknown", passed: false, source: "Not found", details: "" }
  },
  hops: 0,
  received_path: [],
  summary: "",
  verdict: ""
};

function App() {
  const [file, setFile] = useState(null);
  const [sample, setSample] = useState(null);
  const [status, setStatus] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [emailPreviewOpen, setEmailPreviewOpen] = useState(true);
  const [uploadCollapsed, setUploadCollapsed] = useState(false);
  const [lookup, setLookup] = useState({ loading: false, result: null, error: "" });

  const analysis = status?.analysis || null;
  const displayAnalysis = analysis || EMPTY_ANALYSIS;
  const authentication = displayAnalysis.authentication || EMPTY_ANALYSIS.authentication;
  const currentStatus = status?.status || sample?.status || "idle";
  const hasSampleContext = Boolean(file || sample);
  const hasAnalysisContext = Boolean(sample || analysis);
  const hopDomains = extractHopDomains(displayAnalysis.received_path);
  const attachments = displayAnalysis.attachments || [];
  const riskyAttachments = attachments.filter((attachment) => attachment.risky);
  const urls = displayAnalysis.urls || [];
  const suspiciousUrls = urls.filter((url) => url.risk === "suspicious");
  const risk = displayAnalysis.risk || EMPTY_ANALYSIS.risk;

  useEffect(() => {
    if (!sample?.id || currentStatus === "done" || currentStatus === "failed") {
      return undefined;
    }

    const timer = window.setTimeout(() => {
      fetchStatus(sample.id, { silent: true });
    }, 2000);

    return () => window.clearTimeout(timer);
  }, [sample?.id, currentStatus]);

  async function uploadSample(event) {
    event.preventDefault();

    if (!file) {
      setError("Choose an EML file first.");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    setBusy(true);
    setError("");
    setStatus(null);

    try {
      const response = await fetch("/api/upload/", {
        method: "POST",
        body: formData
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Upload failed.");
      }

      setSample(data);
      setUploadCollapsed(true);
      await fetchStatus(data.id, { silent: true });
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function fetchStatus(sampleId = sample?.id, options = {}) {
    if (!sampleId) return;

    if (!options.silent) {
      setBusy(true);
    }
    setError("");

    try {
      const response = await fetch(`/api/upload/${sampleId}/`);
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Could not load analysis.");
      }

      setStatus(data);
    } catch (err) {
      setError(err.message);
    } finally {
      if (!options.silent) {
        setBusy(false);
      }
    }
  }

  async function lookupValue(value) {
    if (!value) return;

    setLookup({ loading: true, result: null, error: "" });

    try {
      const response = await fetch(`/api/lookup/?q=${encodeURIComponent(value)}`);
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Lookup failed.");
      }

      setLookup({ loading: false, result: data, error: "" });
    } catch (err) {
      setLookup({ loading: false, result: null, error: err.message });
    }
  }

  function resetUpload() {
    setFile(null);
    setSample(null);
    setStatus(null);
    setError("");
    setUploadCollapsed(false);
    setLookup({ loading: false, result: null, error: "" });
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-icon" aria-hidden="true">
            <MailCheck size={26} />
          </div>
          <div>
            <h1>EML Analyzer</h1>
            <p>Header intelligence workspace</p>
          </div>
        </div>

        <div className="topbar-actions">
          <StatusBadge status={currentStatus} />
          <button
            className="icon-button"
            type="button"
            onClick={() => fetchStatus()}
            disabled={!sample || busy}
            aria-label="Refresh status"
            title="Refresh status"
          >
            <RefreshCw size={18} />
          </button>
        </div>
      </header>

      <section className="dashboard">
        <section className={sample && uploadCollapsed ? "panel upload-panel collapsed" : "panel upload-panel"}>
          {sample && uploadCollapsed ? (
            <div className="upload-collapsed">
              <div className="upload-collapsed-summary">
                <MailCheck size={24} />
                <div>
                  <strong>{sample.original_name}</strong>
                  <span>{sample?.id ? `Sample #${sample.id}` : "Sample uploaded"}</span>
                </div>
              </div>
              <div className="upload-collapsed-actions">
                <button
                  className="icon-button"
                  type="button"
                  onClick={() => setUploadCollapsed(false)}
                  aria-label="Expand upload panel"
                  title="Expand upload panel"
                >
                  <ChevronDown size={18} />
                </button>
                <button type="button" onClick={resetUpload}>Analyze another</button>
              </div>
            </div>
          ) : (
            <>
              {!sample ? (
                <form onSubmit={uploadSample} className="upload-form">
                  <label className={file ? "drop-zone has-file" : "drop-zone"}>
                    <input
                      type="file"
                      accept=".eml,message/rfc822"
                      onChange={(event) => setFile(event.target.files[0] || null)}
                    />
                    <UploadCloud size={34} />
                    <span>{file ? file.name : "Select EML file"}</span>
                    <small>{file ? formatBytes(file.size) : "message/rfc822 or .eml"}</small>
                  </label>

                  <button className="primary-button" type="submit" disabled={busy}>
                    <UploadCloud size={18} />
                    <span>{busy ? "Processing" : "Analyze"}</span>
                  </button>
                </form>
              ) : (
                <div className="upload-suppressed">
                  <MailCheck size={26} />
                  <div>
                    <strong>Sample uploaded</strong>
                    <span>{sample.original_name}</span>
                  </div>
                  <div className="upload-suppressed-actions">
                    <button type="button" onClick={() => setUploadCollapsed(true)}>
                      <ChevronUp size={16} />
                      <span>Collapse</span>
                    </button>
                    <button type="button" onClick={resetUpload}>Analyze another</button>
                  </div>
                </div>
              )}

              {hasSampleContext && (
                <div className="upload-sample-section">
                  <h2>Sample</h2>
                  <dl className="sample-list">
                    <Meta icon={FileText} label="Name" value={sample?.original_name || file?.name || "No file selected"} />
                    <Meta icon={Inbox} label="Sample ID" value={sample?.id ? `#${sample.id}` : "Pending"} />
                    <Meta icon={Fingerprint} label="SHA-256" value={sample?.sha256 || "Unavailable"} mono />
                    <Meta icon={Clock3} label="Created" value={status?.created_at ? formatDate(status.created_at) : "Pending"} />
                  </dl>
                </div>
              )}
            </>
          )}

          {error && (
            <div className="alert">
              <AlertCircle size={18} />
              <span>{error}</span>
            </div>
          )}
        </section>

        <section className="content">
          {!hasAnalysisContext ? (
            <section className="panel ready-panel">
              <div className="ready-icon" aria-hidden="true">
                <MailCheck size={34} />
              </div>
              <h2>Ready to inspect an email</h2>
              <p>Select an `.eml` file to show the preview, authentication results, headers, and received path.</p>
            </section>
          ) : (
            <>
              <div className="status-strip">
                <Stat icon={Activity} label="State" value={currentStatus} tone={toneForStatus(currentStatus)} />
                <Stat icon={ShieldCheck} label="Severity" value={risk.severity || "waiting"} tone={toneForRiskSeverity(risk.severity)} />
                <Stat icon={AlertCircle} label="Risk" value={`${risk.score ?? 0}/100`} tone={toneForRiskSeverity(risk.severity)} />
                <Stat icon={FileWarning} label="Attachments" value={String(attachments.length)} tone={riskyAttachments.length ? "red" : "neutral"} />
                <Stat icon={Link} label="URLs" value={String(urls.length)} tone={suspiciousUrls.length ? "red" : "neutral"} />
              </div>

              {analysis && (
                <>
                  <div className="analysis-layout">
                    <section className="panel hero-panel">
                      <div className="hero-copy">
                        <div className="eyebrow">Analysis Summary</div>
                        <h2>{analysis?.subject || "Analysis queued"}</h2>
                        <p>{analysis?.summary || "The sample is uploaded. Refresh or wait while analysis finishes."}</p>
                      </div>
                    </section>

                    <RiskPanel risk={risk} />

                    <section className="panel sender-panel">
                      <div className="panel-heading">
                        <h2>Sender Details</h2>
                        <span>{hopDomains.length} hop domains</span>
                      </div>
                      <dl className="sender-detail-list">
                        <LookupField label="Sender" value={displayAnalysis.from} onLookup={lookupValue} />
                        <LookupField label="Return Path" value={displayAnalysis.return_path} onLookup={lookupValue} />
                      </dl>
                      <div className="domain-section">
                        <dt>Domains Mentioned In Hops</dt>
                        {hopDomains.length ? (
                          <div className="domain-chips">
                            {hopDomains.map((domain) => (
                              <button type="button" key={domain} onClick={() => lookupValue(domain)}>
                                {domain}
                              </button>
                            ))}
                          </div>
                        ) : (
                          <p>No domains found in received hops.</p>
                        )}
                      </div>
                      {(lookup.loading || lookup.result || lookup.error) && (
                        <LookupResult loading={lookup.loading} result={lookup.result} error={lookup.error} />
                      )}
                    </section>

                    <section className="panel auth-panel">
                      <div className="panel-heading">
                        <h2>Authentication</h2>
                        <span>{displayAnalysis.authentication_results ? "present" : "missing"}</span>
                      </div>
                      <div className="auth-result-grid">
                        <AuthResultCard status={authentication.spf} />
                        <AuthResultCard status={authentication.dkim} />
                        <AuthResultCard status={authentication.dmarc} />
                      </div>
                      <div className="auth-stack">
                        <Evidence title="Received-SPF" value={displayAnalysis.spf} />
                        <Evidence title="DKIM Signature" value={displayAnalysis.dkim_signature} />
                        <Evidence title="Authentication Results" value={displayAnalysis.authentication_results} />
                      </div>
                    </section>

                    <section className="panel detail-panel">
                      <div className="panel-heading">
                        <h2>Message Headers</h2>
                        <span>parsed</span>
                      </div>
                      <dl className="field-grid">
                        <Field label="From" value={displayAnalysis.from} />
                        <Field label="To" value={displayAnalysis.to} />
                        <Field label="Reply To" value={displayAnalysis.reply_to} />
                        <Field label="Return Path" value={displayAnalysis.return_path} />
                        <Field label="Date" value={displayAnalysis.date} />
                        <Field label="Message ID" value={displayAnalysis.message_id} />
                        <Field label="User Agent" value={displayAnalysis.user_agent} />
                      </dl>
                    </section>

                    <section className="panel attachment-panel">
                      <div className="panel-heading">
                        <h2>Attachments</h2>
                        <span>{riskyAttachments.length ? `${riskyAttachments.length} risky` : `${attachments.length} found`}</span>
                      </div>
                      {attachments.length ? (
                        <div className="attachment-list">
                          {attachments.map((attachment) => (
                            <div className={attachment.risky ? "attachment-item risky" : "attachment-item"} key={`${attachment.index}-${attachment.sha256}`}>
                              <div className="attachment-name">
                                <FileText size={18} />
                                <strong>{attachment.filename}</strong>
                                <span>{attachment.risky ? "Risky extension" : "No extension flag"}</span>
                              </div>
                              <dl>
                                <LookupDatum label="MIME Type" value={attachment.content_type} />
                                <LookupDatum label="Size" value={formatBytes(attachment.size)} />
                                <LookupDatum label="Extension" value={attachment.extension || "none"} />
                                <LookupDatum label="SHA-256" value={attachment.sha256} />
                              </dl>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="empty-state">
                          <FileText size={22} />
                          <span>No attachments found.</span>
                        </div>
                      )}
                    </section>

                    <section className="panel url-panel">
                      <div className="panel-heading">
                        <h2>URL Analysis</h2>
                        <span>{suspiciousUrls.length ? `${suspiciousUrls.length} suspicious` : `${urls.length} found`}</span>
                      </div>
                      {urls.length ? (
                        <div className="url-list">
                          {urls.map((item) => (
                            <div className={item.risk === "suspicious" ? "url-item suspicious" : "url-item"} key={item.url}>
                              <div className="url-heading">
                                <Link size={18} />
                                <strong>{item.domain || item.url}</strong>
                                <span>{item.risk}</span>
                              </div>
                              <p>{item.url}</p>
                              <button className="lookup-link" type="button" onClick={() => lookupValue(item.url)}>
                                Check in lookup
                              </button>
                              <dl>
                                <LookupDatum label="Resolved IPs" value={item.resolved_ips?.join(", ")} />
                                <LookupDatum label="Final URL" value={item.final_url} />
                                <LookupDatum label="Redirects" value={String(Math.max((item.redirect_chain?.length || 1) - 1, 0))} />
                                <LookupDatum label="Flags" value={item.flags?.join(", ") || "none"} />
                              </dl>
                              {item.redirect_error && <div className="url-note">{item.redirect_error}</div>}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="empty-state">
                          <Link size={22} />
                          <span>No URLs found.</span>
                        </div>
                      )}
                    </section>

                    <section className={emailPreviewOpen ? "panel email-preview open" : "panel email-preview"}>
                      <button
                        className="email-preview-toggle"
                        type="button"
                        onClick={() => setEmailPreviewOpen((open) => !open)}
                        aria-expanded={emailPreviewOpen}
                      >
                        <span>Email Preview</span>
                        {emailPreviewOpen ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                      </button>

                      {emailPreviewOpen && (
                        <div className="mail-window">
                          <div className="mail-toolbar" aria-hidden="true">
                            <span></span>
                            <span></span>
                            <span></span>
                          </div>
                          <div className="mail-header">
                            <div className="avatar" aria-hidden="true">{initials(displayAnalysis.from)}</div>
                            <div className="mail-title">
                              <h2>{displayAnalysis.subject || "No subject"}</h2>
                              <p>{displayAnalysis.from || "Unknown sender"}</p>
                            </div>
                            <div className="mail-date">
                              <Calendar size={16} />
                              <span>{displayAnalysis.date || "No date"}</span>
                            </div>
                          </div>

                          <dl className="mail-meta">
                            <EmailMeta label="From" value={displayAnalysis.from} />
                            <EmailMeta label="To" value={displayAnalysis.to} />
                            <EmailMeta label="Date" value={displayAnalysis.date} />
                            <EmailMeta label="Subject" value={displayAnalysis.subject} />
                          </dl>

                          <div className="mail-body">
                            {displayAnalysis.body ? (
                              <p>{displayAnalysis.body}</p>
                            ) : (
                              <div className="empty-mail">No plain-text message content found.</div>
                            )}
                          </div>
                        </div>
                      )}
                    </section>

                    <section className="panel route-panel">
                      <div className="panel-heading">
                        <h2>Received Path</h2>
                        <span>{displayAnalysis.received_path?.length || 0} hops</span>
                      </div>

                      {displayAnalysis.received_path?.length ? (
                        <ol className="hop-list">
                          {displayAnalysis.received_path.map((hop, index) => (
                            <li key={`${index}-${hop}`}>
                              <div className="hop-number">{index + 1}</div>
                              <p>{hop}</p>
                            </li>
                          ))}
                        </ol>
                      ) : (
                        <div className="empty-state">
                          <Route size={22} />
                          <span>No received path available.</span>
                        </div>
                      )}
                    </section>
                  </div>
                </>
              )}
            </>
          )}
        </section>
      </section>
    </main>
  );
}

function StatusBadge({ status }) {
  const normalized = status || "idle";
  return <span className={`status-badge ${toneForStatus(normalized)}`}>{normalized}</span>;
}

function Stat({ icon: Icon, label, value, tone }) {
  return (
    <div className={`stat ${tone}`}>
      <Icon size={20} />
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
    </div>
  );
}

function Meta({ icon: Icon, label, value, mono }) {
  return (
    <div>
      <Icon size={17} />
      <dt>{label}</dt>
      <dd className={mono ? "mono" : undefined}>{value}</dd>
    </div>
  );
}

function Field({ label, value }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value || "N/A"}</dd>
    </div>
  );
}

function LookupField({ label, value, onLookup }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>
        {value ? (
          <button className="lookup-link" type="button" onClick={() => onLookup(value)}>
            {value}
          </button>
        ) : (
          "N/A"
        )}
      </dd>
    </div>
  );
}

function RiskPanel({ risk }) {
  const findings = risk?.findings || [];
  const score = Math.max(0, Math.min(Number(risk?.score || 0), 100));
  const severity = risk?.severity || "low";

  return (
    <section className={`panel risk-panel ${severity}`}>
      <div className="risk-score-card">
        <div>
          <div className="eyebrow">Risk Assessment</div>
          <h2>{severity}</h2>
          <p>{findings.length ? `${findings.length} finding${findings.length === 1 ? "" : "s"} contributed to this score.` : "No risk findings were generated from the extracted evidence."}</p>
        </div>
        <div className="risk-score" aria-label={`Risk score ${score} out of 100`}>
          <strong>{score}</strong>
          <span>/100</span>
        </div>
      </div>

      <div className="risk-meter" aria-hidden="true">
        <span style={{ width: `${score}%` }}></span>
      </div>

      {findings.length ? (
        <div className="finding-list">
          {findings.map((finding) => (
            <article className={`finding-item ${finding.severity}`} key={finding.id}>
              <div className="finding-heading">
                <strong>{finding.title}</strong>
                <span>{finding.points} pts</span>
              </div>
              <p>{finding.details}</p>
              <div className="finding-meta">
                <span>{finding.category}</span>
                <span>{finding.severity}</span>
              </div>
            </article>
          ))}
        </div>
      ) : (
        <div className="empty-state compact">
          <ShieldCheck size={22} />
          <span>No explainable findings for this sample.</span>
        </div>
      )}
    </section>
  );
}

function EmailMeta({ label, value }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value || "N/A"}</dd>
    </div>
  );
}

function LookupResult({ loading, result, error }) {
  if (loading) {
    return <div className="lookup-result">Looking up indicator...</div>;
  }

  if (error) {
    return <div className="lookup-result lookup-error">{error}</div>;
  }

  if (!result) return null;

  const owner = result.rdap?.owner || result.rdap?.name || result.virustotal?.as_owner;

  return (
    <div className="lookup-result">
      <div className="lookup-result-heading">
        <strong>{result.normalized}</strong>
        <span>{result.type}</span>
      </div>
      <dl className="lookup-grid">
        <LookupDatum label="Domain" value={result.domain} />
        <LookupDatum label="IP Addresses" value={result.ip_addresses?.join(", ")} />
        <LookupDatum label="Owner / Name" value={owner} />
        <LookupDatum label="Registrar" value={result.rdap?.registrar} />
        <LookupDatum label="Handle" value={result.rdap?.handle} />
        <LookupDatum label="Country" value={result.rdap?.country || result.virustotal?.country} />
      </dl>
      <VirusTotalResult result={result.virustotal} />
      {result.rdap?.entities?.length > 0 && (
        <div className="lookup-entities">
          <dt>RDAP Entities</dt>
          {result.rdap.entities.map((entity, index) => (
            <span key={`${entity.name}-${index}`}>
              {entity.name || "Unknown"} {entity.roles?.length ? `(${entity.roles.join(", ")})` : ""}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function VirusTotalResult({ result }) {
  if (!result) return null;

  if (!result.available) {
    return (
      <div className="vt-result unavailable">
        <dt>VirusTotal</dt>
        <dd>{result.error || result.reason || "Unavailable"}</dd>
      </div>
    );
  }

  return (
    <div className={result.malicious || result.suspicious ? "vt-result flagged" : "vt-result"}>
      <div className="vt-heading">
        <dt>VirusTotal</dt>
        {result.gui_url && (
          <a href={result.gui_url} target="_blank" rel="noreferrer">
            Open report
          </a>
        )}
      </div>
      <dl className="lookup-grid vt-grid">
        <LookupDatum label="Malicious" value={String(result.malicious ?? 0)} />
        <LookupDatum label="Suspicious" value={String(result.suspicious ?? 0)} />
        <LookupDatum label="Harmless" value={String(result.harmless ?? 0)} />
        <LookupDatum label="Undetected" value={String(result.undetected ?? 0)} />
        <LookupDatum label="Reputation" value={String(result.reputation ?? "N/A")} />
        <LookupDatum label="ASN / Owner" value={[result.asn, result.as_owner].filter(Boolean).join(" ")} />
        <LookupDatum label="Country" value={result.country} />
        <LookupDatum label="Categories" value={result.categories?.join(", ")} />
      </dl>
    </div>
  );
}

function LookupDatum({ label, value }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value || "N/A"}</dd>
    </div>
  );
}

function extractHopDomains(receivedPath = []) {
  const domains = new Set();
  const domainPattern = /\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g;

  for (const hop of receivedPath || []) {
    for (const match of String(hop).matchAll(domainPattern)) {
      domains.add(match[0].toLowerCase());
    }
  }

  return Array.from(domains).sort();
}

function AuthResultCard({ status }) {
  const tone = toneForAuthResult(status?.result);
  const Icon = status?.result === "pass" ? ShieldCheck : status?.result === "unknown" ? HelpCircle : XCircle;

  return (
    <div className={`auth-result-card ${tone}`}>
      <div className="auth-result-icon">
        <Icon size={22} />
      </div>
      <div>
        <strong>{status?.name}</strong>
        <span>{status?.result || "unknown"}</span>
      </div>
      <small>{status?.source || "Not found"}</small>
    </div>
  );
}

function Evidence({ title, value }) {
  return (
    <div className={value ? "evidence present" : "evidence"}>
      <div>
        <strong>{title}</strong>
        <span>{value ? "detected" : "not found"}</span>
      </div>
      <p>{value || "N/A"}</p>
    </div>
  );
}

function toneForAuthResult(result) {
  if (result === "pass") return "pass";
  if (result === "unknown" || result === "none") return "unknown";
  return "fail";
}

function toneForStatus(status) {
  if (status === "done" || status === "parsed") return "green";
  if (status === "failed" || status === "error") return "red";
  if (status === "queued" || status === "processing") return "amber";
  return "neutral";
}

function toneForRiskSeverity(severity) {
  if (severity === "critical" || severity === "high") return "red";
  if (severity === "medium") return "amber";
  if (severity === "low") return "green";
  return "neutral";
}

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** index;
  return `${value.toFixed(value >= 10 || index === 0 ? 0 : 1)} ${units[index]}`;
}

function formatDate(value) {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value));
}

function initials(value) {
  const match = String(value || "").match(/[A-Za-z0-9]+/g);
  if (!match?.length) return "EM";
  return match.slice(0, 2).map((part) => part[0]).join("").toUpperCase();
}

createRoot(document.getElementById("root")).render(<App />);
