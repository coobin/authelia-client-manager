import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  KeyRound,
  Plus,
  Search,
  ArrowLeft,
  Check,
  ShieldCheck,
  RefreshCw,
  LogOut,
  Copy,
  X,
  ClipboardList,
  Layers,
  History,
  LockKeyhole,
} from "lucide-react";
import "./style.css";
import QRCode from "qrcode";
type Client = {
  client_id: string;
  client_name: string;
  public?: boolean;
  redirect_uris: string[];
  scopes: string[];
  authorization_policy?: string;
  require_pkce?: boolean;
  pkce_challenge_method?: string;
  token_endpoint_auth_method?: string;
  grant_types?: string[];
  response_types?: string[];
  editable?: boolean;
  has_secret?: boolean;
  owner?: string;
  environment?: string;
  extra_fields?: string[];
  disabled?: boolean;
  restore_id?: string;
};
type Inventory = {
  revision: string;
  clients: Client[];
  issuer: string;
  writable: boolean;
  demo: boolean;
};
type Form = {
  client: Client;
  owner: string;
  environment: string;
  operation: string;
};
const labels: Record<string, string> = {
  upsert: "应用配置",
  disable: "停用应用",
  rotate: "轮换密钥",
  restore: "恢复应用",
  rollback: "恢复配置",
  queued: "等待执行",
  writing: "应用配置中",
  checking: "检查服务中",
  applied: "已生效",
  rolled_back: "已恢复",
  rolling_back: "正在恢复",
  failed: "未发布",
  attention: "需要处理",
  development: "开发",
  test: "测试",
  production: "生产",
  unclassified: "待补充",
};
let csrf = "";
async function api(path: string, body?: unknown) {
  const r = await fetch("/api" + path, {
    method: body === undefined ? "GET" : "POST",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const d = await r.json();
  if (!r.ok) {
    const error = new Error(
      typeof d.detail === "string" ? d.detail : "输入不正确",
    ) as Error & { totpRequired?: boolean };
    error.totpRequired = r.headers.get("X-ACM-TOTP-Required") === "1";
    throw error;
  }
  return d;
}
// LAN HTTP origins do not expose randomUUID or the async Clipboard API.
function newClientId() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return (
    "acm-" +
    Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("")
  );
}
async function copyText(value: string) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const field = document.createElement("textarea");
  field.value = value;
  field.className = "clipboard-helper";
  field.readOnly = true;
  field.setAttribute("aria-hidden", "true");
  const active = document.activeElement as HTMLElement | null;
  document.body.appendChild(field);
  try {
    field.select();
    field.setSelectionRange(0, field.value.length);
    if (!document.execCommand("copy")) throw new Error("请选中文字手动复制");
  } finally {
    field.remove();
    active?.focus();
  }
}

function App() {
  const [me, setMe] = useState<any>(null),
    [loaded, setLoaded] = useState(false),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [busy, setBusy] = useState(false);
  const [inv, setInv] = useState<Inventory | null>(null),
    [tab, setTab] = useState("clients"),
    [query, setQuery] = useState(""),
    [jobs, setJobs] = useState<any[]>([]),
    [drafts, setDrafts] = useState<any[]>([]),
    [audit, setAudit] = useState<any[]>([]),
    [deliveries, setDeliveries] = useState<any[]>([]);
  const [form, setForm] = useState<Form | null>(null),
    [draftId, setDraftId] = useState(""),
    [checked, setChecked] = useState(false),
    [ack, setAck] = useState(false),
    [params, setParams] = useState(""),
    [secret, setSecret] = useState(""),
    [changes, setChanges] = useState<any[]>([]);
  const [login, setLogin] = useState({ username: "", password: "", code: "" }),
    [reauth, setReauth] = useState(false),
    [reauthData, setReauthData] = useState({ password: "", code: "" });
  const [setupRequired, setSetupRequired] = useState(false),
    [confirmPassword, setConfirmPassword] = useState(""),
    [loginTotp, setLoginTotp] = useState(false);
  const admin = me?.role === "admin";
  async function run(fn: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await fn();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function refresh() {
    const [i, j, d] = await Promise.all([
      api("/clients"),
      api("/deployments"),
      api("/drafts"),
    ]);
    setInv(i);
    setJobs(j);
    setDrafts(d);
    if (admin) setDeliveries(await api("/deliveries"));
  }
  useEffect(() => {
    api("/auth/status")
      .then(async (status) => {
        setSetupRequired(status.setup_required);
        if (!status.setup_required) {
          try {
            const m = await api("/me");
            csrf = m.csrf;
            setMe(m);
          } catch {}
        }
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoaded(true));
  }, []);
  useEffect(() => {
    if (me) run(refresh);
  }, [me]);
  useEffect(() => {
    if (!me) return;
    const id = setInterval(() => {
      if (
        jobs.some((j) =>
          ["queued", "writing", "checking", "rolling_back"].includes(j.state),
        )
      )
        refresh().catch(() => {});
    }, 3000);
    return () => clearInterval(id);
  }, [me, jobs, admin]);
  function open(c?: Client, op = "upsert") {
    const id = newClientId();
    setForm({
      client: c
        ? { ...c }
        : {
            client_id: id,
            client_name: "",
            public: false,
            redirect_uris: [""],
            scopes: ["openid", "profile", "email"],
            authorization_policy: "one_factor",
            require_pkce: true,
            pkce_challenge_method: "S256",
            token_endpoint_auth_method: "client_secret_basic",
            grant_types: ["authorization_code"],
            response_types: ["code"],
          },
      owner: c?.owner || "",
      environment:
        c?.environment && c.environment !== "unclassified"
          ? c.environment
          : "production",
      operation: op,
    });
    setDraftId("");
    setChecked(false);
    setAck(false);
    setError("");
  }
  function field(k: string, v: unknown) {
    if (!form) return;
    setForm({ ...form, client: { ...form.client, [k]: v } });
    setDraftId("");
    setChecked(false);
  }
  async function save() {
    if (!form || !inv) return;
    const c = form.client;
    const safe = Object.fromEntries(
      [
        "client_id",
        "client_name",
        "public",
        "redirect_uris",
        "scopes",
        "authorization_policy",
        "require_pkce",
        "pkce_challenge_method",
        "token_endpoint_auth_method",
        "grant_types",
        "response_types",
      ]
        .filter((k) => (c as any)[k] !== undefined)
        .map((k) => [k, (c as any)[k]]),
    );
    const d = await api("/drafts", {
      ...form,
      restore_id: form.client.restore_id,
      client: safe,
      revision: inv.revision,
    });
    setDraftId(d.id);
    const result = await api("/drafts/" + d.id + "/validate", {});
    setChanges(result.changes || []);
    setChecked(true);
    setNotice(inv.demo ? "演示检查通过" : "Authelia 配置检查通过");
    await refresh();
  }
  async function publish() {
    await api("/deployments", { draft_id: draftId, acknowledge_restart: ack });
    setForm(null);
    setTab("jobs");
    setNotice("发布任务已提交，可以在记录中查看结果");
    await refresh();
  }
  function parameter(c: Client) {
    setParams(
      `应用：${c.client_name}\nIssuer：${inv?.issuer}\n自动发现：${inv?.issuer}/.well-known/openid-configuration\nClient ID：${c.client_id}\n登录流程：Authorization Code\nPKCE：${c.require_pkce === false ? "未强制" : "S256"}\nScope：${c.scopes.join(" ")}\n客户端认证：${c.token_endpoint_auth_method || (c.public ? "none" : "client_secret_basic")}\n回调地址：\n${c.redirect_uris.join("\n")}\n\n${c.public ? "公共客户端，无客户端密钥" : "Client Secret 通过单独的安全渠道交付"}`,
    );
  }
  if (!loaded) return <div className="loading">正在打开管理工具…</div>;
  if (!me)
    return (
      <main className="login-page">
        <div className="login-brand">
          <KeyRound size={40} />
          <h1>
            统一认证
            <br />
            应用管理
          </h1>
          <p>集中登记应用，安全发布接入配置。</p>
          <span>Authelia Client Manager</span>
        </div>
        <form
          className="login-form"
          onSubmit={(e) => {
            e.preventDefault();
            run(async () => {
              if (setupRequired && login.password !== confirmPassword)
                throw new Error("两次输入的密码不一致");
              try {
                const m = await api(
                  setupRequired ? "/setup" : "/login",
                  setupRequired
                    ? {
                        username: login.username,
                        password: login.password,
                        confirm_password: confirmPassword,
                      }
                    : login,
                );
                csrf = m.csrf;
                setMe(await api("/me"));
                setSetupRequired(false);
                setLogin({ username: "", password: "", code: "" });
                setConfirmPassword("");
                setLoginTotp(false);
              } catch (e) {
                if ((e as any).totpRequired) setLoginTotp(true);
                throw e;
              }
            });
          }}
        >
          <ShieldCheck size={28} />
          <h2>{setupRequired ? "创建管理员账户" : "管理员登录"}</h2>
          <p>
            {setupRequired
              ? "设置你的账号和密码，完成后即可开始使用。"
              : "输入账号和密码登录。"}
          </p>
          <label>
            账号
            <input
              required
              autoComplete="username"
              minLength={setupRequired ? 3 : 1}
              maxLength={64}
              value={login.username}
              onChange={(e) => {
                setLogin({ ...login, username: e.target.value, code: "" });
                setLoginTotp(false);
              }}
            />
            {setupRequired && <small>3 至 64 个字符，不含空格。</small>}
          </label>
          <label>
            密码
            <input
              required
              type="password"
              autoComplete={setupRequired ? "new-password" : "current-password"}
              minLength={setupRequired ? 12 : 1}
              maxLength={200}
              value={login.password}
              onChange={(e) => setLogin({ ...login, password: e.target.value })}
            />
            {setupRequired && <small>至少 12 个字符。</small>}
          </label>
          {setupRequired && (
            <label>
              确认密码
              <input
                required
                type="password"
                autoComplete="new-password"
                minLength={12}
                maxLength={200}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
              />
            </label>
          )}
          {!setupRequired && loginTotp && (
            <label>
              动态验证码
              <input
                required
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9]{6}"
                maxLength={6}
                value={login.code}
                onChange={(e) => setLogin({ ...login, code: e.target.value })}
              />
            </label>
          )}
          {error && (
            <p role="alert" className="error">
              {error}
            </p>
          )}
          <button className="primary" disabled={busy}>
            {setupRequired ? "创建账户并开始使用" : "登录"}
          </button>
          <small>
            {setupRequired
              ? "双因素认证默认关闭，可在设置中开启。"
              : "开启双因素认证的账户需要验证动态码。"}
          </small>
        </form>
      </main>
    );
  return (
    <div className="shell">
      <aside className="sidebar">
        <a className="brand" href="/">
          <KeyRound />
          <strong>
            统一认证<span>应用管理</span>
          </strong>
        </a>
        <nav>
          {[
            ["clients", "应用登记", Layers],
            ["drafts", "待发布", ClipboardList],
            ["jobs", "发布记录", History],
            ["audit", "操作记录", ShieldCheck],
            ...(admin ? [["settings", "设置", LockKeyhole]] : []),
          ].map(([id, title, Icon]) => (
            <button
              key={id as string}
              className={tab === id ? "active" : ""}
              onClick={() => {
                setTab(id as string);
                if (id === "audit")
                  run(async () => setAudit(await api("/audit")));
              }}
            >
              {React.createElement(Icon as any, { size: 19 })}
              {title as string}
              {id === "drafts" && drafts.filter((x) => !x.used).length > 0 && (
                <b>{drafts.filter((x) => !x.used).length}</b>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <span>
            <span className="dot" />
            {inv?.demo ? "演示环境" : inv?.writable ? "发布已启用" : "只读纳管"}
          </span>
          <p>
            {me.username} · {admin ? "管理员" : "只读审计员"}
          </p>
          <button
            onClick={() =>
              run(async () => {
                await api("/logout", {});
                setMe(null);
                setInv(null);
              })
            }
          >
            <LogOut size={16} />
            退出登录
          </button>
        </div>
      </aside>
      <main className="workspace">
        <header>
          <div>
            <p className="breadcrumb">
              统一认证 /{" "}
              {
                (
                  {
                    clients: "应用登记",
                    drafts: "待发布",
                    jobs: "发布记录",
                    audit: "操作记录",
                    settings: "设置",
                  } as any
                )[tab]
              }
            </p>
            <h1>
              {
                (
                  {
                    clients: "管理应用接入",
                    drafts: "检查待发布变更",
                    jobs: "查看发布结果",
                    audit: "查看管理操作",
                    settings: "账户安全设置",
                  } as any
                )[tab]
              }
            </h1>
          </div>
          <div className="header-actions">
            <button title="刷新" onClick={() => run(refresh)}>
              <RefreshCw size={17} />
            </button>
            {admin && (
              <button className="primary" onClick={() => open()}>
                <Plus size={17} />
                新增应用
              </button>
            )}
          </div>
        </header>
        {inv?.demo && (
          <div className="banner">
            演示环境使用虚构应用；发布操作只修改演示配置。
          </div>
        )}
        {inv && !inv.writable && (
          <div className="banner">
            当前为只读纳管，可查看应用和检查草稿。服务器管理员启用发布后，才能应用变更。
          </div>
        )}
        {error && (
          <div className="error" role="alert">
            {error}
            <button onClick={() => setError("")} aria-label="关闭错误">
              <X size={16} />
            </button>
            {error.includes("近期安全验证") && (
              <button onClick={() => setReauth(true)}>完成安全验证</button>
            )}
          </div>
        )}
        {notice && (
          <div className="notice" role="status">
            <Check size={16} />
            {notice}
            <button aria-label="关闭提示" onClick={() => setNotice("")}>
              <X size={15} />
            </button>
          </div>
        )}
        {tab === "settings" && (
          <SecuritySettings
            me={me}
            updated={async () => setMe(await api("/me"))}
          />
        )}
        {tab === "clients" && (
          <>
            <div className="toolbar">
              <div>
                <strong>{inv?.clients.length || 0}</strong> 个已登记应用
                <span>每个应用及环境独立管理</span>
              </div>
              <label className="search">
                <Search size={17} />
                <input
                  aria-label="搜索应用"
                  placeholder="搜索名称或客户端标识"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                />
              </label>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>应用</th>
                    <th>环境与负责人</th>
                    <th>接入地址</th>
                    <th>认证要求</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {inv?.clients
                    .filter((c) =>
                      (c.client_name + c.client_id)
                        .toLowerCase()
                        .includes(query.toLowerCase()),
                    )
                    .map((c) => (
                      <tr key={c.client_id}>
                        <td>
                          <strong>
                            {c.client_name}
                            {c.disabled && <span className="tag">已停用</span>}
                          </strong>
                          <code title={c.client_id}>{c.client_id}</code>
                        </td>
                        <td>
                          <span
                            className={
                              "tag " +
                              (c.environment === "production" ? "prod" : "")
                            }
                          >
                            {labels[c.environment || "unclassified"]}
                          </span>
                          <small>{c.owner || "负责人待补充"}</small>
                        </td>
                        <td>
                          <span
                            className="uri"
                            title={c.redirect_uris.join("\n")}
                          >
                            {c.redirect_uris[0]}
                          </span>
                          {c.redirect_uris.length > 1 && (
                            <small>
                              另有 {c.redirect_uris.length - 1} 个回调地址
                            </small>
                          )}
                        </td>
                        <td>
                          <span>
                            {c.authorization_policy === "two_factor"
                              ? "双因素"
                              : "单因素"}
                          </span>
                          <small>
                            {c.public ? "公共客户端" : "后端客户端"} ·{" "}
                            {c.require_pkce === false ? "PKCE 未强制" : "PKCE"}
                          </small>
                        </td>
                        <td>
                          <div className="actions">
                            <button onClick={() => parameter(c)}>
                              接入参数
                            </button>
                            {admin && (
                              <button
                                disabled={!c.editable}
                                onClick={() =>
                                  open(c, c.disabled ? "restore" : "upsert")
                                }
                              >
                                {c.disabled ? "恢复" : "管理"}
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
              {inv?.clients.length === 0 && (
                <div className="empty">
                  <Layers />
                  <h3>还没有登记应用</h3>
                  <p>新增一个应用，生成接入配置。</p>
                </div>
              )}
            </div>
            <p className="footnote">
              配置以认证服务当前文件为准。保存草稿后，需要发布才能生效。
            </p>
          </>
        )}
        {tab === "drafts" && (
          <div className="record-list">
            {drafts.map((d) => (
              <article key={d.id}>
                <ClipboardList />
                <div>
                  <strong>{d.client_name}</strong>
                  <p>
                    {labels[d.operation]} · {labels[d.environment]} ·{" "}
                    {d.owner || "未填写负责人"}
                  </p>
                  <small>
                    {d.used
                      ? "已提交发布"
                      : d.validated
                        ? "检查通过"
                        : "尚未检查"}{" "}
                    · {new Date(d.created * 1000).toLocaleString()}
                  </small>
                </div>
                {admin && !d.used && (
                  <button
                    onClick={() =>
                      run(async () => {
                        const result = await api(
                          "/drafts/" + d.id + "/validate",
                          {},
                        );
                        setChanges(result.changes || []);
                        setDraftId(d.id);
                        setAck(false);
                        setParams("");
                        setNotice("检查通过，请到发布确认窗口继续");
                        const c = inv?.clients.find(
                          (c) => c.client_id === d.client_id,
                        );
                        setForm({
                          client: c || {
                            client_id: d.client_id,
                            client_name: d.client_name,
                            redirect_uris: [],
                            scopes: [],
                          },
                          owner: d.owner,
                          environment: d.environment,
                          operation: d.operation,
                        });
                        setChecked(true);
                      })
                    }
                  >
                    检查并发布
                  </button>
                )}
              </article>
            ))}
            {!drafts.length && (
              <div className="empty">
                没有待发布变更。修改应用后会在这里保留草稿。
              </div>
            )}
          </div>
        )}
        {tab === "jobs" && (
          <>
            <div className="record-list">
              {jobs.map((j, i) => (
                <article key={j.id}>
                  <History />
                  <div>
                    <strong>
                      {labels[j.operation]} · {j.client_id}
                    </strong>
                    <p>
                      <span
                        className={
                          "tag " + (j.state === "applied" ? "success" : "")
                        }
                      >
                        {labels[j.state] || j.state}
                      </span>{" "}
                      {j.message}
                    </p>
                    <small>{new Date(j.created * 1000).toLocaleString()}</small>
                  </div>
                  {admin && i === 0 && j.state === "applied" && (
                    <button
                      disabled={busy || !inv?.writable}
                      onClick={() => {
                        if (
                          confirm(
                            "恢复上一版会重启认证服务，并可能恢复旧密钥或重新启用应用。确认继续？",
                          )
                        )
                          run(async () => {
                            await api("/deployments/" + j.id + "/rollback", {});
                            await refresh();
                          });
                      }}
                    >
                      恢复上一版
                    </button>
                  )}
                </article>
              ))}
              {!jobs.length && <div className="empty">还没有发布记录。</div>}
            </div>
            {admin && deliveries.length > 0 && (
              <section className="deliveries">
                <h2>待领取密钥</h2>
                <p>
                  仅发布成功后可以领取；领取后无法再次显示，请及时安全保存。
                </p>
                {deliveries.map((d) => (
                  <div key={d.id}>
                    <span>
                      关联发布 {d.draft_id.slice(0, 8)} ·{" "}
                      {new Date(d.expires * 1000).toLocaleString()} 到期
                    </span>
                    <button
                      onClick={() =>
                        run(async () => {
                          setSecret(
                            (await api("/deliveries/" + d.id + "/claim", {}))
                              .secret,
                          );
                          await refresh();
                        })
                      }
                    >
                      <LockKeyhole size={16} />
                      领取密钥
                    </button>
                  </div>
                ))}
              </section>
            )}
          </>
        )}
        {tab === "audit" && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>时间</th>
                  <th>操作者</th>
                  <th>操作</th>
                  <th>对象</th>
                </tr>
              </thead>
              <tbody>
                {audit.map((x) => (
                  <tr key={x.id}>
                    <td>{new Date(x.at * 1000).toLocaleString()}</td>
                    <td>{x.actor}</td>
                    <td>
                      {(
                        {
                          login: "登录",
                          "draft-created": "创建草稿",
                          "deployment-requested": "提交发布",
                          "secret-claimed": "领取密钥",
                          "rollback-requested": "请求恢复",
                          "administrator-created": "建立管理员",
                        } as any
                      )[x.action] || x.action}
                    </td>
                    <td>
                      <code>{x.target}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </main>
      {form && (
        <div className="overlay">
          <section
            className="drawer"
            role="dialog"
            aria-modal="true"
            aria-label="应用配置"
          >
            <header>
              <div>
                <p>应用接入配置</p>
                <h2>
                  {form.operation === "restore"
                    ? "恢复应用"
                    : form.operation === "disable"
                      ? "停用应用"
                      : form.operation === "rotate"
                        ? "轮换密钥"
                        : form.client.client_name || "新增应用"}
                </h2>
              </div>
              <button aria-label="关闭" onClick={() => setForm(null)}>
                <X />
              </button>
            </header>
            <div className="drawer-content">
              {!checked && (
                <>
                  <label>
                    应用名称
                    <input
                      value={form.client.client_name}
                      onChange={(e) => field("client_name", e.target.value)}
                    />
                  </label>
                  <div className="two-col">
                    <label>
                      接入环境
                      <select
                        value={form.environment}
                        onChange={(e) => {
                          setForm({ ...form, environment: e.target.value });
                          setChecked(false);
                        }}
                      >
                        <option value="production">生产</option>
                        <option value="test">测试</option>
                        <option value="development">开发</option>
                      </select>
                    </label>
                    <label>
                      负责人
                      <input
                        value={form.owner}
                        onChange={(e) =>
                          setForm({ ...form, owner: e.target.value })
                        }
                      />
                    </label>
                  </div>
                  <label>
                    客户端标识
                    <input
                      value={form.client.client_id}
                      readOnly={
                        !!inv?.clients.some(
                          (c) => c.client_id === form.client.client_id,
                        )
                      }
                      onChange={(e) => field("client_id", e.target.value)}
                    />
                    <small>自动生成，应用上线后保持不变。</small>
                  </label>
                  <label>
                    应用类型
                    <select
                      value={form.client.public ? "public" : "confidential"}
                      disabled={
                        !!inv?.clients.some(
                          (c) => c.client_id === form.client.client_id,
                        )
                      }
                      onChange={(e) => {
                        const pub = e.target.value === "public";
                        setForm({
                          ...form,
                          client: {
                            ...form.client,
                            public: pub,
                            token_endpoint_auth_method: pub
                              ? "none"
                              : "client_secret_basic",
                            require_pkce: true,
                          },
                        });
                      }}
                    >
                      <option value="confidential">有后端的 Web 应用</option>
                      <option value="public">纯前端或公共客户端</option>
                    </select>
                  </label>
                  <label>
                    登录回调地址
                    <textarea
                      rows={4}
                      value={form.client.redirect_uris.join("\n")}
                      onChange={(e) =>
                        field("redirect_uris", e.target.value.split("\n"))
                      }
                    />
                    <small>每行一个完整地址。生产环境使用 HTTPS。</small>
                  </label>
                  <label>
                    认证强度
                    <select
                      value={form.client.authorization_policy || "one_factor"}
                      onChange={(e) =>
                        field("authorization_policy", e.target.value)
                      }
                    >
                      <option value="one_factor">单因素认证</option>
                      <option value="two_factor">双因素认证</option>
                    </select>
                  </label>
                  <fieldset>
                    <legend>用户资料</legend>
                    {[
                      ["profile", "姓名等基本资料"],
                      ["email", "邮箱"],
                      ["groups", "部门或授权组"],
                    ].map(([scope, title]) => (
                      <label className="checkbox" key={scope}>
                        <input
                          type="checkbox"
                          checked={form.client.scopes.includes(scope)}
                          onChange={(e) =>
                            field(
                              "scopes",
                              e.target.checked
                                ? [...form.client.scopes, scope]
                                : form.client.scopes.filter((x) => x !== scope),
                            )
                          }
                        />
                        {title}
                      </label>
                    ))}
                  </fieldset>
                  <label className="checkbox">
                    <input
                      type="checkbox"
                      checked={form.client.require_pkce !== false}
                      disabled={form.client.public}
                      onChange={(e) => field("require_pkce", e.target.checked)}
                    />
                    要求 PKCE S256
                  </label>
                  {!form.client.public && (
                    <label>
                      客户端认证方式
                      <select
                        value={
                          form.client.token_endpoint_auth_method ||
                          "client_secret_basic"
                        }
                        onChange={(e) =>
                          field("token_endpoint_auth_method", e.target.value)
                        }
                      >
                        <option value="client_secret_basic">
                          client_secret_basic
                        </option>
                        <option value="client_secret_post">
                          client_secret_post
                        </option>
                      </select>
                    </label>
                  )}
                  {inv?.clients.some(
                    (c) => c.client_id === form.client.client_id,
                  ) && (
                    <div className="danger-actions">
                      <button
                        onClick={() =>
                          setForm({ ...form, operation: "rotate" })
                        }
                        disabled={form.client.public}
                      >
                        改为轮换密钥
                      </button>
                      <button
                        onClick={() =>
                          setForm({ ...form, operation: "disable" })
                        }
                      >
                        改为停用应用
                      </button>
                    </div>
                  )}
                </>
              )}
              {checked && (
                <>
                  <div className="validated">
                    <ShieldCheck />
                    <h3>配置检查通过</h3>
                    <p>
                      {inv?.demo
                        ? "已通过演示检查。"
                        : "候选配置已通过 Authelia 原生检查。"}
                    </p>
                  </div>
                  <dl>
                    <dt>应用</dt>
                    <dd>{form.client.client_name}</dd>
                    <dt>操作</dt>
                    <dd>{labels[form.operation]}</dd>
                    <dt>环境</dt>
                    <dd>{labels[form.environment]}</dd>
                    <dt>回调地址</dt>
                    <dd>{form.client.redirect_uris.join("\n")}</dd>
                  </dl>
                  <div className="change-preview">
                    <h3>本次变更</h3>
                    {changes.map((x) => (
                      <div key={x.field}>
                        <strong>
                          {(
                            {
                              client_name: "应用名称",
                              client_id: "客户端标识",
                              redirect_uris: "回调地址",
                              client_secret: "应用密钥",
                              public: "公共客户端",
                              scopes: "资料范围",
                              require_pkce: "要求 PKCE",
                              authorization_policy: "认证强度",
                              token_endpoint_auth_method: "客户端认证",
                              pkce_challenge_method: "PKCE 算法",
                              grant_types: "授权方式",
                              response_types: "响应方式",
                            } as any
                          )[x.field] || x.field}
                        </strong>
                        <del>{JSON.stringify(x.before) ?? "未配置"}</del>
                        <span>{JSON.stringify(x.after) ?? "未配置"}</span>
                      </div>
                    ))}
                  </div>
                  <p className="impact">
                    发布会重启认证服务，正在登录的请求可能需要重试。停用或轮换不会自动结束业务系统已有会话。
                  </p>
                  <label className="checkbox">
                    <input
                      type="checkbox"
                      checked={ack}
                      onChange={(e) => setAck(e.target.checked)}
                    />
                    我已确认变更内容和重启影响
                  </label>
                </>
              )}
              {error && (
                <p className="error" role="alert">
                  {error}
                </p>
              )}
            </div>
            <footer>
              {checked ? (
                <>
                  <button
                    onClick={() => {
                      setChecked(false);
                      setDraftId("");
                    }}
                  >
                    返回修改
                  </button>
                  <button onClick={() => setReauth(true)}>安全验证</button>
                  <button
                    className="primary"
                    disabled={busy || !ack || !inv?.writable}
                    onClick={() => run(publish)}
                  >
                    确认发布
                  </button>
                </>
              ) : (
                <>
                  <span>
                    {form.operation === "upsert"
                      ? "保存前自动检查配置"
                      : labels[form.operation]}
                  </span>
                  <button
                    className="primary"
                    disabled={busy}
                    onClick={() => run(save)}
                  >
                    保存并检查
                  </button>
                </>
              )}
            </footer>
          </section>
        </div>
      )}
      {params && (
        <Modal title="接入参数" close={() => setParams("")}>
          <textarea
            className="parameter-text"
            readOnly
            rows={16}
            value={params}
          />
          <button
            className="primary"
            onClick={() =>
              run(async () => {
                await copyText(params);
                setNotice("接入参数已复制");
              })
            }
          >
            <Copy size={16} />
            复制参数
          </button>
        </Modal>
      )}
      {secret && (
        <Modal title="保存应用密钥" close={() => setSecret("")}>
          <p>请保存到受控密码库。关闭后无法再次显示。</p>
          <textarea readOnly rows={4} value={secret} />
          <button
            className="primary"
            onClick={() =>
              run(async () => {
                await copyText(secret);
                setNotice("密钥已复制，请及时安全保存");
              })
            }
          >
            复制密钥
          </button>
        </Modal>
      )}
      {reauth && (
        <Modal title="安全验证" close={() => setReauth(false)}>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              run(async () => {
                await api("/reauth", reauthData);
                setReauth(false);
                setReauthData({ password: "", code: "" });
                setNotice("安全验证通过，五分钟内可执行敏感操作");
              });
            }}
          >
            <label>
              密码
              <input
                type="password"
                required
                value={reauthData.password}
                onChange={(e) =>
                  setReauthData({ ...reauthData, password: e.target.value })
                }
              />
            </label>
            {Boolean(me.totp_enabled) && (
              <label>
                动态验证码
                <input
                  inputMode="numeric"
                  pattern="[0-9]{6}"
                  required
                  value={reauthData.code}
                  onChange={(e) =>
                    setReauthData({ ...reauthData, code: e.target.value })
                  }
                />
              </label>
            )}
            {error && <p className="error">{error}</p>}
            <button className="primary" disabled={busy}>
              确认
            </button>
          </form>
        </Modal>
      )}
    </div>
  );
}
function SecuritySettings({
  me,
  updated,
}: {
  me: any;
  updated: () => Promise<void>;
}) {
  const [mode, setMode] = useState<"enable" | "disable" | null>(null),
    [password, setPassword] = useState(""),
    [code, setCode] = useState(""),
    [enrollment, setEnrollment] = useState<any>(null),
    [qr, setQr] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [message, setMessage] = useState("");
  function close() {
    setMode(null);
    setPassword("");
    setCode("");
    setEnrollment(null);
    setQr("");
    setError("");
  }
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (mode === "disable") {
        await api("/settings/totp/disable", { password, code });
        await updated();
        close();
        setMessage("双因素认证已关闭，下次使用账号和密码登录。");
      } else if (!enrollment) {
        const d = await api("/settings/totp/begin", { password });
        setQr(await QRCode.toDataURL(d.uri, { width: 224, margin: 2 }));
        setEnrollment(d);
        setPassword("");
      } else {
        await api("/settings/totp/confirm", { code });
        await updated();
        close();
        setMessage("双因素认证已开启，下次登录需要动态验证码。");
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="settings-panel">
      <h2>账户安全</h2>
      <p>当前账户：{me.username}</p>
      {message && (
        <div className="notice" role="status">
          {message}
        </div>
      )}
      <div className="security-option">
        <div>
          <h3>
            双因素认证 TOTP{" "}
            <span className={me.totp_enabled ? "tag success" : "tag"}>
              {me.totp_enabled ? "已开启" : "未开启"}
            </span>
          </h3>
          <p>按需开启。开启后，登录及安全验证还需输入验证器生成的动态码。</p>
        </div>
        <button
          onClick={() => {
            close();
            setMessage("");
            setMode(me.totp_enabled ? "disable" : "enable");
          }}
        >
          {me.totp_enabled ? "关闭双因素认证" : "开启双因素认证"}
        </button>
      </div>
      {mode && (
        <Modal
          title={mode === "disable" ? "关闭双因素认证" : "开启双因素认证"}
          close={close}
        >
          <form onSubmit={submit}>
            {!enrollment && (
              <label>
                当前密码
                <input
                  required
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </label>
            )}
            {enrollment && (
              <>
                <p>
                  使用验证器扫描二维码，或手动输入绑定密钥，然后输入生成的动态码。绑定在十分钟后过期。
                </p>
                <img className="totp-qr" src={qr} alt="验证器绑定二维码" />
                <label>
                  绑定密钥
                  <input readOnly value={enrollment.secret} />
                </label>
              </>
            )}
            {(mode === "disable" || enrollment) && (
              <label>
                动态验证码
                <input
                  required
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                />
              </label>
            )}
            {error && (
              <p className="error" role="alert">
                {error}
              </p>
            )}
            <button className="primary" disabled={busy}>
              {mode === "disable"
                ? "确认关闭"
                : enrollment
                  ? "验证并开启"
                  : "下一步"}
            </button>
          </form>
        </Modal>
      )}
    </section>
  );
}

function Modal({
  title,
  close,
  children,
}: {
  title: string;
  close: () => void;
  children: React.ReactNode;
}) {
  return (
    <div className="overlay modal-overlay">
      <section
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <header>
          <h2>{title}</h2>
          <button aria-label="关闭" onClick={close}>
            <X />
          </button>
        </header>
        {children}
      </section>
    </div>
  );
}
createRoot(document.getElementById("root")!).render(<App />);
