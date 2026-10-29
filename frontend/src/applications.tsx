import React, { useEffect, useState } from "react";
import { ClipboardList, KeyRound, LogOut, RefreshCw, ArrowLeft, Plus } from "lucide-react";

type Api = (path: string, body?: unknown) => Promise<any>;
const states: Record<string, string> = {
  submitted: "待审批", returned: "待补充", rejected: "未通过", approved: "待发布",
  publishing: "发布中", ready: "待验收", completed: "已完成", failed: "发布失败",
  attention: "需要核查", claimed: "密钥已领取", resubmitted: "已补充提交",
  "acceptance-submitted": "已提交验收",
  reissuing: "重新签发密钥",
};
const envs: Record<string, string> = { development: "开发", test: "测试", production: "生产" };
const defaults = {
  name: "", purpose: "", department: "", business_owner: "", technical_owner: "",
  contact: "", environment: "test", app_type: "backend",
  access_url: "", redirect_uris: [""], agreement: false,
};
const fields: [string, string, string?][] = [
  ["name", "应用名称"], ["purpose", "应用用途", "area"], ["department", "申请部门"],
  ["business_owner", "业务负责人"], ["technical_owner", "技术负责人"],
  ["contact", "联系方式"],
];

function ApplicationForm({ initial, onSave, onCancel, busy, domain }: {
  domain: string; initial: any; onSave: (data: any) => void; onCancel: () => void; busy: boolean;
}) {
  const [data, setData] = useState({ ...defaults, ...initial, agreement: false });
  const initialHost = (() => {
    if (!domain || !initial?.access_url) return "";
    try {
      const u = new URL(initial.access_url);
      const prefix = u.hostname.endsWith("." + domain) ? u.hostname.slice(0, -(domain.length + 1)) : "";
      return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(prefix)
        && initial.access_url === `https://${prefix}.${domain}`
        && initial.redirect_uris?.length === 1
        && initial.redirect_uris[0] === `https://${prefix}.${domain}/auth/callback` ? prefix : "";
    } catch { return ""; }
  })();
  const [subdomain, setSubdomain] = useState(initialHost);
  const [custom, setCustom] = useState(!domain || (!!initial?.access_url && !initialHost));
  const accessUrl = subdomain ? `https://${subdomain}.${domain}` : "";
  const callbackUrl = accessUrl ? accessUrl + "/auth/callback" : "";
  const update = (key: string, value: any) => setData((d: any) => ({ ...d, [key]: value }));
  return <form className="application-form" onSubmit={e => {
    e.preventDefault();
    onSave({ ...Object.fromEntries(Object.keys(defaults).map(key => [key, data[key]])), access_url: custom ? data.access_url : accessUrl, redirect_uris: custom ? data.redirect_uris.map((x: string) => x.trim()).filter(Boolean) : [callbackUrl] });
  }}>
    <h2>{initial?.name ? "补充申请资料" : "申请应用接入"}</h2>
    <p className="muted">每个应用、每个环境独立申请。提交后可在这里查看审批进度、领取接入参数和密钥。带 * 的为必填项。</p>
    <div className="application-fields">
      {fields.map(([key, label, type]) => <label key={key} className={type === "area" ? "wide" : ""}>
        <span>{label}<span className="required-mark" aria-hidden="true"> *</span></span>
        {type === "area"
          ? <textarea required maxLength={2000} rows={3} value={data[key]} onChange={e => update(key, e.target.value)} />
          : <input required type={type || "text"} maxLength={key === "access_url" ? 2048 : 150}
                   value={data[key]} onChange={e => update(key, e.target.value)} />}
      </label>)}
      <label><span>接入环境<span className="required-mark" aria-hidden="true"> *</span></span><select required value={data.environment} onChange={e => update("environment", e.target.value)}>
        {Object.entries(envs).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
      </select></label>
      <label><span>应用类型<span className="required-mark" aria-hidden="true"> *</span></span><select required value={data.app_type} onChange={e => update("app_type", e.target.value)}>
        <option value="backend">有后端的 Web 系统</option><option value="spa">纯前端应用</option><option value="mobile">移动应用</option>
      </select><small>{data.app_type === "backend" ? "密钥仅保存在服务端。" : "公共客户端使用 PKCE，不分配客户端密钥。"}</small></label>
      {domain && <label className="check wide"><input type="checkbox" checked={custom} onChange={e => {
        if (e.target.checked && accessUrl) setData((d: any) => ({ ...d, access_url: accessUrl, redirect_uris: [callbackUrl] }));
        setCustom(e.target.checked);
      }} />自定义地址</label>}
      {!custom ? <>
        <label className="wide"><span>应用子域名<span className="required-mark" aria-hidden="true"> *</span></span>
          <div className="application-domain"><span>https://</span><input required aria-label="应用子域名" autoCapitalize="none" autoCorrect="off" spellCheck={false}
            pattern={"[a-z0-9]([a-z0-9\\-]{0,61}[a-z0-9])?"} maxLength={63} placeholder="例如：oa" value={subdomain}
            onChange={e => setSubdomain(e.target.value.toLowerCase())} title="只填写子域名，可用小写字母、数字和中间的短横线" /><span>.{domain}</span></div>
          <small>只填写子域名，例如 oa；应用需支持 /auth/callback 回调路径。已有应用使用其他地址时，选择“自定义地址”。</small>
        </label>
        <div className="application-address-preview wide" aria-live="polite"><p>应用访问地址：<strong>{accessUrl || "填写子域名后自动生成"}</strong></p>
          <p>登录回调地址：<strong>{callbackUrl || "填写子域名后自动生成"}</strong></p></div>
      </> : <>
        <label className="wide"><span>应用访问地址<span className="required-mark" aria-hidden="true"> *</span></span>
          <input required type="url" maxLength={2048} value={data.access_url} onChange={e => update("access_url", e.target.value)} placeholder="https://app.example.com" />
          <small>员工平时打开应用的完整网址。</small>
        </label>
        <label className="wide"><span>登录回调地址<span className="required-mark" aria-hidden="true"> *</span></span>
          <textarea required rows={3} value={data.redirect_uris.join("\n")} onChange={e => update("redirect_uris", e.target.value.split("\n"))}
            placeholder="每行一个完整回调地址" />
          <small>以应用登录组件的实际配置为准，必须完全一致，不支持通配符；生产环境使用 HTTPS。</small>
        </label>
      </>}
    </div>
    <details className="application-rules"><summary>统一认证接入要求</summary>
      <p>使用授权码流程和 PKCE S256；通过成熟 OIDC 组件校验 state、nonce、签名、Issuer、Audience 和令牌有效期。以 Issuer 与 sub 关联用户。</p>
      <p>应用负责业务权限，登录成功不自动授予管理员权限。密钥仅存服务端，不放前端、Git、日志或申请内容。</p>
      <p>生产使用 HTTPS。上线前验证登录、权限、员工停用、退出及故障处理。变更回调、权限、负责人或应用下线时联系认证管理员。</p>
    </details>
    <label className="check"><input required type="checkbox" checked={data.agreement}
      onChange={e => update("agreement", e.target.checked)} />我已阅读接入要求，确认资料准确，并配合接入验收<span className="required-mark" aria-hidden="true"> *</span></label>
    <div className="application-actions"><button type="button" onClick={onCancel} disabled={busy}>取消</button>
      <button className="primary" disabled={busy}>{busy ? "正在提交…" : "提交申请"}</button></div>
  </form>;
}

function parameters(d: any) {
  const p = d.parameters, c = p?.client;
  if (!c) return "";
  return `Issuer: ${p.issuer}\nDiscovery: ${p.discovery}\nClient ID: ${c.client_id}\nScope: ${c.scopes.join(" ")}\nFlow: Authorization Code + PKCE S256\nToken endpoint auth: ${c.token_endpoint_auth_method}\nRedirect URIs:\n${c.redirect_uris.join("\n")}\n${c.public ? "公共客户端，无 Client Secret" : "Client Secret 请单独领取并保存至服务端秘密配置"}`;
}

export function ApplicationPanel({ api, admin = false, me, domain = "" }: { api: Api; admin?: boolean; me: any; domain?: string }) {
  const [list, setList] = useState<any[]>([]), [detail, setDetail] = useState<any>(null);
  const [editing, setEditing] = useState(false), [error, setError] = useState(""), [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false), [secret, setSecret] = useState("");
  const [comment, setComment] = useState(""), [twoFactor, setTwoFactor] = useState(false);
  const [ack, setAck] = useState(false), [results, setResults] = useState("");
  const [reauth, setReauth] = useState(false), [password, setPassword] = useState(""), [code, setCode] = useState("");
  async function load(id?: string) {
    setList(await api("/applications"));
    if (id) setDetail(await api("/applications/" + id));
  }
  async function run(fn: () => Promise<void>) {
    setBusy(true); setError(""); setNotice("");
    try { await fn(); } catch (e: any) {
      setError(e.message);
      if (e.message.includes("近期安全验证")) setReauth(true);
    } finally { setBusy(false); }
  }
  useEffect(() => { run(() => load()); }, []);
  useEffect(() => {
    if (!detail?.draft_id || editing) return;
    let stopped = false;
    const id = setInterval(async () => {
      try {
        const d = await api("/applications/" + detail.id);
        if (!stopped) setDetail(d);
      } catch {}
    }, 5000);
    return () => { stopped = true; clearInterval(id); };
  }, [detail?.id, detail?.draft_id, editing]);
  async function select(id: string) {
    setSecret(""); setAck(false); setComment(""); setTwoFactor(false); setResults("");
    const d = await api("/applications/" + id);
    setDetail(d); setResults(d.acceptance || "");
  }
  async function action(path: string, body: any) {
    await api(`/applications/${detail.id}/${path}`, body);
    await load(detail.id);
    setAck(false);
    setNotice("操作已保存");
  }
  return <section className="applications">
    <div className="application-toolbar">
      <div><h2>{admin ? "接入申请审批" : "我的接入申请"}</h2><p className="muted">{admin ? "核对申请资料，审批后发布，再由申请人领取凭据。" : "申请、审批、领取凭据和接入验收都在这里完成。"}</p></div>
      <div className="application-actions">
        <button aria-label="刷新申请" disabled={busy} onClick={() => run(() => load(detail?.id))}><RefreshCw size={16} /></button>
        {!admin && !editing && <button className="primary" onClick={() => { setDetail(null); setSecret(""); setEditing(true); setError(""); }}><Plus size={16} />新建申请</button>}
      </div>
    </div>
    {error && <div className="error" role="alert">{error}</div>}
    {notice && <div className="notice" role="status">{notice}</div>}
    {reauth && <form className="application-review" onSubmit={e => { e.preventDefault(); run(async () => {
      await api("/reauth", { password, code }); setPassword(""); setCode(""); setReauth(false); setNotice("安全验证完成，请重新执行发布");
    }); }}>
      <h3>发布前安全验证</h3><label>管理员密码<input type="password" required value={password} onChange={e => setPassword(e.target.value)} autoComplete="current-password" /></label>
      {!!me?.totp_enabled && <label>动态验证码<input required value={code} onChange={e => setCode(e.target.value)} inputMode="numeric" pattern="[0-9]{6}" /></label>}
      <button className="primary" disabled={busy}>验证</button>
    </form>}
    {editing ? <ApplicationForm domain={domain} busy={busy} initial={detail?.payload || { technical_owner: me?.name || "", contact: me?.email || "" }}
      onCancel={() => setEditing(false)} onSave={data => run(async () => {
        const result = detail
          ? await api(`/applications/${detail.id}/resubmit`, { ...data, version: detail.version })
          : await api("/applications", data);
        setEditing(false); await load(detail?.id || result.id); setNotice("申请已提交，等待管理员审批");
      })} /> : detail ? <>
      <button className="application-back" onClick={() => { setDetail(null); setSecret(""); run(() => load()); }}><ArrowLeft size={16} />返回申请列表</button>
      <article className="application-detail">
        <div className="application-title"><div><h2>{detail.payload.name}</h2><p className="muted">{envs[detail.payload.environment]}环境 · {detail.applicant_profile.name}{detail.applicant_profile.email && `（${detail.applicant_profile.email}）`}</p></div>
          <span className={"tag request-" + detail.status}>{states[detail.status] || detail.status}</span></div>
        <dl className="application-summary">{fields.map(([k, label]) => <React.Fragment key={k}><dt>{label}</dt><dd>{detail.payload[k]}</dd></React.Fragment>)}
          <dt>应用类型</dt><dd>{{ backend: "有后端的 Web 系统", spa: "纯前端", mobile: "移动应用" }[detail.payload.app_type as string]}</dd>
          <dt>应用访问地址</dt><dd>{detail.payload.access_url}</dd>
          <dt>登录回调地址</dt><dd>{detail.payload.redirect_uris.join("\n")}</dd>
          <dt>资料范围</dt><dd>openid profile email{detail.payload.groups ? " groups" : ""}</dd>
        </dl>
        {detail.comment && <div className="banner"><strong>审批意见：</strong>{detail.comment}</div>}
        {!admin && detail.status === "returned" && <button className="primary" disabled={busy} onClick={() => setEditing(true)}>补充资料并重新提交</button>}
        {admin && detail.status === "submitted" && <div className="application-review">
          <h3>审批意见</h3><label>办理说明<textarea rows={3} maxLength={2000} value={comment} onChange={e => setComment(e.target.value)} placeholder="退回或拒绝时必填" /></label>
          <label className="check"><input type="checkbox" checked={twoFactor} onChange={e => setTwoFactor(e.target.checked)} />要求双因素认证</label>
          <div className="application-actions">{[["return", "退回补充"], ["reject", "不同意"], ["approve", "批准接入"]].map(([decision, title]) =>
            <button key={decision} className={decision === "approve" ? "primary" : ""} disabled={busy}
              onClick={() => run(() => action("review", { version: detail.version, decision, comment, two_factor: twoFactor }))}>{title}</button>)}</div>
        </div>}
        {detail.approved && <section className="application-review">
          <h3>批准的接入配置</h3>
          <p>Client ID：<span className="request-value">{detail.approved.client_id}</span></p>
          <p>资料范围：{detail.approved.scopes.join(" ")}；认证要求：{detail.approved.authorization_policy === "two_factor" ? "双因素" : "单因素"}</p>
          {detail.deployment_message && <p className="muted">发布结果：{detail.deployment_message}</p>}
          {admin && ["approved", "failed", "publishing"].includes(detail.status) && <>
            <p className="muted">发布成功并通过健康检查后，申请人才可领取密钥。发布失败时请核查记录后重试。</p>
            <label className="check"><input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)} />我已核对配置及发布窗口，确认重启认证服务的影响</label>
            <button className="primary" disabled={busy || !ack || ["queued", "writing", "checking", "rolling_back", "attention"].includes(detail.deployment_state)}
              onClick={() => run(() => action("publish", { version: detail.version, acknowledge_restart: ack }))}>{detail.status === "approved" ? "发布接入配置" : "核查后重试发布"}</button>
          </>}
        </section>}
        {detail.parameters && <section className="application-review">
          <h3>接入参数与密钥</h3>
          {!detail.parameters.active && <p className="error">当前配置未生效或已发生变更，请联系管理员核查。</p>}
          <label>应用配置参数<textarea readOnly rows={10} value={parameters(detail)} onFocus={e => e.target.select()} /></label>
          {detail.approved.public ? <p>公共客户端使用授权码及 PKCE S256，无需客户端密钥。</p> :
            secret ? <div className="application-secret"><label>Client Secret，请立即保存至服务端秘密配置<textarea readOnly value={secret} rows={3} onFocus={e => e.target.select()} /></label><p>仅展示本次，刷新或离开后不能再次查看。</p><button onClick={() => setSecret("")}>我已保存，隐藏密钥</button></div> :
            detail.claimed_at ? <p>密钥已于 {new Date(detail.claimed_at * 1000).toLocaleString()} 领取。如已丢失，请联系管理员轮换。</p> :
            detail.delivery ? <><p>领取有效期至 {new Date(detail.delivery.expires * 1000).toLocaleString()}。密钥只能由申请人本人领取一次。</p>
              {!admin && <button className="primary" disabled={busy || !detail.delivery.ready} onClick={() => run(async () => {
                const result = await api(`/applications/${detail.id}/claim`, {}); setSecret(result.secret); await load(detail.id);
              })}>领取一次性密钥</button>}</> : <p>暂无可领取密钥；如已过期，请联系管理员重新签发。</p>}
          {admin && ["ready", "completed", "attention", "failed"].includes(detail.status) && !detail.approved.public && <div className="application-review">
            <p>密钥丢失或过期时可以重新签发。新配置生效后旧密钥立即失效，请先与技术负责人安排切换。</p>
            <label className="check"><input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)} />已确认密钥切换安排及认证服务重启影响</label>
            <button disabled={busy || !ack} onClick={() => run(() => action("publish", { version: detail.version, acknowledge_restart: ack, reissue: true }))}>重新签发密钥</button>
          </div>}
        </section>}
        {detail.status === "ready" && <section className="application-review">
          <h3>接入验收</h3><p>请记录正常登录、协议及令牌校验、权限控制、员工停用、退出、认证故障和敏感信息检查的测试结果。</p>
          {!admin ? <><label>验收结果<textarea rows={5} minLength={20} maxLength={6000} value={results} onChange={e => setResults(e.target.value)} /></label>
            <button disabled={busy || results.trim().length < 20} onClick={() => run(() => action("acceptance", { version: detail.version, results }))}>提交验收结果</button></>
            : <><p className="request-value">{detail.acceptance || "等待申请人提交测试结果"}</p>
              <button className="primary" disabled={busy || !detail.acceptance} onClick={() => run(() => action("complete", { version: detail.version }))}>确认验收完成</button></>}
        </section>}
        {detail.status === "completed" && <section className="application-review"><h3>已确认的验收结果</h3><p className="request-value">{detail.acceptance}</p></section>}
        <section className="application-review"><h3>办理记录</h3><ol className="application-timeline">{detail.events.map((e: any, i: number) =>
          <li key={i}><time>{new Date(e.at * 1000).toLocaleString()}</time><strong>{states[e.action] || e.action}</strong>{admin && <small>{e.actor}</small>}{e.comment && <p>{e.comment}</p>}</li>)}</ol></section>
      </article>
    </> : <div className="table-wrap"><table><thead><tr><th>应用</th><th>环境</th><th>技术负责人</th><th>进度</th><th>提交时间</th><th>操作</th></tr></thead>
      <tbody>{list.length ? list.map(d => <tr key={d.id}><td><strong>{d.payload.name}</strong><small>{d.payload.department}</small></td><td>{envs[d.payload.environment]}</td><td>{d.payload.technical_owner}</td>
        <td><span className={"tag request-" + d.status}>{states[d.status] || d.status}</span></td><td>{new Date(d.created * 1000).toLocaleString()}</td><td><button disabled={busy} onClick={() => run(() => select(d.id))}>查看申请</button></td></tr>) :
        <tr><td colSpan={6} className="application-empty"><ClipboardList size={30} /><p>{admin ? "暂无待办理的接入申请" : "还没有接入申请，点击“新建申请”开始填写"}</p></td></tr>}</tbody></table></div>}
  </section>;
}

export function ApplicantPortal() {
  const [me, setMe] = useState<any>(null), [ready, setReady] = useState(false), [enabled, setEnabled] = useState(false);
  const [error, setError] = useState(new URLSearchParams(location.search).get("login") === "failed" ? "统一登录未完成，请重新登录；仍失败时联系管理员。" : "");
  const [csrf, setCsrf] = useState("");
  const [domain, setDomain] = useState("");
  const api: Api = async (path, body) => {
    const r = await fetch("/api" + path, { method: body === undefined ? "GET" : "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: body === undefined ? undefined : JSON.stringify(body) });
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || "操作未完成，请重试");
    return data;
  };
  useEffect(() => {
    Promise.all([api("/applicant/auth"), api("/me").catch(() => null)]).then(([auth, user]) => {
      setDomain(auth.application_domain || ""); setEnabled(auth.enabled); setMe(user); setCsrf(user?.csrf || "");
    }).catch(e => setError(e.message)).finally(() => setReady(true));
  }, []);
  return <div className="applicant-page"><header className="applicant-header"><a href="/apply"><KeyRound size={25} /><strong>统一认证接入</strong></a>
    <div>{me ? <><span>{me.name || me.username}</span><button onClick={async () => {
      try { await api("/logout", {}); setMe(null); setCsrf(""); } catch (e: any) { setError(e.message); }
    }}><LogOut size={16} />退出</button></> : null}</div></header>
    <main className="applicant-content">{!ready ? <p>正在打开申请入口…</p> : me ? <>
      {me.role === "admin" && <div className="banner">当前以管理员身份查看申请入口。<a href="/">返回管理后台审批</a></div>}
      <ApplicationPanel key={me.username} api={api} me={me} domain={domain} />
    </> : <section className="applicant-welcome"><ClipboardList size={42} /><h1>申请应用统一认证接入</h1>
      <p>用员工账号登录，提交应用接入资料。审批发布完成后，在这里领取接入参数和密钥，并完成联调验收。</p>
      <ol><li>填写应用和权限需求</li><li>管理员审核并发布</li><li>领取凭据，完成接入验收</li></ol>
      {error && <div className="error" role="alert">{error}</div>}
      {enabled ? <a className="portal-login" href="/api/applicant/login">使用员工统一账号登录</a> : <p className="banner">员工统一登录尚未启用，请联系认证管理员完成配置。</p>}
      <small>每个应用每个环境独立申请。请勿在申请内容中填写密码、密钥或令牌。</small>
    </section>}</main></div>;
}
