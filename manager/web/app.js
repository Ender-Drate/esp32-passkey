/* TechXPassKey Manager — UI controller */
(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const state = {
    view: "overview",
    device: null,
    deviceError: null,
    vault: { exists: false, locked: true, count: 0 },
    items: [],
    passkeys: [],
    search: "",
    demo: { registered: false },
  };

  const TITLES = {
    overview: ["TECHXPASSKEY", "概览"],
    passkeys: ["CREDENTIALS", "Passkeys"],
    vault: ["ENCRYPTED VAULT", "密码库"],
    security: ["DEVICE", "安全"],
    demo: ["WEBAUTHN", "演示"],
    about: ["PRODUCT", "关于"],
  };

  // ---------------------------------------------------------------- helpers
  function esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }
  function fmtDate(epoch) {
    if (!epoch || epoch < 946684800) return "—";
    const d = new Date(epoch * 1000);
    if (isNaN(d)) return "—";
    return d.toLocaleDateString(undefined, { year: "numeric", month: "2-digit", day: "2-digit" });
  }
  function toast(msg, kind = "") {
    const el = document.createElement("div");
    el.className = "toast " + kind;
    el.textContent = msg;
    $("#toast-root").appendChild(el);
    setTimeout(() => el.remove(), 3200);
  }
  async function api(path, opts = {}) {
    const res = await fetch(path, {
      method: opts.method || "GET",
      headers: opts.raw ? {"Content-Type": "application/octet-stream"} : {"Content-Type": "application/json"},
      body: opts.raw ? opts.body : opts.body ? JSON.stringify(opts.body) : undefined,
    });
    const ct = res.headers.get("content-type") || "";
    const data = ct.includes("json") ? await res.json() : await res.text();
    if (!res.ok) throw new Error((data && data.error) || res.statusText);
    return data;
  }
  async function copy(text, label = "已复制") {
    try {
      await navigator.clipboard.writeText(text);
      toast(label, "ok");
    } catch {
      toast("复制失败", "err");
    }
  }

  // ---------------------------------------------------------------- routing
  function navigate(view) {
    if (!TITLES[view]) view = "overview";
    state.view = view;
    document.body.dataset.view = view;
    $$(".nav-item").forEach((b) => b.classList.toggle("is-active", b.dataset.view === view));
    $$(".view").forEach((v) => v.classList.toggle("is-hidden", v.dataset.view !== view));
    const [eyebrow, title] = TITLES[view];
    $("#eyebrow").textContent = eyebrow;
    $("#page-title").textContent = title;
    $("#global-search").placeholder =
      view === "passkeys" ? "搜索 Passkey" :
      view === "vault" ? "搜索密码" : "搜索";
    $("#global-search").value = state.search = "";
    window.scrollTo({ top: 0, behavior: "smooth" });
    if (view === "passkeys") loadPasskeys();
    if (view === "vault") renderVault();
    if (view === "security") renderSecurity();
    if (view === "demo") renderDemoStatus();
  }
  $$(".nav-item").forEach((b) => b.addEventListener("click", () => navigate(b.dataset.view)));
  $$("[data-view]").forEach((el) => {
    if (el.classList.contains("nav-item")) return;
    el.addEventListener("click", (e) => {
      e.preventDefault();
      navigate(el.dataset.view);
    });
  });

  // ---------------------------------------------------------------- state
  async function refresh() {
    try {
      const s = await api("/api/state");
      state.device = s.device;
      state.deviceError = s.deviceError;
      state.vault = s.vault;
      renderDevice();
      renderStats();
      if (state.device && state.view === "passkeys") await loadPasskeys();
      if (state.view === "overview" && state.device) await loadPasskeys(true);
    } catch (e) {
      toast(e.message, "err");
    }
  }

  function renderDevice() {
    const d = state.device;
    const ilOk = d ? d.il !== false : false;
    const ilPaired = d ? d.ilPaired !== false : true;
    $("#device-dot").className = "dot " + (d ? (ilOk ? "is-live" : "is-lock") : "is-off");
    $("#device-name").textContent = d ? "已连接" : "未连接";
    $("#device-port").textContent = d ? d.port : "";
    $("#device-name").title = d ? `${d.port} · ${d.pin ? "PIN 已设置" : "未设 PIN"}` : "";
    const badge = $("#hero-badge");
    if (d) {
      const note = ilOk ? "" : ilPaired ? " · 副板未连接" : " · 副板未配对";
      badge.innerHTML = `<span class="dot ${ilOk ? "is-live" : "is-lock"}"></span><span>已连接 · ${esc(d.port)}${note}</span>`;
    } else {
      badge.innerHTML = `<span class="dot"></span><span>设备未连接</span>`;
    }
    $("#nav-passkeys").textContent = d ? String(d.creds ?? "—") : "—";
    const connect = $("#btn-connect");
    if (connect) {
      connect.innerHTML = `${d ? "重新连接" : "连接设备"} <svg class="icon"><use href="#i-chevron"/></svg>`;
    }
  }

  function renderStats() {
    const d = state.device;
    $("#stat-passkeys").textContent = d ? d.creds : "—";
    $("#stat-passkeys-foot").textContent = d ? `最多 ${d.maxCreds} 个` : "常驻凭据";
    $("#stat-vault").textContent = state.vault.locked ? "—" : (state.vault.count ?? 0);
    $("#stat-vault-foot").textContent = state.vault.exists ? (state.vault.locked ? "已锁定" : "已解锁") : "尚未创建";
    $("#stat-pin").textContent = d ? (d.pin ? "已设置" : "未设置") : "—";
    $("#stat-pin").classList.add("text");
    $("#stat-pin-foot").textContent = d ? `剩余 ${d.retries} 次尝试` : "保护设备操作";
    $("#stat-space").textContent = d ? `${d.maxCreds - d.creds}` : "—";
  }

  // ---------------------------------------------------------------- passkeys
  async function loadPasskeys(silent = false) {
    if (!state.device) {
      renderPasskeys([]);
      return;
    }
    try {
      const r = await api("/api/device/passkeys");
      state.passkeys = r.items || [];
      state.device = { ...state.device, ...r.info };
      renderPasskeys(state.passkeys);
      renderStats();
    } catch (e) {
      if (!silent) toast(e.message, "err");
      renderPasskeys([]);
    }
  }

  function passkeyMatches(p) {
    if (!state.search) return true;
    const q = state.search.toLowerCase();
    return [p.rpId, p.userName, p.displayName, p.rpName].some((v) => (v || "").toLowerCase().includes(q));
  }

  function renderPasskeys(items) {
    const list = items.filter(passkeyMatches);
    const target = state.view === "overview" ? $("#overview-passkeys") : $("#passkey-list");
    if (!target) return;
    if (!items.length) {
      target.innerHTML = `<div class="empty"><strong>还没有 Passkey</strong>在 Chrome 里注册一个，或到「演示」页试一次。</div>`;
      return;
    }
    if (!list.length) {
      target.innerHTML = `<div class="empty">没有匹配的 Passkey</div>`;
      return;
    }
    const rows = (state.view === "overview" ? list.slice(0, 5) : list).map((p) => {
      const initial = (p.rpId || "?")[0];
      return `<div class="row">
        <div class="row-avatar">${esc(initial)}</div>
        <div class="row-main">
          <span class="row-title">${esc(p.rpId)}</span>
          <span class="row-sub">${esc(p.userName || p.displayName || "未命名用户")}${p.rpName ? " · " + esc(p.rpName) : ""}</span>
        </div>
        <span class="row-meta">${fmtDate(p.created)}</span>
        <div class="row-actions">
          <button class="row-action" data-copy="${esc(p.id)}">复制 ID</button>
          <button class="row-action danger" data-del-passkey="${esc(p.id)}">删除</button>
        </div>
      </div>`;
    }).join("");
    target.innerHTML = rows;
    $$("[data-copy]", target).forEach((b) => b.addEventListener("click", () => copy(b.dataset.copy, "凭据 ID 已复制")));
    $$("[data-del-passkey]", target).forEach((b) => b.addEventListener("click", () => confirmDeletePasskey(b.dataset.delPasskey)));
  }

  function confirmDeletePasskey(id) {
    const needsPin = state.device && state.device.pin;
    openSheet({
      title: "删除这个 Passkey？",
      subtitle: "删除后该网站将无法再用这块设备登录，操作不可撤销。",
      body: needsPin
        ? `<label class="form-label">设备 PIN</label><input class="field" id="del-pin" type="password" placeholder="输入设备 PIN">`
        : `<p class="muted">设备未设置 PIN，直接确认删除。</p>`,
      actions: [
        { label: "取消", kind: "ghost", close: true },
        { label: "删除", kind: "danger", onClick: async (root) => {
            const pin = needsPin ? $("#del-pin", root).value : "";
            await api("/api/device/passkeys/delete", { method: "POST", body: { id, pin } });
            toast("已删除", "ok");
            closeSheet();
            await loadPasskeys();
            await refresh();
          } },
      ],
    });
  }

  // ---------------------------------------------------------------- vault
  function renderVault() {
    const unlocked = !state.vault.locked;
    $("#vault-locked").classList.toggle("is-hidden", unlocked);
    $("#vault-unlocked").classList.toggle("is-hidden", !unlocked);
    $("#unlock-title").textContent = state.vault.exists ? "解锁密码库" : "创建密码库";
    $("#unlock-sub").textContent = state.vault.exists
      ? "密码库使用 scrypt + AES-256-GCM 加密，只保存在本机。"
      : "第一次使用：设置一个主密码，它不会被上传，也无法找回。";
    $("#unlock-submit").textContent = state.vault.exists ? "解锁" : "创建并解锁";
    $("#unlock-hint").classList.toggle("is-hidden", state.vault.exists);
    if (unlocked) loadVaultItems();
  }

  async function loadVaultItems() {
    try {
      const r = await api("/api/vault/items");
      state.items = r.items || [];
      state.vault.count = state.items.length;
      $("#vault-summary").textContent = `${state.items.length} 个条目 · 已解锁 · AES-256-GCM`;
      renderVaultItems();
    } catch (e) {
      toast(e.message, "err");
    }
  }

  function vaultMatches(it) {
    if (!state.search) return true;
    const q = state.search.toLowerCase();
    return [it.title, it.username, it.url, it.notes].some((v) => (v || "").toLowerCase().includes(q));
  }

  function renderVaultItems() {
    const list = state.items.filter(vaultMatches).sort((a, b) => (b.updated || 0) - (a.updated || 0));
    const target = $("#vault-list");
    if (!state.items.length) {
      target.innerHTML = `<div class="empty"><strong>密码库是空的</strong>新建一个条目，或从 Chrome / Bitwarden / KeePass 导入。</div>`;
      return;
    }
    if (!list.length) {
      target.innerHTML = `<div class="empty">没有匹配的条目</div>`;
      return;
    }
    target.innerHTML = list.map((it) => `
      <div class="row" data-item="${it.id}">
        <div class="row-avatar">${esc((it.title || "?")[0])}</div>
        <div class="row-main">
          <span class="row-title">${esc(it.title || "未命名")}</span>
          <span class="row-sub">${esc(it.username || "无用户名")}${it.url ? " · " + esc(it.url) : ""}</span>
        </div>
        ${it.totp ? `<span class="totp" data-totp="${it.id}"><span class="code">------</span><span class="totp-bar"><i></i></span></span>` : ""}
        <div class="row-actions">
          <button class="row-action" data-copy-pass="${it.id}">复制</button>
          <button class="row-action" data-edit="${it.id}">编辑</button>
          <button class="row-action danger" data-del-item="${it.id}">删除</button>
        </div>
      </div>`).join("");
    $$("[data-copy-user]").forEach((b) => b.addEventListener("click", () => {
      const it = state.items.find((x) => x.id === b.dataset.copyUser);
      if (it) copy(it.username || "");
    }));
    $$("[data-copy-pass]").forEach((b) => b.addEventListener("click", () => {
      const it = state.items.find((x) => x.id === b.dataset.copyPass);
      if (it) copy(it.password || "", "密码已复制");
    }));
    $$("[data-edit]").forEach((b) => b.addEventListener("click", () => {
      const it = state.items.find((x) => x.id === b.dataset.edit);
      if (it) openItemSheet(it);
    }));
    $$("[data-del-item]").forEach((b) => b.addEventListener("click", () => {
      const it = state.items.find((x) => x.id === b.dataset.delItem);
      if (it) confirmDeleteItem(it);
    }));
    updateTotpCodes();
  }

  function confirmDeleteItem(it) {
    openSheet({
      title: "删除条目？",
      subtitle: `「${it.title || "未命名"}」将从加密密码库中移除。`,
      body: `<p class="muted">此操作不可撤销。</p>`,
      actions: [
        { label: "取消", kind: "ghost", close: true },
        { label: "删除", kind: "danger", onClick: async () => {
            await api(`/api/vault/items/${it.id}`, { method: "DELETE" });
            closeSheet();
            toast("已删除", "ok");
            await loadVaultItems();
          } },
      ],
    });
  }

  function openItemSheet(item = null) {
    const it = item || { title: "", username: "", password: "", url: "", totp: "", notes: "", tags: [] };
    openSheet({
      title: item ? "编辑条目" : "新建条目",
      subtitle: "内容只写入本地加密密码库。",
      body: `
        <div class="form-grid">
          <div class="full"><label class="form-label">标题</label><input class="field" id="f-title" value="${esc(it.title)}" placeholder="例如 GitHub"></div>
          <div><label class="form-label">用户名</label><input class="field" id="f-user" value="${esc(it.username)}" placeholder="me@example.com"></div>
          <div><label class="form-label">网址</label><input class="field" id="f-url" value="${esc(it.url)}" placeholder="https://"></div>
          <div class="full"><label class="form-label">密码</label>
            <div class="pw-wrap"><input class="field" id="f-pass" type="password" value="${esc(it.password)}" placeholder="••••••••">
            <button class="icon-btn" id="f-eye" type="button" title="显示"><svg class="icon"><use href="#i-eye"/></svg></button></div>
          </div>
          <div class="full"><button class="btn ghost small" id="f-gen" type="button"><svg class="icon"><use href="#i-sparkle"/></svg>生成随机密码</button></div>
          <div class="full"><label class="form-label">TOTP 密钥（可选）</label><input class="field" id="f-totp" value="${esc(it.totp)}" placeholder="BASE32 或 otpauth:// URI"></div>
          <div class="full"><label class="form-label">备注</label><textarea class="field" id="f-notes" placeholder="恢复码、安全问题…">${esc(it.notes)}</textarea></div>
        </div>`,
      actions: [
        { label: "取消", kind: "ghost", close: true },
        { label: "保存", kind: "primary", onClick: async (root) => {
            const payload = {
              title: $("#f-title", root).value.trim(),
              username: $("#f-user", root).value.trim(),
              url: $("#f-url", root).value.trim(),
              password: $("#f-pass", root).value,
              totp: $("#f-totp", root).value.trim(),
              notes: $("#f-notes", root).value,
            };
            if (!payload.title) { toast("请填写标题", "err"); return; }
            if (item) await api(`/api/vault/items/${item.id}`, { method: "PUT", body: { item: payload } });
            else await api("/api/vault/items", { method: "POST", body: { item: payload } });
            closeSheet();
            toast("已保存", "ok");
            await loadVaultItems();
          } },
      ],
      onMount: (root) => {
        $("#f-eye", root).addEventListener("click", () => {
          const f = $("#f-pass", root);
          f.type = f.type === "password" ? "text" : "password";
        });
        $("#f-gen", root).addEventListener("click", async () => {
          const r = await api("/api/vault/generate", { method: "POST", body: { length: 20 } });
          const f = $("#f-pass", root);
          f.value = r.password;
          f.type = "text";
          toast("已生成 20 位密码", "ok");
        });
      },
    });
  }

  function updateTotpCodes() {
    $$("[data-totp]").forEach(async (el) => {
      const id = el.dataset.totp;
      try {
        const r = await api(`/api/totp/${id}`);
        $(".code", el).textContent = r.code.replace(/(\d{3})(\d{3})/, "$1 $2");
        const bar = $(".totp-bar i", el);
        if (bar) bar.style.width = `${(r.remaining / 30) * 100}%`;
      } catch { /* ignore */ }
    });
  }
  setInterval(() => {
    if (!state.vault.locked && state.view === "vault") updateTotpCodes();
  }, 1000);

  // ---------------------------------------------------------------- sheets
  let sheetEl = null;
  function openSheet({ title, subtitle, body, actions = [], onMount }) {
    closeSheet();
    const backdrop = document.createElement("div");
    backdrop.className = "modal-backdrop";
    backdrop.innerHTML = `
      <div class="sheet" role="dialog" aria-modal="true">
        <div class="sheet-head">
          <div><h2>${esc(title)}</h2>${subtitle ? `<p>${esc(subtitle)}</p>` : ""}</div>
          <button class="sheet-close" title="关闭"><svg class="icon"><use href="#i-x"/></svg></button>
        </div>
        <div class="sheet-body">${body}</div>
        <div class="sheet-actions"></div>
      </div>`;
    const actionsEl = $(".sheet-actions", backdrop);
    actions.forEach((a) => {
      const btn = document.createElement("button");
      btn.className = "btn " + (a.kind || "ghost");
      btn.textContent = a.label;
      btn.addEventListener("click", async () => {
        try {
          if (a.close) return closeSheet();
          if (a.onClick) { btn.disabled = true; await a.onClick(backdrop); }
        } catch (e) {
          toast(e.message, "err");
        } finally {
          btn.disabled = false;
        }
      });
      actionsEl.appendChild(btn);
    });
    $(".sheet-close", backdrop).addEventListener("click", closeSheet);
    backdrop.addEventListener("mousedown", (e) => { if (e.target === backdrop) closeSheet(); });
    document.addEventListener("keydown", escClose);
    $("#modal-root").appendChild(backdrop);
    sheetEl = backdrop;
    if (onMount) onMount(backdrop);
  }
  function closeSheet() {
    if (sheetEl) { sheetEl.remove(); sheetEl = null; }
    document.removeEventListener("keydown", escClose);
  }
  function escClose(e) { if (e.key === "Escape") closeSheet(); }

  // ---------------------------------------------------------------- security
  function renderSecurity() {
    const d = state.device;
    const ilPill = $("#il-pill");
    if (ilPill) {
      if (!d) {
        ilPill.className = "pill";
        ilPill.textContent = "—";
      } else if (d.il === false) {
        ilPill.className = "pill bad";
        ilPill.textContent = d.ilPaired === false ? "未配对" : "未连接";
      } else {
        ilPill.className = "pill ok";
        ilPill.textContent = "已连接";
      }
    }
    const pill = $("#pin-pill");
    if (!d) { pill.className = "pill"; pill.textContent = "未连接"; return; }
    pill.className = "pill " + (d.pin ? "ok" : "warn");
    pill.textContent = d.pin ? `已设置 · 剩余 ${d.retries} 次` : "未设置";
    $$("#upmode-seg button").forEach((b) => b.classList.toggle("is-active", (b.dataset.mode === "auto") === (d.upMode === 1)));
  }

  $("#pin-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const current = $("#pin-current").value;
    const next = $("#pin-new").value;
    if (next.length < 4) return toast("新 PIN 至少 4 位", "err");
    try {
      const action = state.device && state.device.pin ? "change" : "set";
      await api("/api/device/pin", { method: "POST", body: { action, pin: current, newPin: next } });
      $("#pin-current").value = $("#pin-new").value = "";
      toast("PIN 已更新", "ok");
      await refresh();
      renderSecurity();
    } catch (err) { toast(err.message, "err"); }
  });

  $$("#upmode-seg button").forEach((b) => b.addEventListener("click", async () => {
    try {
      await api("/api/device/upmode", { method: "POST", body: { mode: b.dataset.mode } });
      toast(b.dataset.mode === "auto" ? "已开启自动确认（仅测试用）" : "已切换为按键确认", "ok");
      await refresh();
      renderSecurity();
    } catch (e) { toast(e.message, "err"); }
  }));

  $("#ota-file").addEventListener("change", (e) => {
    const f = e.target.files[0];
    const label = $("#ota-file-label");
    if (f) label.innerHTML = `<svg class="icon"><use href="#i-check"/></svg>${esc(f.name)}`;
  });

  $("#btn-ota").addEventListener("click", async () => {
    const file = $("#ota-file").files[0];
    if (!file) return toast("先选择 firmware.bin", "err");    const buf = await file.arrayBuffer();
    const prog = $("#ota-progress");
    prog.classList.remove("is-hidden");
    $(".bar", prog).style.width = "30%";
    try {
      const r = await api("/api/device/ota", { method: "POST", raw: true, body: buf });
      $(".bar", prog).style.width = "100%";
      toast(`固件已写入 ${r.bytes} 字节，设备重启中`, "ok");
      setTimeout(() => refresh(), 4000);
    } catch (e) {
      toast(e.message, "err");
      prog.classList.add("is-hidden");
    }
  });

  $("#reset-form").addEventListener("submit", async (e) => {    e.preventDefault();
    const pin = $("#reset-pin").value;
    openSheet({
      title: "确认恢复出厂？",
      subtitle: "设备中的 Passkey、PIN、largeBlob 会全部清除，无法撤销。",
      body: `<p class="muted">这条操作会立即执行。</p>`,
      actions: [
        { label: "取消", kind: "ghost", close: true },
        { label: "确认清除", kind: "danger", onClick: async () => {
            await api("/api/device/reset", { method: "POST", body: { pin } });
            closeSheet();
            $("#reset-pin").value = "";
            toast("设备已恢复出厂", "ok");
            state.passkeys = [];
            await refresh();
          } },
      ],
    });
  });

  // ---------------------------------------------------------------- vault forms
  $("#unlock-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const pw = $("#unlock-password").value;
    if (!pw) return;
    try {
      if (state.vault.exists) await api("/api/vault/unlock", { method: "POST", body: { password: pw } });
      else await api("/api/vault/create", { method: "POST", body: { password: pw } });
      $("#unlock-password").value = "";
      state.vault.locked = false;
      state.vault.exists = true;
      toast(state.vault.exists ? "密码库已解锁" : "密码库已创建", "ok");
      await refresh();
      renderVault();
    } catch (err) { toast(err.message, "err"); }
  });

  $("#btn-vault-lock").addEventListener("click", async () => {
    await api("/api/vault/lock", { method: "POST" });
    state.vault.locked = true;
    state.items = [];
    toast("密码库已锁定");
    renderVault();
  });
  $("#btn-vault-add").addEventListener("click", () => openItemSheet());
  $("#btn-refresh-passkeys")?.addEventListener("click", () => loadPasskeys());
  $("#btn-connect").addEventListener("click", async () => {
    try { await api("/api/device/connect", { method: "POST", body: {} }); toast("设备已连接", "ok"); await refresh(); }
    catch (e) { toast(e.message, "err"); }
  });
  $("#btn-refresh").addEventListener("click", () => refresh());

  $("#btn-vault-import").addEventListener("click", () => openSheet({
    title: "导入密码",
    subtitle: "支持 Chrome/Edge CSV、Bitwarden JSON/CSV、1Password、KeePass、LastPass 与通用 CSV。",
    body: `
      <label class="form-label">粘贴导出内容</label>
      <textarea class="field" id="imp-text" placeholder="把 CSV / JSON 粘到这里，或选择文件"></textarea>
      <div style="margin-top:10px"><input type="file" id="imp-file" accept=".csv,.json,.txt" class="field"></div>`,
    actions: [
      { label: "取消", kind: "ghost", close: true },
      { label: "导入", kind: "primary", onClick: async (root) => {
          const text = $("#imp-text", root).value.trim();
          if (!text) { toast("内容为空", "err"); return; }
          const r = await api("/api/vault/import", { method: "POST", body: { format: "auto", text } });
          closeSheet();
          toast(`已导入 ${r.count} 条（${r.format}）`, "ok");
          await loadVaultItems();
        } },
    ],
    onMount: (root) => {
      $("#imp-file", root).addEventListener("change", async (e) => {
        const f = e.target.files[0];
        if (f) $("#imp-text", root).value = await f.text();
      });
    },
  }));

  $("#btn-vault-export").addEventListener("click", () => openSheet({
    title: "导出密码库",
    subtitle: "导出文件是明文，请妥善保管，使用后及时删除。",
    body: `<div class="stack">
      <button class="btn ghost wide" data-exp="chrome">Chrome / Edge CSV</button>
      <button class="btn ghost wide" data-exp="bitwarden-json">Bitwarden JSON</button>
      <button class="btn ghost wide" data-exp="keepass">KeePass CSV</button>
    </div>`,
    actions: [{ label: "关闭", kind: "ghost", close: true }],
    onMount: (root) => {
      $$("[data-exp]", root).forEach((b) => b.addEventListener("click", async () => {
        try {
          const r = await api("/api/vault/export", { method: "POST", body: { format: b.dataset.exp } });
          const blob = new Blob([r.content], { type: "text/plain;charset=utf-8" });
          const a = document.createElement("a");
          a.href = URL.createObjectURL(blob);
          a.download = r.filename;
          a.click();
          URL.revokeObjectURL(a.href);
          toast("导出文件已生成", "ok");
        } catch (e) { toast(e.message, "err"); }
      }));
    },
  }));

  // ---------------------------------------------------------------- demo
  function demoLog(msg, cls = "") {
    const el = $("#demo-log");
    const t = new Date().toLocaleTimeString();
    el.insertAdjacentHTML("beforeend", `<div class="${cls}">[${t}] ${esc(msg)}</div>`);
    el.scrollTop = el.scrollHeight;
  }
  async function renderDemoStatus() {
    try {
      const s = await api("/api/webauthn/status");
      state.demo = s;
      $("#demo-state").textContent = s.registered ? "已注册 · 凭据可用" : "未注册";
      $("#btn-wa-login").disabled = !s.registered;
    } catch { /* ignore */ }
  }
  function b64u(buf) {
    const b = new Uint8Array(buf);
    let s = "";
    for (const x of b) s += String.fromCharCode(x);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function unb64u(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    const raw = atob(s + "=".repeat((4 - s.length % 4) % 4));
    return Uint8Array.from(raw, (c) => c.charCodeAt(0));
  }
  $("#btn-wa-register").addEventListener("click", async () => {
    try {
      demoLog("获取注册参数…");
      const opt = (await api("/api/webauthn/register/options", { method: "POST" })).publicKey;
      opt.challenge = unb64u(opt.challenge);
      opt.user.id = unb64u(opt.user.id);
      demoLog("请选择 TechXPassKey，然后按 BOOT…");
      const cred = await navigator.credentials.create({ publicKey: opt });
      const r = await api("/api/webauthn/register/verify", { method: "POST", body: {
        id: cred.id, rawId: b64u(cred.rawId),
        response: {
          clientDataJSON: b64u(cred.response.clientDataJSON),
          attestationObject: b64u(cred.response.attestationObject),
        },
      } });
      demoLog(`注册成功 · ${r.credId}`, "ok");
      await renderDemoStatus();
      await refresh();
    } catch (e) { demoLog("注册失败: " + e.message, "err"); }
  });
  $("#btn-wa-login").addEventListener("click", async () => {
    try {
      const opt = (await api("/api/webauthn/login/options", { method: "POST" })).publicKey;
      opt.challenge = unb64u(opt.challenge);
      opt.allowCredentials = (opt.allowCredentials || []).map((c) => ({ ...c, id: unb64u(c.id) }));
      demoLog("请选择 TechXPassKey，然后按 BOOT…");
      const cred = await navigator.credentials.get({ publicKey: opt });
      const r = await api("/api/webauthn/login/verify", { method: "POST", body: {
        id: cred.id, rawId: b64u(cred.rawId),
        response: {
          clientDataJSON: b64u(cred.response.clientDataJSON),
          authenticatorData: b64u(cred.response.authenticatorData),
          signature: b64u(cred.response.signature),
        },
      } });
      demoLog(`登录验证通过 · counter=${r.signCount} flags=0x${r.flags.toString(16)}`, "ok");
    } catch (e) { demoLog("登录失败: " + e.message, "err"); }
  });

  // ---------------------------------------------------------------- global
  $("#global-search").addEventListener("input", (e) => {
    state.search = e.target.value.trim();
    if (state.view === "passkeys" || state.view === "overview") renderPasskeys(state.passkeys);
    if (state.view === "vault") renderVaultItems();
  });

  $$("[data-action]").forEach((b) => b.addEventListener("click", () => {
    const a = b.dataset.action;
    if (a === "set-pin") { navigate("security"); $("#pin-new").focus(); }
    if (a === "sync-time") api("/api/device/connect", { method: "POST", body: {} })
      .then(() => toast("时间已同步", "ok")).catch((e) => toast(e.message, "err"));
    if (a === "ota") navigate("security");
    if (a === "demo") navigate("demo");
  }));

  // boot
  document.body.dataset.view = "overview";
  const bootView = new URLSearchParams(location.search).get("view");
  refresh().then(() => {
    if (state.device) loadPasskeys(true);
    renderVault();
    if (bootView) navigate(bootView);
  });
  setInterval(() => { if (state.view === "overview" || state.view === "passkeys") refresh(); }, 15000);
})();
