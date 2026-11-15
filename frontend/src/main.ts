// The window's behaviour. All decisions (is the button ready, what is missing)
// come from Go's SageService.Status, so they live in one tested place.

import "./style.css";
import {Browser, Events} from "@wailsio/runtime";
import {SageService} from "../bindings/sage";

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

const list = $("list");
const summary = $("summary");
const hint = $("hint");
const actionBtn = $<HTMLButtonElement>("action");
const cancelBtn = $<HTMLButtonElement>("cancel");
const fill = $("progressFill");
const passphrase = $<HTMLInputElement>("passphrase");
const confirmPass = $<HTMLInputElement>("confirm");
const showPass = $<HTMLButtonElement>("showPass");
const recipients = $<HTMLTextAreaElement>("recipients");
const recipientsFile = $<HTMLInputElement>("recipientsFile");
const identities = $<HTMLTextAreaElement>("identities");
const armor = $<HTMLInputElement>("armor");
const pq = $<HTMLInputElement>("pq");

// ---------------------------------------------------------------- state

// One row per file. "done" rows stay visible with their result but are not part
// of the next run; "failed" rows show why and are retried by the next run.
type RowStatus = "ready" | "working" | "done" | "failed";
interface Entry {
    path: string;
    size?: number;
    status: RowStatus;
    output?: string; // the file written
    error?: string;  // why it failed
}

let entries: Entry[] = [];
const rowEls = new Map<Entry, HTMLElement>();
let tab: "passphrase" | "recipient" = "passphrase";
let busy = false;
let lastSummary = "";   // "Finished: 2 OK, 1 failed." after a run
let notes = "";         // notes from adding files, settings, etc.
let notesWarn = false;
let notesSticky = false; // a reminder that a run doesn't clear (the generated passphrase)

/** The files the next run will process. */
function pending(): string[] {
    return entries.filter(e => e.status !== "done").map(e => e.path);
}

/** .age files are decrypted, everything else encrypted (Go keeps the list from mixing). */
function modeOf(paths: string[]): "" | "encrypt" | "decrypt" {
    if (paths.length === 0) return "";
    return paths.every(p => p.toLowerCase().endsWith(".age")) ? "decrypt" : "encrypt";
}

function baseName(p: string): string {
    return p.slice(Math.max(p.lastIndexOf("\\"), p.lastIndexOf("/")) + 1);
}

function folderOf(p: string): string {
    const dir = p.slice(0, Math.max(p.lastIndexOf("\\"), p.lastIndexOf("/")));
    return /^[A-Za-z]:$/.test(dir) ? dir + "\\" : dir; // a drive root is "F:\" ("F:" alone means the current folder there)
}

function formatSize(n?: number): string {
    if (n === undefined) return "";
    if (n < 1024) return `${n} B`;
    const units = ["KB", "MB", "GB", "TB"];
    let v = n / 1024, u = 0;
    while (v >= 1024 && u < units.length - 1) { v /= 1024; u++; }
    return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[u]}`;
}

function icon(name: string, cls = "ic"): SVGSVGElement {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", cls);
    svg.setAttribute("aria-hidden", "true");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", `#i-${name}`);
    svg.append(use);
    return svg;
}

// ---------------------------------------------------------------- the list

const STATUS_TEXT: Record<RowStatus, string> = {
    ready: "ready", working: "working", done: "done", failed: "failed",
};

function rowButton(iconName: string, label: string, onclick: () => void, disabled = false): HTMLButtonElement {
    const btn = document.createElement("button");
    btn.className = "row-btn";
    btn.type = "button";
    btn.append(icon(iconName));
    btn.title = label;
    btn.setAttribute("aria-label", label);
    btn.dataset.action = iconName;
    btn.disabled = disabled;
    btn.onclick = onclick;
    return btn;
}

function removeEntry(e: Entry) {
    const index = entries.indexOf(e);
    entries = entries.filter(x => x !== e);
    if (!entries.some(x => x.status === "done" || x.status === "failed")) lastSummary = "";
    renderList();
    refresh();
    // Keep keyboard focus nearby instead of losing it with the removed row.
    const rows = list.querySelectorAll<HTMLElement>(".row-file");
    const next = rows[Math.min(index, rows.length - 1)]?.querySelector<HTMLButtonElement>("button[data-action='x']");
    (next ?? $("addFiles")).focus();
}

function buildRow(e: Entry): HTMLElement {
    const row = document.createElement("div");
    row.className = `row-file ${e.status}`;
    row.setAttribute("role", "listitem");
    row.title = e.path;

    const name = document.createElement("span");
    name.className = "cell-name";
    const iconName = e.status === "done" ? "check" : e.status === "failed" ? "alert"
        : e.status === "working" ? "loader" : e.path.toLowerCase().endsWith(".age") ? "lock" : "file";
    const label = document.createElement("span");
    label.className = "ellipsis";
    label.textContent = baseName(e.path);
    name.append(icon(iconName), label);

    // Second column: the folder, or after a run the output name or what went wrong.
    const sub = document.createElement("span");
    sub.className = "cell-sub ellipsis";
    const detail = e.status === "done" ? `\u2192 ${baseName(e.output ?? "")}`
        : e.status === "failed" ? e.error ?? "Failed" : folderOf(e.path);
    sub.textContent = detail;
    if (e.status === "done") sub.title = e.output ?? "";
    if (e.status === "failed") sub.title = e.error ?? "";

    const size = document.createElement("span");
    size.className = "num cell-sub";
    size.textContent = formatSize(e.size);

    const actions = document.createElement("span");
    actions.className = "row-actions";
    if (e.status === "done") {
        actions.append(rowButton("folder-open", `Show ${baseName(e.output ?? "")} in its folder`,
            () => SageService.OpenFolder(e.output ?? "").catch(err => setNotes(String(err?.message ?? err), true))));
    }
    actions.append(rowButton("x", `Remove ${baseName(e.path)} from the list`, () => removeEntry(e), busy));

    // Screen readers: the row says what it is and how it went (the icon is decorative).
    row.setAttribute("aria-label", `${baseName(e.path)}, ${STATUS_TEXT[e.status]}: ${detail}`);
    row.append(name, sub, size, actions);
    rowEls.set(e, row);
    return row;
}

function updateHeader() {
    // After a run the second column shows each file's result instead of its folder.
    const ran = entries.filter(e => e.status === "done" || e.status === "failed").length;
    $("colSecond").textContent = ran === 0 ? "Folder" : ran === entries.length ? "Result" : "Folder / result";
}

/** Rebuild every row, keeping the scroll position and keyboard focus. */
function renderList() {
    const scroll = list.scrollTop;
    const focused = document.activeElement as HTMLElement | null;
    const focusRow = focused && list.contains(focused)
        ? Array.from(rowEls.entries()).find(([, el]) => el.contains(focused))?.[0] : undefined;
    const focusAction = focused?.dataset?.action;

    list.replaceChildren();
    rowEls.clear();
    updateHeader();
    if (entries.length === 0) {
        const empty = document.createElement("div");
        empty.className = "empty";
        empty.setAttribute("role", "listitem");
        const title = document.createElement("strong");
        title.textContent = "Drop files or folders here";
        const l1 = document.createElement("span");
        l1.textContent = ".age files are decrypted, everything else is encrypted.";
        const l2 = document.createElement("span");
        l2.textContent = "Output goes next to each file; existing files are never overwritten.";
        empty.append(icon("file-plus"), title, l1, l2);
        list.append(empty);
        return;
    }
    for (const e of entries) list.append(buildRow(e));
    list.scrollTop = scroll;
    if (focusRow && rowEls.has(focusRow)) {
        rowEls.get(focusRow)!.querySelector<HTMLButtonElement>(`button[data-action='${focusAction}']`)?.focus();
    }
}

/** Redraw one row in place (results and progress), keeping focus if it was in that row. */
function updateRow(e: Entry) {
    const old = rowEls.get(e);
    if (!old) return renderList();
    const focused = document.activeElement as HTMLElement | null;
    const hadFocus = focused && old.contains(focused) ? focused.dataset.action : undefined;
    const row = buildRow(e);
    old.replaceWith(row);
    if (hadFocus) row.querySelector<HTMLButtonElement>(`button[data-action='${hadFocus}']`)?.focus();
    updateHeader();
}

function setNotes(text: string, warn = false, sticky = false) {
    notes = text;
    notesWarn = warn;
    notesSticky = sticky;
    renderSummary();
}

function renderSummary() {
    const lines: string[] = [];
    const todo = pending();
    if (lastSummary) {
        lines.push(lastSummary);
    } else if (todo.length) {
        const bytes = entries.filter(e => e.status !== "done").reduce((s, e) => s + (e.size ?? 0), 0);
        const verb = modeOf(todo) === "decrypt" ? "decrypted" : "encrypted";
        lines.push(`${todo.length} file${todo.length === 1 ? "" : "s"} will be ${verb} \u00b7 ${formatSize(bytes)}`);
    }
    summary.replaceChildren();
    if (lines.length) summary.append(lines.join("\n"));
    if (notes) {
        const n = document.createElement("div");
        if (notesWarn) n.className = "warn";
        n.textContent = notes;
        summary.append(n);
    }
}

function setProgress(fraction: number, visible = true) {
    fill.style.width = `${Math.round(fraction * 100)}%`;
    fill.style.opacity = visible ? "1" : "0";
}

// ---------------------------------------------------------------- state -> UI

// For Status (called on every keystroke): facts about the passphrase, never the
// passphrase itself. Start sends the real passphrase, once.
function request(withPassphrase = false) {
    const p = passphrase.value, c = confirmPass.value;
    const files = pending();
    return {
        files, mode: modeOf(files), tab,
        passphrase: withPassphrase ? p : "",
        confirm: withPassphrase ? c : "",
        passInfo: {set: p !== "", confirmSet: c !== "", match: p === c, lineBreak: /[\r\n]/.test(p + c)},
        recipients: recipients.value,
        recipientsFile: recipientsFile.value,
        identities: identities.value,
        armor: armor.checked,
    };
}

let refreshSeq = 0;

async function refresh() {
    const mode = modeOf(pending());
    confirmPass.hidden = mode === "decrypt";
    $("genPass").hidden = mode === "decrypt";
    armor.disabled = busy || mode === "decrypt";
    $<HTMLButtonElement>("inspect").disabled = busy || !entries.some(e => e.path.toLowerCase().endsWith(".age"));

    for (const id of ["addFiles", "addFolder", "clear", "tabPassphrase", "tabRecipient", "help",
        "browseRecipients", "addIdentity", "keygen", "genPass", "showPass"]) {
        $<HTMLButtonElement>(id).disabled = busy;
    }
    for (const el of [passphrase, confirmPass, recipients, recipientsFile, identities, pq]) {
        el.disabled = busy;
    }
    list.querySelectorAll<HTMLButtonElement>("button[data-action='x']").forEach(b => { b.disabled = busy; });
    renderSummary();
    cancelBtn.hidden = !busy;
    if (busy) {
        actionBtn.disabled = true;
        actionBtn.textContent = "Working...";
        return;
    }

    const seq = ++refreshSeq;
    const st = await SageService.Status(request() as any);
    if (seq !== refreshSeq || busy) return; // a newer refresh, or a job started meanwhile
    actionBtn.disabled = !st.enabled;
    actionBtn.textContent = st.button;
    if (entries.length && pending().length === 0) {
        hint.textContent = "All done. Add more files, or Clear to start over.";
        hint.classList.remove("warn");
    } else {
        hint.textContent = st.hint;
        hint.classList.toggle("warn", st.warn);
    }
}

function setTab(t: "passphrase" | "recipient", save = true) {
    tab = t;
    for (const [id, on] of [["tabPassphrase", t === "passphrase"], ["tabRecipient", t === "recipient"]] as const) {
        $(id).classList.toggle("active", on);
        $(id).setAttribute("aria-selected", String(on));
        $(id).tabIndex = on ? 0 : -1;
    }
    $("panelPassphrase").hidden = t !== "passphrase";
    $("panelRecipient").hidden = t !== "recipient";
    if (save) saveSettingsSoon();
    refresh();
}

// ---------------------------------------------------------------- settings

let saveTimer: ReturnType<typeof setTimeout> | undefined;
let settingsErrorShown = false;

function saveSettingsSoon() {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
        SageService.SaveSettings({
            activeTab: tab,
            recipients: recipients.value,
            recipientsFile: recipientsFile.value,
            identities: identities.value,
            armor: armor.checked,
            postQuantum: pq.checked,
        } as any).catch(err => {
            if (!settingsErrorShown) {
                settingsErrorShown = true;
                setNotes(String(err?.message ?? err), true);
            }
        });
    }, 400);
}

// ---------------------------------------------------------------- files

// Adds run one after another, so two quick drops can't overwrite each other's files.
let addQueue: Promise<void> = Promise.resolve();
function addPaths(paths: string[] | null): Promise<void> {
    addQueue = addQueue.then(() => addPathsNow(paths)).catch(() => {});
    return addQueue;
}

async function addPathsNow(paths: string[] | null) {
    if (!paths || paths.length === 0) return;
    if (busy) {
        hint.textContent = "Busy: wait for the current job to finish, or press Cancel.";
        hint.classList.add("warn");
        return;
    }
    const before = pending();
    const res = await SageService.AddPaths(before, paths);
    if (busy) return; // a job started while this was in flight
    const resFiles = res.files ?? []; // Go sends an empty list as null
    const warn = res.note.startsWith("No files") || res.note.includes("Not added");
    // Nothing new: keep the list (and the last run's results); just show the note.
    if (resFiles.length === before.length && resFiles.every((p, i) => p === before[i])) {
        setNotes(res.note, warn);
        return;
    }
    const sizes = res.sizes ?? {};
    // New files start a new batch: finished rows from the last run go away.
    const old = new Map(entries.filter(e => e.status !== "done").map(e => [e.path, e]));
    entries = resFiles.map(p => old.get(p) ?? {path: p, size: sizes[p], status: "ready" as RowStatus});
    for (const e of entries) if (e.size === undefined) e.size = sizes[e.path];
    lastSummary = "";
    setProgress(0, false);
    renderList();
    setNotes(res.note, warn);
    refresh();
    if (tab === "passphrase" && entries.length) passphrase.focus();
}

function appendLine(area: HTMLTextAreaElement, line: string) {
    const v = area.value;
    area.value = (v && !v.endsWith("\n") ? v + "\n" : v) + line + "\n";
}

// ---------------------------------------------------------------- dialogs

// Dialogs are modal: focus moves to their Close button, Tab stays inside, Esc closes,
// and focus returns to whatever opened them.
let dialogOpener: HTMLElement | null = null;

function openDialog(id: string) {
    dialogOpener = document.activeElement as HTMLElement | null;
    $(id).hidden = false;
    $(id).querySelector<HTMLButtonElement>(".modal-actions .btn")?.focus();
}

function closeDialog(id: string) {
    if ($(id).hidden) return;
    $(id).hidden = true;
    if (dialogOpener && document.contains(dialogOpener)) dialogOpener.focus();
    dialogOpener = null;
}

function openModal(): HTMLElement | null {
    return document.querySelector<HTMLElement>(".modal:not([hidden])");
}

document.addEventListener("keydown", e => {
    const modal = openModal();
    if (!modal) return;
    if (e.key === "Escape") {
        e.preventDefault();
        closeDialog(modal.id);
    } else if (e.key === "Tab") {
        const items = Array.from(modal.querySelectorAll<HTMLElement>("a[href], button:not([disabled])"));
        if (items.length === 0) return;
        const i = items.indexOf(document.activeElement as HTMLElement);
        const next = e.shiftKey ? (i <= 0 ? items.length - 1 : i - 1) : (i === items.length - 1 ? 0 : i + 1);
        e.preventDefault();
        items[next].focus();
    }
});

function showInfo(title: string, text: string) {
    $("infoTitle").textContent = title;
    $("infoText").textContent = text;
    openDialog("infoDialog");
}

// ---------------------------------------------------------------- the job

async function run() {
    if (busy || actionBtn.disabled) return;
    // Failed rows are retried; remember their messages in case Start is refused.
    const previous = entries.filter(e => e.status === "failed").map(e => [e, e.error] as const);
    try {
        busy = true;
        lastSummary = "";
        if (!notesSticky) setNotes("");
        setProgress(0);
        for (const [e] of previous) { e.status = "ready"; e.error = undefined; }
        renderList();
        refresh();
        await SageService.Start(request(true) as any);
    } catch (err: any) {
        busy = false;
        for (const [e, error] of previous) { e.status = "failed"; e.error = error; }
        setNotes("Could not start: " + (err?.message ?? err), true);
        renderList();
        refresh();
    }
}

function applyResult(r: any): Entry | undefined {
    const e = entries.find(x => x.path === r.path);
    if (!e) return undefined;
    if (r.ok) {
        e.status = "done";
        e.output = r.output;
        e.error = undefined;
    } else if (r.cancelled) {
        e.status = "ready"; // nothing happened to it; the next run does it
        e.error = undefined;
    } else {
        e.status = "failed";
        e.error = r.error;
    }
    return e;
}

Events.On("job:file", ev => {
    const e = applyResult(ev.data);
    if (e) updateRow(e);
});

Events.On("job:progress", ev => {
    const p = ev.data as any;
    const fraction = p.bytesTotal > 0 ? p.bytes / p.bytesTotal : (p.total ? p.done / p.total : 0);
    setProgress(Math.min(1, fraction));
    if (!busy || !p.current) return;
    const e = entries.find(x => x.path === p.current);
    // Only a waiting row becomes "working": a late tick must not undo a finished one.
    if (e && e.status === "ready") {
        for (const x of entries) if (x.status === "working") { x.status = "ready"; updateRow(x); }
        e.status = "working";
        updateRow(e);
        rowEls.get(e)?.scrollIntoView({block: "nearest"});
    }
    hint.textContent = `Working on file ${Math.min(p.done + 1, p.total)} of ${p.total}: ${baseName(p.current)}`;
    hint.classList.remove("warn");
});

Events.On("job:done", ev => {
    const d = ev.data as any;
    busy = false;
    for (const r of d.results ?? []) applyResult(r);
    for (const e of entries) if (e.status === "working") e.status = "ready"; // not reached (cancelled)
    lastSummary = d.summary;
    renderList();
    refresh();
});

Events.On("files:dropped", ev => addPaths(ev.data as string[]));

// ---------------------------------------------------------------- wiring

actionBtn.onclick = run;
cancelBtn.onclick = () => SageService.Cancel();
for (const el of [passphrase, confirmPass]) {
    el.addEventListener("input", () => { genArmed = false; refresh(); });
    el.addEventListener("keydown", e => { if (e.key === "Enter") run(); });
}
// These fields make Go read the recipients file and identity files, so their check
// waits until typing pauses instead of running on every keystroke.
let fieldTimer: ReturnType<typeof setTimeout> | undefined;
for (const el of [recipients, recipientsFile, identities]) {
    el.addEventListener("input", () => {
        saveSettingsSoon();
        clearTimeout(fieldTimer);
        fieldTimer = setTimeout(refresh, 200);
    });
}
for (const el of [armor, pq]) {
    el.addEventListener("change", () => { saveSettingsSoon(); refresh(); });
}

function setPassVisible(show: boolean) {
    passphrase.type = confirmPass.type = show ? "text" : "password";
    showPass.setAttribute("aria-pressed", String(show));
    showPass.title = show ? "Hide passphrase" : "Show passphrase";
    showPass.setAttribute("aria-label", showPass.title);
}
showPass.onclick = () => setPassVisible(passphrase.type === "password");

// Generate: a typed passphrase is only replaced on a second click.
let genArmed = false;
$("genPass").onclick = async () => {
    if (passphrase.value && !genArmed) {
        genArmed = true;
        setNotes("Click again to replace the passphrase you typed with a generated one.", true);
        return;
    }
    genArmed = false;
    try {
        const p = await SageService.GeneratePassphrase();
        passphrase.value = confirmPass.value = p;
        setPassVisible(true);
        setNotes("Generated a passphrase. Copy it and keep it somewhere safe: without it the files can't be decrypted.", true, true);
        refresh();
    } catch (err: any) {
        setNotes("Could not generate a passphrase: " + (err?.message ?? err), true);
    }
};
$("tabPassphrase").onclick = () => setTab("passphrase");
$("tabRecipient").onclick = () => setTab("recipient");
for (const id of ["tabPassphrase", "tabRecipient"]) {
    $(id).addEventListener("keydown", e => {
        if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
            setTab(tab === "passphrase" ? "recipient" : "passphrase");
            $(tab === "passphrase" ? "tabPassphrase" : "tabRecipient").focus();
        }
    });
}

$("addFiles").onclick = async () => addPaths(await SageService.ChooseFiles());
$("addFolder").onclick = async () => {
    const dir = await SageService.ChooseFolder();
    if (dir) addPaths([dir]);
};
$("clear").onclick = () => {
    entries = [];
    lastSummary = "";
    passphrase.value = confirmPass.value = "";
    genArmed = false;
    setPassVisible(false);
    setNotes("");
    setProgress(0, false);
    renderList();
    refresh();
};
$("inspect").onclick = async () => {
    showInfo("Inspect", await SageService.Inspect(entries.map(e => e.path)));
};
$("browseRecipients").onclick = async () => {
    const p = await SageService.ChooseRecipientsFile();
    if (p) { recipientsFile.value = p; saveSettingsSoon(); refresh(); }
};
$("addIdentity").onclick = async () => {
    for (const p of (await SageService.ChooseIdentityFiles()) ?? []) appendLine(identities, p);
    saveSettingsSoon();
    refresh();
};
$("keygen").onclick = async () => {
    try {
        const kp = await SageService.GenerateKey(pq.checked);
        appendLine(identities, kp.path);
        // age refuses to mix post-quantum and classic keys in one file, so only add
        // the new public key to 'Encrypt to' if it matches the keys already there.
        const isPQ = (line: string) => line.startsWith("age1pq1") || line.startsWith("age1tagpq1");
        const existing = recipients.value.split("\n").map(l => l.trim())
            .filter(l => l && !l.startsWith("#"));
        const mixes = existing.some(l => isPQ(l) !== isPQ(kp.publicKey));
        if (!mixes) appendLine(recipients, kp.publicKey);
        showInfo("New key pair", [
            `Saved to ${kp.path}`,
            "",
            mixes
                ? "Its public key was NOT added to 'Encrypt to': post-quantum and classic keys can't be mixed in one file. It is in the key file, on the '# public key:' line."
                : "Its public key was added to 'Encrypt to'.",
            "",
            "Keep the identity file secret and backed up: without it, files encrypted to its public key can't be decrypted.",
        ].join("\n"));
        saveSettingsSoon();
        refresh();
    } catch (err: any) {
        const msg = String(err?.message ?? err);
        if (!msg.includes("cancelled")) showInfo("Key generation failed", msg);
    }
};
$("help").onclick = () => openDialog("helpDialog");
$("helpClose").onclick = () => closeDialog("helpDialog");
$("about").onclick = async () => {
    $("aboutVersion").textContent = (await SageService.Title()).replace(/^sage\s*/, "");
    openDialog("aboutDialog");
};
$("aboutClose").onclick = () => closeDialog("aboutDialog");
$("adminChip").onclick = () => openDialog("adminDialog");
$("adminClose").onclick = () => closeDialog("adminDialog");
$("infoClose").onclick = () => closeDialog("infoDialog");
// Links open in the default browser, not inside the app window.
document.querySelectorAll<HTMLAnchorElement>("a[data-url]").forEach(a => {
    a.onclick = e => { e.preventDefault(); Browser.OpenURL(a.dataset.url!); };
});

// ---------------------------------------------------------------- start

(async () => {
    renderList();
    const st = await SageService.LoadSettings();
    recipients.value = st.recipients ? st.recipients + "\n" : "";
    recipientsFile.value = st.recipientsFile ?? "";
    identities.value = st.identities ? st.identities + "\n" : "";
    armor.checked = st.armor;
    pq.checked = st.postQuantum;
    if (st.notice) setNotes(st.notice, true, true);
    setProgress(0, false);
    setTab(st.activeTab === "recipient" ? "recipient" : "passphrase", false);
    // Running as administrator: a warning dialog at start (like About), and an "Admin"
    // pill in the toolbar that reopens it, so a later blocked drag still has an explanation.
    const adminWarning = await SageService.AdminWarning();
    if (adminWarning) {
        // The app's name in bold: "<b>sage</b> is running as administrator. ... Close <b>sage</b> and ..."
        const adminText = $("adminText");
        adminText.replaceChildren();
        for (const part of adminWarning.replace(/^Warning:\s*/, "").split(/\b(sage)\b/)) {
            if (part === "sage") {
                const b = document.createElement("strong");
                b.textContent = part;
                adminText.append(b);
            } else {
                adminText.append(part);
            }
        }
        $("adminChip").hidden = false;
        openDialog("adminDialog");
    }
    await addPaths(await SageService.LaunchPaths());
})();
