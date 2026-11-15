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
let tab: "passphrase" | "recipient" = "passphrase";
let busy = false;
let lastSummary = "";   // "Finished: 2 OK, 1 failed." after a run
let notes = "";         // notes from adding files, settings, etc.
let notesWarn = false;

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

function renderList() {
    list.replaceChildren();
    // After a run the second column shows each file's result instead of its folder.
    $("colSecond").textContent = entries.some(e => e.status === "done" || e.status === "failed") ? "Result" : "Folder";
    if (entries.length === 0) {
        const empty = document.createElement("div");
        empty.className = "empty";
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
    for (const e of entries) {
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
        sub.textContent = e.status === "done" ? `\u2192 ${baseName(e.output ?? "")}`
            : e.status === "failed" ? e.error ?? "Failed" : folderOf(e.path);
        if (e.status === "done" || e.status === "failed") sub.title = e.status === "done" ? e.output ?? "" : e.error ?? "";

        const size = document.createElement("span");
        size.className = "num cell-sub";
        size.textContent = formatSize(e.size);

        const btn = document.createElement("button");
        btn.className = "row-btn";
        btn.type = "button";
        if (e.status === "done") {
            btn.append(icon("folder-open"));
            btn.title = "Show in folder";
            btn.setAttribute("aria-label", `Show ${baseName(e.output ?? "")} in its folder`);
            btn.onclick = () => SageService.OpenFolder(e.output ?? "").catch(err => setNotes(String(err?.message ?? err), true));
        } else {
            btn.append(icon("x"));
            btn.title = "Remove from the list";
            btn.setAttribute("aria-label", `Remove ${baseName(e.path)}`);
            btn.disabled = busy;
            btn.onclick = () => {
                entries = entries.filter(x => x !== e);
                lastSummary = "";
                renderList();
                refresh();
            };
        }
        row.append(name, sub, size, btn);
        list.append(row);
    }
}

function setNotes(text: string, warn = false) {
    notes = text;
    notesWarn = warn;
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
    hint.textContent = st.hint;
    hint.classList.toggle("warn", st.warn);
}

function setTab(t: "passphrase" | "recipient", save = true) {
    tab = t;
    for (const [id, on] of [["tabPassphrase", t === "passphrase"], ["tabRecipient", t === "recipient"]] as const) {
        $(id).classList.toggle("active", on);
        $(id).setAttribute("aria-selected", String(on));
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

async function addPaths(paths: string[] | null) {
    if (!paths || paths.length === 0) return;
    if (busy) {
        hint.textContent = "Busy: wait for the current job to finish, or press Cancel.";
        hint.classList.add("warn");
        return;
    }
    const res = await SageService.AddPaths(pending(), paths);
    if (busy) return; // a job started while this was in flight
    const resFiles = res.files ?? []; // Go sends an empty list as null
    const sizes = res.sizes ?? {};
    // New files start a new batch: finished rows from the last run go away.
    const old = new Map(entries.filter(e => e.status !== "done").map(e => [e.path, e]));
    entries = resFiles.map(p => {
        const prev = old.get(p);
        return prev ?? {path: p, size: sizes[p], status: "ready" as RowStatus};
    });
    for (const e of entries) if (e.size === undefined) e.size = sizes[e.path];
    lastSummary = "";
    setProgress(0, false);
    renderList();
    setNotes(res.note, res.note.startsWith("No files") || res.note.includes("Not added"));
    refresh();
    if (tab === "passphrase" && entries.length) passphrase.focus();
}

function appendLine(area: HTMLTextAreaElement, line: string) {
    const v = area.value;
    area.value = (v && !v.endsWith("\n") ? v + "\n" : v) + line + "\n";
}

// ---------------------------------------------------------------- dialogs

function showInfo(title: string, text: string) {
    $("infoTitle").textContent = title;
    $("infoText").textContent = text;
    $("infoDialog").hidden = false;
    $("infoClose").focus();
}

// ---------------------------------------------------------------- the job

async function run() {
    if (busy || actionBtn.disabled) return;
    try {
        busy = true;
        lastSummary = "";
        setNotes("");
        setProgress(0);
        for (const e of entries) if (e.status === "failed") { e.status = "ready"; e.error = undefined; }
        renderList();
        refresh();
        await SageService.Start(request(true) as any);
    } catch (err: any) {
        busy = false;
        setNotes("Could not start: " + (err?.message ?? err), true);
        renderList();
        refresh();
    }
}

function applyResult(r: any) {
    const e = entries.find(x => x.path === r.path);
    if (!e) return;
    if (r.ok) {
        e.status = "done";
        e.output = r.output;
        e.error = undefined;
    } else {
        e.status = "failed";
        e.error = r.error;
    }
}

Events.On("job:file", ev => {
    applyResult(ev.data);
    renderList();
});

Events.On("job:progress", ev => {
    const p = ev.data as any;
    const fraction = p.bytesTotal > 0 ? p.bytes / p.bytesTotal : (p.total ? p.done / p.total : 0);
    setProgress(Math.min(1, fraction));
    if (busy && p.current) {
        const e = entries.find(x => x.path === p.current);
        if (e && e.status !== "working") {
            for (const x of entries) if (x.status === "working") x.status = "ready";
            e.status = "working";
            renderList();
        }
        hint.textContent = `Working on file ${Math.min(p.done + 1, p.total)} of ${p.total}: ${baseName(p.current)}`;
        hint.classList.remove("warn");
    }
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
    el.addEventListener("input", refresh);
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
$("genPass").onclick = async () => {
    try {
        const p = await SageService.GeneratePassphrase();
        passphrase.value = confirmPass.value = p;
        setPassVisible(true);
        setNotes("Generated a passphrase. Copy it and keep it somewhere safe: without it the files can't be decrypted.", true);
        refresh();
    } catch (err: any) {
        setNotes("Could not generate a passphrase: " + (err?.message ?? err), true);
    }
};
$("tabPassphrase").onclick = () => setTab("passphrase");
$("tabRecipient").onclick = () => setTab("recipient");

$("addFiles").onclick = async () => addPaths(await SageService.ChooseFiles());
$("addFolder").onclick = async () => {
    const dir = await SageService.ChooseFolder();
    if (dir) addPaths([dir]);
};
$("clear").onclick = () => {
    entries = [];
    lastSummary = "";
    passphrase.value = confirmPass.value = "";
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
$("help").onclick = () => { $("helpDialog").hidden = false; };
$("helpClose").onclick = () => { $("helpDialog").hidden = true; };
$("about").onclick = async () => {
    $("aboutVersion").textContent = (await SageService.Title()).replace(/^sage\s*/, "");
    $("aboutDialog").hidden = false;
};
$("aboutClose").onclick = () => { $("aboutDialog").hidden = true; };
$("adminChip").onclick = () => { $("adminDialog").hidden = false; $("adminClose").focus(); };
$("adminClose").onclick = () => { $("adminDialog").hidden = true; };
$("infoClose").onclick = () => { $("infoDialog").hidden = true; };
// Esc closes whichever dialog is open.
document.addEventListener("keydown", e => {
    if (e.key !== "Escape") return;
    for (const id of ["infoDialog", "helpDialog", "aboutDialog", "adminDialog"]) $(id).hidden = true;
});
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
    if (st.notice) setNotes(st.notice, true);
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
        $("adminDialog").hidden = false;
        $("adminClose").focus();
    }
    addPaths(await SageService.LaunchPaths());
})();
