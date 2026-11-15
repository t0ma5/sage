// The window's behaviour. All decisions (is the button ready, what is missing)
// come from Go's SageService.Status, so they live in one tested place.

import "./style.css";
import {Browser, Events} from "@wailsio/runtime";
import {SageService} from "../bindings/sage";

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

const box = $<HTMLDivElement>("box");
const badge = $("badge");
const hint = $("hint");
const actionBtn = $<HTMLButtonElement>("action");
const cancelBtn = $<HTMLButtonElement>("cancel");
const fill = $("progressFill");
const passphrase = $<HTMLInputElement>("passphrase");
const confirmPass = $<HTMLInputElement>("confirm");
const recipients = $<HTMLTextAreaElement>("recipients");
const recipientsFile = $<HTMLInputElement>("recipientsFile");
const identities = $<HTMLTextAreaElement>("identities");
const armor = $<HTMLInputElement>("armor");
const writeLog = $<HTMLInputElement>("writeLog");
const pq = $<HTMLInputElement>("pq");

let files: string[] = [];
let mode = "";
let tab: "passphrase" | "recipient" = "passphrase";
let busy = false;
let lastSummary = "";

// ---------------------------------------------------------------- the box

// Each line of the box is its own block: its own leading spaces (real text, so
// nesting shows and survives copying), a bullet, and the text; wrapped text is
// indented under the first word. The bullet is left out of copied text.
const BULLET = "• ";
function addLines(text: string) {
    for (const raw of text.split("\n")) {
        const div = document.createElement("div");
        div.className = "ln";
        const body = raw.replace(/^[ \t]+/, "").trimEnd();
        if (!body) {
            div.append(document.createElement("br")); // an empty line, also when copied
        } else {
            const indent = raw.slice(0, raw.length - raw.replace(/^[ \t]+/, "").length).replace(/\t/g, "    ");
            const hang = indent.length + BULLET.length;
            div.style.paddingLeft = `${hang}ch`;
            div.style.textIndent = `-${hang}ch`;
            const bullet = document.createElement("span");
            bullet.className = "bullet";
            bullet.setAttribute("aria-hidden", "true");
            bullet.textContent = BULLET;
            if (indent) div.append(indent);
            div.append(bullet, body);
        }
        box.append(div);
    }
}

// Copying from the box gives the lines with their indentation, without bullets.
box.addEventListener("copy", e => {
    const text = document.getSelection()?.toString() ?? "";
    if (!text) return; // nothing selected: leave the clipboard alone
    e.clipboardData?.setData("text/plain", text.replace(/^([ \t]*)• /gm, "$1"));
    e.preventDefault();
});

function setBox(text: string) {
    box.replaceChildren();
    if (text) addLines(text);
    box.scrollTop = box.scrollHeight;
}

function appendBox(line: string) {
    addLines(line);
    box.scrollTop = box.scrollHeight;
}

// A one-time settings notice (e.g. a damaged settings file) stays part of the
// welcome text, so Clear doesn't make it disappear (page does the same).
let settingsNotice = "";

function showWelcome() {
    setBox([
        "Drop files or folders here.",
        "",
        "  .age files are decrypted, everything else is encrypted.",
        "  Output goes next to each file; existing files are never overwritten.",
        "  Encryption by the official age library, built in.",
        ...(settingsNotice ? ["", settingsNotice] : []),
    ].join("\n"));
    box.scrollTop = 0; // the welcome text starts at the top
}

function showFiles(note = "") {
    const lines = files.map(f => {
        const i = Math.max(f.lastIndexOf("\\"), f.lastIndexOf("/"));
        let dir = f.slice(0, i);
        if (/^[A-Za-z]:$/.test(dir)) dir += "\\"; // a drive root is "F:\" ("F:" alone means the current folder there)
        return `${f.slice(i + 1)}    (${dir})`;
    });
    setBox(lines.join("\n") + (note ? "\n" + note : ""));
    setProgress(0, false);
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
    return {
        files, mode, tab,
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
    // Badge and decrypt-only fields.
    badge.hidden = files.length === 0;
    badge.className = "badge " + mode;
    badge.textContent = `${mode.toUpperCase()} · ${files.length}`;
    confirmPass.hidden = mode === "decrypt";
    armor.disabled = busy || mode === "decrypt";
    $<HTMLButtonElement>("inspect").disabled = busy || !files.some(f => f.toLowerCase().endsWith(".age"));

    for (const id of ["addFiles", "addFolder", "clear", "tabPassphrase", "tabRecipient", "help",
        "browseRecipients", "addIdentity", "keygen"]) {
        $<HTMLButtonElement>(id).disabled = busy;
    }
    for (const el of [passphrase, confirmPass, recipients, recipientsFile, identities, pq, writeLog,
        $<HTMLInputElement>("showPass")]) {
        el.disabled = busy;
    }
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
    hint.textContent = lastSummary ? `${lastSummary} ${st.hint}` : st.hint;
    hint.classList.toggle("warn", st.warn);
}

function setTab(t: "passphrase" | "recipient", save = true) {
    tab = t;
    $("tabPassphrase").classList.toggle("active", t === "passphrase");
    $("tabRecipient").classList.toggle("active", t === "recipient");
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
            writeLog: writeLog.checked,
            postQuantum: pq.checked,
        } as any).catch(err => {
            if (!settingsErrorShown) {
                settingsErrorShown = true;
                appendBox(String(err?.message ?? err));
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
    const res = await SageService.AddPaths(files, paths);
    if (busy) return; // a job started while this was in flight; it owns the box now
    const resFiles = res.files ?? []; // Go sends an empty list as null
    if (resFiles.length === files.length && res.note.startsWith("No files")) {
        appendBox(res.note); // keep what is shown, just add the note
        return;
    }
    files = resFiles;
    mode = res.mode;
    lastSummary = "";
    showFiles(res.note);
    refresh();
    if (tab === "passphrase") passphrase.focus();
}

function appendLine(area: HTMLTextAreaElement, line: string) {
    const v = area.value;
    area.value = (v && !v.endsWith("\n") ? v + "\n" : v) + line + "\n";
}

// ---------------------------------------------------------------- the job

async function run() {
    if (busy || actionBtn.disabled) return;
    try {
        busy = true;
        // Screen readers: hold the log's announcements until the job ends, then read the
        // result, instead of reading every line of every file as it's written.
        box.setAttribute("aria-busy", "true");
        lastSummary = "";
        setProgress(0);
        refresh();
        setBox("");
        await SageService.Start(request(true) as any);
    } catch (err: any) {
        busy = false;
        box.removeAttribute("aria-busy");
        appendBox("Could not start: " + (err?.message ?? err));
        refresh();
    }
}

Events.On("job:log", ev => appendBox(ev.data as string));

Events.On("job:progress", ev => {
    const p = ev.data as any;
    const fraction = p.bytesTotal > 0 ? p.bytes / p.bytesTotal : (p.total ? p.done / p.total : 0);
    setProgress(Math.min(1, fraction));
    if (busy && p.current) {
        hint.textContent = `Working on file ${Math.min(p.done + 1, p.total)} of ${p.total}: ${p.current}`;
        hint.classList.remove("warn");
    }
});

Events.On("job:done", ev => {
    const d = ev.data as any;
    busy = false;
    box.removeAttribute("aria-busy");
    files = d.remaining ?? [];
    mode = files.length === 0 ? "" : (files.every(f => f.toLowerCase().endsWith(".age")) ? "decrypt" : "encrypt");
    lastSummary = d.summary;
    if (files.length) appendBox(`${files.length} file(s) not done are still in the list.`);
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
for (const el of [armor, writeLog, pq]) {
    el.addEventListener("change", () => { saveSettingsSoon(); refresh(); });
}
$<HTMLInputElement>("showPass").onchange = e => {
    const type = (e.target as HTMLInputElement).checked ? "text" : "password";
    passphrase.type = confirmPass.type = type;
};
$("tabPassphrase").onclick = () => setTab("passphrase");
$("tabRecipient").onclick = () => setTab("recipient");

$("addFiles").onclick = async () => addPaths(await SageService.ChooseFiles());
$("addFolder").onclick = async () => {
    const dir = await SageService.ChooseFolder();
    if (dir) addPaths([dir]);
};
$("clear").onclick = () => {
    files = [];
    mode = "";
    lastSummary = "";
    passphrase.value = confirmPass.value = "";
    showWelcome();
    setProgress(0, false);
    refresh();
};
$("inspect").onclick = async () => {
    setBox(await SageService.Inspect(files));
    appendBox(`\n${files.length} file(s) still in the list.`);
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
        setBox([
            `New identity saved to ${kp.path}`,
            mixes
                ? "Its public key was NOT added to 'Encrypt to': post-quantum and classic keys can't be mixed in one file. It is in the key file, on the '# public key:' line."
                : "Its public key was added to 'Encrypt to'.",
            "Keep the identity file secret and backed up.",
        ].join("\n"));
        saveSettingsSoon();
        refresh();
    } catch (err: any) {
        const msg = String(err?.message ?? err);
        if (!msg.includes("cancelled")) setBox("Key generation failed: " + msg);
    }
};
$("help").onclick = () => { $("helpDialog").hidden = false; };
$("helpClose").onclick = () => { $("helpDialog").hidden = true; };
$("about").onclick = async () => {
    $("aboutVersion").textContent = (await SageService.Title()).replace(/^sage\s*/, "");
    $("aboutDialog").hidden = false;
};
$("aboutClose").onclick = () => { $("aboutDialog").hidden = true; };
// Links open in the default browser, not inside the app window.
document.querySelectorAll<HTMLAnchorElement>("a[data-url]").forEach(a => {
    a.onclick = e => { e.preventDefault(); Browser.OpenURL(a.dataset.url!); };
});

// ---------------------------------------------------------------- start

(async () => {
    const st = await SageService.LoadSettings();
    recipients.value = st.recipients ? st.recipients + "\n" : "";
    recipientsFile.value = st.recipientsFile ?? "";
    identities.value = st.identities ? st.identities + "\n" : "";
    armor.checked = st.armor;
    writeLog.checked = st.writeLog;
    pq.checked = st.postQuantum;
    settingsNotice = st.notice ?? "";
    showWelcome();
    setProgress(0, false);
    setTab(st.activeTab === "recipient" ? "recipient" : "passphrase", false);
    // Running as administrator: a permanent line above the box, so file lists and
    // job logs can't push it out of view.
    const adminWarning = await SageService.AdminWarning();
    const banner = $("adminBanner");
    banner.textContent = adminWarning;
    banner.hidden = !adminWarning;
    addPaths(await SageService.LaunchPaths());
})();
