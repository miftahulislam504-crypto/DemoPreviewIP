// Builds dist/index.html with every project list encrypted under its own password.
// Usage: ACCESS='{"admin-pass":"*","client-pass":["melvora-bd"]}' node build.js
const fs = require("fs");
const { pbkdf2Sync, randomBytes, createCipheriv } = require("crypto");

// Phone keyboards sometimes put a line break or tab inside a quoted password/id, which breaks JSON.
// A password field is single-line, so such characters could never be typed anyway: drop them inside strings.
function stripControlInStrings(src) {
  let out = "", inStr = false, esc = false;
  for (const ch of src) {
    if (inStr && ch < " ") continue;
    out += ch;
    if (esc) esc = false;
    else if (inStr && ch === "\\") esc = true;
    else if (ch === '"') inStr = !inStr;
  }
  return out;
}

let access;
try {
  access = JSON.parse(stripControlInStrings(process.env.ACCESS || "{}"));
  if (!access || typeof access !== "object" || Array.isArray(access)) throw new Error("it must be an object like {\"password\": ...}");
  for (const [pw, ids] of Object.entries(access))
    if (ids !== "*" && !(Array.isArray(ids) && ids.every(x => typeof x === "string")))
      throw new Error("the value for one password must be \"*\" or a list of project ids in [ ]");
} catch (e) {
  console.error("ACCESS secret is not valid: " + e.message);
  console.error("Fix it on one line with straight quotes (\"), commas between items, no comma after the last one.");
  console.error('Example: {"admin-pass":"*","client-a":["ez_menu","ez_erp"]}');
  process.exit(1);
}
if (!Object.keys(access).length) { console.error("ACCESS secret is empty"); process.exit(1); }

const all = JSON.parse(fs.readFileSync("projects.json", "utf8"))
  .map(o => [o.id, o.name, o.description || "", o.stack || "", o.url, o.year || ""]);

function seal(pw, data) {
  const salt = randomBytes(16), iv = randomBytes(12);
  const key = pbkdf2Sync(pw, salt, 200000, 32, "sha256");
  const c = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(JSON.stringify(data), "utf8"), c.final()]);
  return { s: salt.toString("base64"), i: iv.toString("base64"), d: Buffer.concat([ct, c.getAuthTag()]).toString("base64") };
}

const vault = Object.entries(access).map(([pw, ids]) => {
  if (ids === "*") return seal(pw, all);
  const unknown = ids.filter(id => !all.some(p => p[0] === id));
  if (unknown.length) { console.error("Unknown project id: " + unknown.join(", ")); process.exit(1); }
  return seal(pw, all.filter(p => ids.includes(p[0])));
});

fs.mkdirSync("dist", { recursive: true });
fs.cpSync("public", "dist", { recursive: true }); // PWA manifest, service worker, icons
fs.writeFileSync("dist/index.html", fs.readFileSync("template.html", "utf8").replace("__VAULT__", () => JSON.stringify(vault)));
console.log("Built dist/index.html with " + vault.length + " password(s)");
