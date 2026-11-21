// Builds dist/index.html with every project list encrypted under its own password.
// Usage: ACCESS='{"admin-pass":"*","client-pass":["melvora-bd"]}' node build.js
const fs = require("fs");
const { pbkdf2Sync, randomBytes, createCipheriv } = require("crypto");

const access = JSON.parse(process.env.ACCESS || "{}");
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
