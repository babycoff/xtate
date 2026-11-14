#!/usr/bin/env node
/*
 * Regression test for browser-side port validation.
 *
 * The GUI sends ports as an integer array, so a CLI-style prefix has to be
 * interpreted before the request is built.  Prefixes that contradict the
 * selected scan engine must fail loudly instead of being silently dropped.
 */
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const assert = require("assert");

const htmlPath = path.resolve(__dirname, "../../web/gui.html");
const html = fs.readFileSync(htmlPath, "utf8");
const match = html.match(/<script>\r?\n([\s\S]*?)\r?\n<\/script>/);
if (!match) throw new Error("GUI script not found in web/gui.html");
let script = match[1];
script = script.replace(
  /\ninit\(\);\s*$/,
  "\nglobalThis.__guiTest = { portInputError, expandPorts, formInputError, state };\n",
);

const fields = {
  rate: { value: "100" },
  timeout: { value: "300" },
  ports: { value: "80,443" },
};
const context = {
  console,
  URLSearchParams,
  location: { search: "", hash: "" },
  localStorage: { getItem: () => null, setItem: () => {} },
  document: {
    documentElement: { lang: "en" },
    body: {},
    getElementById: (id) => fields[id] || null,
    querySelectorAll: () => [],
  },
};
vm.createContext(context);
vm.runInContext(script, context);
const gui = context.__guiTest;

gui.state.scan = "tcp-syn";
gui.state.modules = [{ name: "tcp-syn", kind: "scan", probe_type: "none" }];
assert.strictEqual(gui.portInputError("80,443"), "");
assert.strictEqual(gui.portInputError("80-90"), "");
assert.strictEqual(gui.portInputError("t:80"), "");
assert.ok(gui.portInputError("u:53"), "UDP prefix must be rejected for TCP");
assert.ok(gui.portInputError("s:38412"), "SCTP prefix must be rejected for TCP");
assert.ok(gui.portInputError("1-70000"), "out-of-range port must be rejected");
assert.ok(gui.portInputError("not-a-port"), "garbage must be rejected");
assert.deepStrictEqual(Array.from(gui.expandPorts("80,80-82")), [80, 81, 82]);

gui.state.scan = "udp";
assert.strictEqual(gui.portInputError("u:53"), "");
assert.deepStrictEqual(Array.from(gui.expandPorts("u:53")), [53]);

gui.state.scan = "sctp-init";
assert.strictEqual(gui.portInputError("s:38412"), "");
assert.deepStrictEqual(Array.from(gui.expandPorts("s:38412")), [38412]);

gui.state.scan = "tcp-syn";
assert.strictEqual(gui.formInputError(), "");
fields.rate.value = "0";
assert.ok(gui.formInputError(), "zero rate must be rejected");
fields.rate.value = "10001";
assert.ok(gui.formInputError(), "rate above 10000 must be rejected");
fields.rate.value = "100";
fields.timeout.value = "1.5";
assert.ok(gui.formInputError(), "fractional timeout must be rejected");
fields.timeout.value = "300";
fields.ports.value = "1-5000";
assert.ok(gui.formInputError(), "more than 4096 ports must be rejected");

console.log("GUI input validation: PASS");
