#!/usr/bin/env node
/*
 * Regression test for the GUI's nested-probe argument serializer.
 *
 * The browser serializes a subprobe's flags/values into one command-line
 * string.  The C side then parses that string with safe_str_to_args(), so the
 * quoting must round-trip.  This test extracts the real functions from
 * web/gui.html and runs them with a minimal DOM stub; it does not duplicate the
 * serializer logic.
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
  "\nglobalThis.__guiTest = { serializeSubprobeArgs, quoteSubprobeValue, collectProbeArgs, state };\n",
);

const probeEl = { value: "tls-state" };
const subprobeEl = { value: "http-state" };
const argElements = {
  probe: [
    { dataset: { argName: "sni", argType: "arg" }, value: "example.test" },
  ],
  subprobe: [
    { dataset: { argName: "all-banner", argType: "flag" }, checked: true, value: "" },
    { dataset: { argName: "max-body", argType: "arg" }, value: "4096" },
    { dataset: { argName: "filter", argType: "arg" }, value: "a b" },
    { dataset: { argName: "quoted", argType: "arg" }, value: 'a"b' },
    { dataset: { argName: "empty", argType: "arg" }, value: "" },
    { dataset: { argName: "off", argType: "flag" }, checked: false, value: "" },
  ],
};

const context = {
  console,
  URLSearchParams,
  location: { search: "", hash: "" },
  localStorage: { getItem: () => null, setItem: () => {} },
  document: {
    documentElement: { lang: "en" },
    body: {},
    getElementById: (id) =>
      id === "probe" ? probeEl : id === "subprobe" ? subprobeEl : null,
    querySelectorAll: (selector) => {
      const kind = selector.match(/data-arg-kind="([^"]+)"/);
      return kind && argElements[kind[1]] ? argElements[kind[1]] : [];
    },
  },
};
vm.createContext(context);
vm.runInContext(script, context);
const gui = context.__guiTest;

gui.state.modules = [
  {
    kind: "probe",
    name: "tls-state",
    probe_type: "state",
    parameters: [{ name: "subprobe", type: "arg" }],
  },
  {
    kind: "probe",
    name: "http-state",
    probe_type: "state",
    parameters: [{ name: "all-banner", type: "flag" }],
  },
];

const args = JSON.parse(JSON.stringify(gui.collectProbeArgs()));
assert.deepStrictEqual(args, {
  sni: "example.test",
  subprobe: "http-state",
  "subprobe-arg": "--all-banner --max-body=4096 --filter='a b' --quoted=a\"b",
});
assert.strictEqual(gui.quoteSubprobeValue("plain"), "plain");
assert.strictEqual(gui.quoteSubprobeValue("a b"), "'a b'");
assert.strictEqual(gui.quoteSubprobeValue("a'b"), "'a\\'b'");
console.log("nested-probe JS serialization: PASS");
