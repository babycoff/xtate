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
  "\nglobalThis.__guiTest = { serializeSubprobeArgs, quoteSubprobeValue, collectProbeArgs, subprobeCandidates, probeCandidatesForScan, scanInfo, probeTypeLabel, state };\n",
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
  { kind: "scan", name: "zbanner", probe_type: "tcp" },
  {
    kind: "scan",
    name: "tcp-state",
    probe_type: "state",
    required_state_transports: ["tcp"],
    required_capabilities: [],
  },
  { kind: "scan", name: "udp", probe_type: "udp" },
  {
    kind: "scan",
    name: "quic-state",
    probe_type: "state",
    required_state_transports: ["quic"],
    required_capabilities: [],
  },
  { kind: "scan", name: "icmp-echo", probe_type: "none" },
  {
    kind: "probe",
    name: "tls-state",
    probe_type: "state",
    state_transports: ["tcp"],
    capabilities: [],
    parameters: [{ name: "subprobe", type: "arg" }],
  },
  {
    kind: "probe",
    name: "http-state",
    probe_type: "state",
    state_transports: ["tcp"],
    capabilities: [],
    parameters: [{ name: "all-banner", type: "flag" }],
  },
  {
    kind: "probe",
    name: "close-state",
    probe_type: "state",
    state_transports: ["tcp", "quic"],
    capabilities: [],
    parameters: [],
  },
  {
    kind: "probe",
    name: "http3-state",
    probe_type: "state",
    state_transports: ["quic"],
    capabilities: ["stream-data"],
    parameters: [],
  },
  {
    kind: "probe",
    name: "dual-state",
    probe_type: "state",
    state_transports: ["tcp", "quic"],
    capabilities: ["stream-data"],
    parameters: [],
  },
  { kind: "probe", name: "http", probe_type: "tcp", parameters: [] },
  { kind: "probe", name: "dns", probe_type: "udp", parameters: [] },
];

gui.state.probes = gui.state.modules.filter((m) => m.kind === "probe");

assert.deepStrictEqual(
  gui.subprobeCandidates().map((m) => m.name),
  ["http-state", "close-state", "dual-state"],
  "only TCP state probes are valid TLS subprobes",
);
assert.deepStrictEqual(
  gui.probeCandidatesForScan("quic-state").map((m) => m.name).sort(),
  ["close-state", "dual-state", "http3-state"],
  "quic-state requires QUIC-capable state probes",
);
assert.deepStrictEqual(
  gui.probeCandidatesForScan("tcp-state").map((m) => m.name),
  ["tls-state", "http-state", "close-state", "dual-state"],
  "tcp-state offers TCP-capable state probes only",
);
assert.strictEqual(gui.scanInfo("zbanner").probe, "tcp");
assert.strictEqual(gui.scanInfo("tcp-state").probe, "state");
assert.deepStrictEqual(gui.scanInfo("tcp-state").transports, ["tcp"]);
assert.deepStrictEqual(gui.scanInfo("quic-state").transports, ["quic"]);
assert.deepStrictEqual(gui.scanInfo("quic-state").capabilities, []);
assert.strictEqual(gui.scanInfo("udp").probe, "udp");
assert.strictEqual(gui.scanInfo("icmp-echo").probe, null);
assert.strictEqual(gui.scanInfo("icmp-echo").ports, false);
assert.strictEqual(gui.scanInfo("tcp-state").ports, true);
assert.strictEqual(
  gui.probeTypeLabel({ kind: "scan", probe_type: "state", required_state_transports: ["tcp"] }),
  "TCP · stateful",
);
assert.strictEqual(
  gui.probeTypeLabel({ kind: "scan", probe_type: "state", required_state_transports: ["quic"] }),
  "QUIC · stateful",
);
assert.strictEqual(
  gui.probeTypeLabel({ kind: "probe", probe_type: "state", state_transports: ["quic"] }),
  "QUIC · stateful",
);
assert.strictEqual(
  gui.probeTypeLabel({ kind: "probe", probe_type: "state", state_transports: ["tcp", "quic"] }),
  "TCP/QUIC · stateful",
);

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
