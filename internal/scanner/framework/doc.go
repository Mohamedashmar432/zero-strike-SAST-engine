// Package framework detects framework-level security misconfigurations
// (insecure defaults, debug mode exposure, permissive CORS) by reading
// config files directly — no tree-sitter/IR involved, same shape as
// internal/scanner/secrets.
//
// # Where a new check belongs
//
// A setting that is source code belongs in a YAML SAST rule under
// internal/rules/data: Python settings modules, Express app.use(...) and
// session({...}) calls, jsonwebtoken options, Flask app.run(debug=True).
// Those have an AST, taint, per-file caching and once_per_file, and they
// report as Kind "sast".
//
// A file that is not source belongs here: Dockerfile, docker-compose, Spring
// .properties/.yml, .env, web.config, php.ini, GitHub workflows, and
// templates whose verdict depends on a sibling file (ZS-CFG-020 reads the
// component .ts next to the .html, which the per-file SAST caches, keyed on
// one file's content, cannot track). This package is pure Go and needs no
// CGo. Findings are Kind "config" and carry Config.Framework.
//
// Do not move an existing rule between the two to make coverage look
// different: the portal and customer CI gates read Kind, RuleID and
// fingerprints, and an accepted exemption is keyed on them. Framework
// coverage is made visible instead by Stats.ByFramework, a count of config
// findings by Config.Framework.
//
// # Checks
//
// Each check is {ruleID, accepts(path), detect(path, data)} in the checks
// list in scanner.go. A check that is not in that list never runs, so
// registering it is part of writing it. detect returns findings built with
// findings.BuildConfigFinding; Scan then stamps the fingerprint from
// findings.ConfigFingerprint(ruleID, root-relative file, Config.Key), so
// Config.Key must name the setting, not a line number, and a finding keeps
// its identity when the file is edited above it.
//
// # Tiers
//
// A check whose finding is defence in depth with no exploit path of its own
// sets Finding.Tier = core.TierHardening and is left out of default output
// (counted in Stats.TierExcluded). Missing helmet, a Dockerfile that runs as
// root, an unpinned base image and a remote ADD are hardening. A literal
// credential, an exposed debug console or raw HTML with the sanitizer off is
// not, and ships in default output.
//
// # Comments
//
// Substring tests on source text must run on stripJSComments(data), not the
// raw bytes, or a commented-out require("helmet") counts as the real thing.
package framework
