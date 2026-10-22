# ADR 0001: Security bulletins in the action

- Status: Accepted
- Date: 2026-10-22

## Context

DeepSweep publishes security bulletins at https://deepsweep.ai/advisories, with a
machine-readable copy at https://deepsweep.ai/advisories/v1/feed.json and its JSON Schema
at https://deepsweep.ai/advisories/v1/schema.json. Version 1 only gains fields. A reader
ignores fields and enum values it does not know.

A team that runs this action on every pull request is a team that should hear about a
critical flaw in something its repository uses. Until now the action made no network
request at all, and the README said so.

## Decision

A step named `Security bulletins` runs after the review, including after a failed
`fail-below-score` gate, and never fails the job.

1. Input `bulletins`, default `true`. Any other value skips the step and makes no request.
2. The step looks for ecosystems the action knows how to recognise, at the top of `path`
   and one folder down, skipping hidden, dependency and build folders. PHP is the only one
   today: `composer.json`, `.php-version`, or a Dockerfile built `FROM` a `php` image. If
   none is found, no request is made.
3. One GET of the feed: 5 second timeout covering the body, no redirects, status 200,
   `content-type` containing `application/json`, at most 1 MB, parses, `version === 1`.
   Anything else is treated as no feed.
4. An entry is shown when `severity` is exactly `critical`, `published_at` is less than
   30 days old, it has a title and an https `url`, and one of its `affected[].ecosystem`
   values names an ecosystem found in step 2. At most three are shown.
5. Each shown entry adds one block to `$GITHUB_STEP_SUMMARY` and prints one `::notice`
   annotation, both carrying the title, the first entry of `actions[]` as the fix, and
   the entry `url`. Feed text is escaped so it cannot start another workflow command.
6. Every failure prints nothing about bulletins. The script catches everything and exits
   0. The step also has `continue-on-error: true` and `|| true`.

No events are sent. The action reports nothing anywhere today, and this does not change
that.

The code is `bulletins/bulletins.mjs`, Node built-ins only, on the Node the action
already installs. Tests are `tests/bulletins.test.mjs`, run with
`node --test tests/*.test.mjs`. They cover the fetch guards against a local HTTP server,
the 30-day window, ecosystem matching on fixture repositories, the exact summary and
annotation text, the input turned off, and failure paths.

## Alternatives rejected

- A bundled copy of the feed in each tag. Users pin `@v1` and get new code only when the
  tag moves, so a bundled copy would be stale for exactly the bulletins that matter.
- Showing every critical bulletin to every repository. A notice that does not apply
  teaches people to ignore the next one.
- Failing or warning the job on a match. The action reviews agent configuration. A
  runtime flaw elsewhere in the repository is something to know about, and it should
  not block a merge.
- Reading installed versions to decide whether a repository is already patched. Version
  pins in a repository do not say what a server runs, and a wrong "you are safe" is worse
  than a reminder.

## Consequences

- The README now says the action makes one request, for a public file, carrying nothing
  about the repository, and that `bulletins: false` stops it.
- A bulletin for an ecosystem with no matcher here is silent until a matcher is added.
- A new bulletin reaches users within about an hour of publication (the file's cache
  lifetime), with no new release of the action.

## Rollback

Set `bulletins: false` in a workflow, or remove the step and the input in a release.
