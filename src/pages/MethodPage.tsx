import { Link } from 'react-router-dom'
import { STAGES } from '@/data/clouds'
import { curriculumStats } from '@/data/curriculum'

export function MethodPage() {
  const stats = curriculumStats()
  return (
    <div className="shell" style={{ paddingBlock: '2.5rem 4rem' }}>
      <header className="page-head">
        <h1>How the method works</h1>
        <p>
          Most cloud security material is either documentation restated or a list
          of misconfiguration checkboxes. Neither teaches you how an attacker
          thinks. This site uses one structure, applied to every topic, so the
          knowledge transfers between clouds.
        </p>
      </header>

      <div className="prose">
        <h2>The four beats</h2>
        <p>
          Every topic is taught the same way, in the same order, and always
          completely. You are not told a concept is useful and left to work out
          how; you are shown what it is, how it is broken, how you would notice
          the break, and what you change.
        </p>
        <ul>
          <li>
            <strong>Concept.</strong> The mechanism, why the platform built it
            that way, and a mental model you can reuse. Includes the
            misconceptions that catch people out — including experienced ones.
          </li>
          <li>
            <strong>Attack.</strong> Concrete techniques with commands that run,
            ordered quiet to loud, and the blast radius of each. Where a
            technique has been seen in public write-ups, that is cited.
          </li>
          <li>
            <strong>Detect.</strong> The signal in the audit log, as a query you
            can paste into CloudWatch Logs Insights, Azure Monitor or Cloud
            Logging. Plus the guardrails that shrink the blast radius.
          </li>
          <li>
            <strong>Fix.</strong> The remediation, ordered by priority, with the
            policy or configuration that closes the gap.
          </li>
        </ul>

        <h2>Why the order matters</h2>
        <p>
          Cloud privilege escalation is a graph problem, not a checklist problem.
          The useful insight is rarely "this permission is dangerous" — it is "this
          permission lets me become someone else". Teaching concept before attack
          gives you the vocabulary to see that. Teaching detection before
          remediation stops you from writing controls that do not map to any
          signal you can actually see.
        </p>
        <blockquote>
          <p>
            The stages are sequenced so that each one is buildable on the last.
            You cannot reason about an attack path through a cloud you do not
            understand how identity works in.
          </p>
        </blockquote>

        <h2>The stages</h2>
        <div className="stage-strip">
          {STAGES.map((s) => (
            <div className="stage-row" key={s.id}>
              <div className="stage-row__name">{s.name}</div>
              <p className="stage-row__outcome">{s.outcome}</p>
            </div>
          ))}
        </div>

        <h2>Checklists, not labs</h2>
        <p>
          There are no live labs. Every topic ends with a checklist of commands
          you run against an account you control — enumeration steps, a permission
          check, a log query — with what a correct result looks like. This keeps
          the site free, keeps it safe to run against production-adjacent
          accounts you own, and makes the verification repeatable when you come
          back to a topic a year later.
        </p>
        <p>
          Commands are written for the current CLI generation and tested for
          syntax. Where a technique needs a specific permission, the checklist
          says which one, so you can tell whether a failure means "not
          vulnerable" or "you are not allowed to check".
        </p>

        <h2>What stays current</h2>
        <p>
          The curriculum is curated and reviewed by hand — that is what keeps the
          voice consistent and the accuracy high. The advisory feed is
          automated: it pulls the CISA Known Exploited Vulnerabilities catalog
          and the three providers' security bulletins on a schedule, maps entries
          to the topic that explains the mechanism, and commits the result. The
          fundamentals do not rot; the advisories do, so only the advisories are
          automated.
        </p>

        <h2>Where the line is drawn</h2>
        <p>
          This is written for authorised testing and for understanding your own
          estate. Techniques are described so you can recognise and detect them,
          with the commands needed to verify a finding you have legitimate access
          to. It is not a step-by-step guide to attacking infrastructure you do
          not own, and the topics say so where the distinction matters.
        </p>
      </div>

      <div className="prose" style={{ marginTop: '3rem' }}>
        <h2>Current size</h2>
        <ul>
          <li>{stats.topics} topics across {stats.clouds} clouds</li>
          <li>{stats.techniques} attack techniques</li>
          <li>{stats.signals} detection signals with queries</li>
          <li>{stats.remediations} prioritised remediations</li>
          <li>{stats.checks} runnable verification steps</li>
        </ul>
        <p>
          <Link className="btn" to="/curriculum">
            Open the curriculum
          </Link>
        </p>
      </div>
    </div>
  )
}
