# Dashboard Design

<!-- impeccable:design-schema 1 -->

## Surface

Local Security Dashboard, an Operate-mode tool used by one developer while an AI-generated project is being audited.

## Visual World

Run ledger / instrument panel. The interface borrows from a well-kept engineering runbook: cool paper, ink-blue structure, amber attention markers, and small mono labels for measurements. It intentionally avoids a dense enterprise SOC wall and avoids decorative data visualizations that could imply more certainty than the scanners provide.

## Color Strategy

Restrained. The main surface is a cool graphite paper (`#f4f6f8`) with one structural navy (`#0f2538`) and semantic accents: green for pass/healthy, amber for running/warning, red for fail/high-risk, and blue for informational links.

## Type

System sans for UI reading and action labels. A monospace stack is reserved for paths, timestamps, version numbers, and state labels. The scale is compact because the product is used for scanability, not presentation.

## Composition

Desktop uses a narrow dark navigation rail plus a wide evidence canvas. The first viewport leads with the release gate and run details, then the pipeline ledger, scanner status, and activity stream. Mobile collapses the rail into a wrapped local navigation bar and stacks the evidence panels.

## Interaction

Buttons expose only predefined safe actions. Real-time status uses Server-Sent Events. Running scanners are visibly marked. History is append-only, and a later absence of a stable finding ID becomes `VERIFIED` rather than deleting the earlier record.

## Accessibility

Semantic headings, labelled fields, visible focus, text labels for every state color, responsive layout, and reduced-motion support are required. Contrast is kept high on the navy rail and white evidence panels.
