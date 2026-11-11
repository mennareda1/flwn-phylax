# Components

The registry (SKILL.md section 5a). Before building any UI: use what is here, extend it with a prop, and only then add a component, registered in this file in the same change.
One component per file, `PascalCase.jsx`. Tokens only: no hex, no px outside hairlines, two radii. Every interactive piece has hover, press, focus, disabled and loading states.

## `ui/` generic

| Component | What it is |
|---|---|
| `AiAvatar` | The navy "AI" circle, one of the two dark elements. `thinking` adds the soft ring. |
| `Button` | `primary` (the dark one, at most one per view), `secondary`, `ghost`. `loading` swaps the label for a spinner at the same width. `icon` takes a Lucide component. |
| `Callout` | Pastel block with a meaning: `tip` green, `decision` lavender, `note` gold, `warning` salmon, `info` blue. |
| `CardSkeleton` | The shape of a finding or correction card while it loads. |
| `Checkbox` | A real checkbox drawn as a rounded square; the mark draws in. 2.75rem target. |
| `ChecksList` | What Phylax checked about a correction, each line ticked or failed, in plain words. |
| `Chip` | Small tag on a card. |
| `CodeDiff` | A unified diff with line numbers, removed lines on salmon and added on green, spoken labels for screen readers. |
| `Counter` | A number that crossfades when it changes. |
| `Drawer` | Panel from the right (full-screen sheet on a phone). Fades in and out, traps Tab, restores focus, `locked` stops it closing, `footer` stays visible. |
| `IconButton` | Icon-only control: `aria-label` and a tooltip are required. |
| `Popover` | Panel that opens from its trigger, closes on Escape or an outside click, fades out before it is removed. |
| `Skeleton` | A placeholder bar. `tone="pastel"` for use on a coloured card. |
| `Spinner` | The 1rem ring (Lucide `loader-circle`). |
| `ThinkingIndicator` | Three bouncing dots and a status line that crossfades through the lines it is given. |
| `Toast` (`ToastStack`) | Messages that slide in, count down, leave. Never take clicks. |
| `Tooltip` | Opens after a short pause; no pause between neighbours. |

## `layout/` shell

| Component | What it is |
|---|---|
| `Canvas` | Cream page, dotted grid, thin rounded frame. |
| `RailTabs` (`SideTabs`, `BottomBar`) | The same three actions as pennants on a wide screen and a bottom bar on a phone. |
| `UserBadge` | The lavender circle with initials, bottom left on a wide screen. |
| `Wordmark` | The flwn wordmark, exactly as delivered, nothing beside it. |

## `review/` the security review

| Component | What it is |
|---|---|
| `Column` | A board column: white header, pastel square, title, count; the empty message when it has no cards. |
| `CorrectionCard` | A correction waiting for a decision (lavender). "Review correction" opens the drawer. It never applies itself. |
| `CorrectionDrawer` | The one place a correction is approved: what Phylax checked, the exact change, and Apply correction or Not now. |
| `CoveragePanel` | What was and was not checked. Opens by grid rows. |
| `DemoChip` | The "Demo data" label with its explanation and the two demo controls. |
| `ErrorCallout` | Salmon block: what went wrong, "Nothing was changed", Try again. |
| `FindingCard` | One finding on a pastel by severity. A checkbox only if it can be corrected; otherwise the service's reason. |
| `FixedCard` | A correction that was applied and checked again (green). |
| `ProjectSwitcher` | The blue block naming the project, overlapping the banner. |
| `ReviewBoard` | The three columns with their skeletons and empty states. |
| `SumUpBanner` | The gold strip: the review's state in a sentence, or the thinking indicator. |
| `TopActions` | The one dark action: Scan project, then Prepare corrections (n). |
