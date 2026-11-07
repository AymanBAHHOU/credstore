# credstore visual system

The desktop app's look, as built in `app/ui/` (2026-11-07). Product context is in
[PRODUCT.md](../PRODUCT.md); the approved mockup is `design/mockup/index.html`.

## Direction

A calm infrastructure console, with cloudflare.com as the craft bar: flat dark ground,
one clean sans, hairlines and pill shapes. The app is quiet while idle and unmistakable
when an agent is waiting. The owner rejected a skeuomorphic "hardware panel" take
(screws, glowing lights, engraved labels) as childish: no skeuomorphism, no shadows,
gradients or glows.

## Color

Three colors chosen by the owner; everything else is derived from them.

| Token        | Value                    | Use |
| ------------ | ------------------------ | --- |
| `--obsidian` | `#0E0F12`                | the ground; text on the primary button |
| `--ice`      | `#DCE3EA`                | primary text, the primary button, "on" dots |
| `--red`      | `#D40000`                | only what needs the human: the waiting band, counts, the denied tag, unsaved changes |
| `--text-2`   | `#A3ADB8`                | secondary text |
| `--text-3`   | `#76808B`                | labels and help |
| `--red-text` | `#FF6A5E`                | red as small text or outline (AA on obsidian) |
| `--line` / `--line-2` | ice at 12% / 22% | hairlines |
| `--fill` / `--fill-2` | ice at 4% / 7%   | surfaces, selected rows |

Red never carries a state alone: the band says "Waiting for you", tags say "denied" or
"refused", the badge holds a number.

## Type

Geist for text, Geist Mono for labels, commands, URLs, secret names and timestamps (both
SIL OFL, bundled in `app/ui/fonts/`). Headings 38 px weight 500 with tight tracking;
body 15 px; labels 11.5 px mono, uppercase, letter-spaced.

## Shapes and components

- **Pills** for buttons, inputs, nav items, status, tags and toggles (`.btn`,
  `.input`, `.pill`, `.tag`, `.seg`). The primary button is solid ice; the danger
  button is red outline text. Deny and Approve sit side by side at the same size.
- **Boxes**: 14 px radius, one hairline, 4% fill. Sections inside a box are split by
  hairlines (`.sec`, `.row`).
- **Request**: a solid red band ("Waiting for you"), then a two-column readout (`.kv`)
  with mono values, then the decision bar (passphrase, Deny, Approve for a while,
  Approve once). Keyboard: A approves once, D denies.
- **Notice**: a ring dot, one sentence in plain words, the fix as the primary button.
- **Chips** for hosts and command patterns; a dashed chip says what an empty list means.
- **Save bar** appears only with unsaved changes: count, passphrase, Discard, Save.
- **Switch** for on/off settings; selects for timers.
- **Island**: a waiting request at the top of the screen. Collapsed, an obsidian pill
  with a hairline edge, a red dot, "Agent wants NAME → host" (the name in mono) and a
  red count when more wait. Open, a 560 px box with 18 px radius: the red "Waiting for
  you" band, a mono readout, the passphrase field and the decision buttons, "Open
  credstore" as a text link. It drops in from 12 px above (none with reduced motion).
  After a decision it shrinks to a pill saying "Approved once" (ice dot) or "Denied"
  (red ring) for a moment.
- **Passphrase dialog** for changes: never pre-filled, cleared after use, stays open on
  a wrong passphrase.

## Icon

An obsidian rounded tile with a thin `#3A4048` edge, an ice slot across the middle (a
key's opening) and one red dot top right, the same red that means a request is waiting.
64-unit grid: tile `rx 15`, slot `x13 y27 w38 h10 rx5`, dot `cx47 cy16 r5`. The SVG is
in `app/ui/index.html`; `app/icons/make_icons.py` renders the PNGs and the ICO.

## Not done

The finish review from the impeccable workflow was done in this session by the same
agent that built the page (no separate reviewer was available), against the mockup and
the principles in PRODUCT.md. A review by someone else is still worth doing.
