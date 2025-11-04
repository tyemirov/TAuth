# LoopAware Footer Reference

This document captures the exact structure, styling hooks, and behavioural contracts of the LoopAware public footer so the TAuth demo can reproduce it faithfully without depending on the original Go templates.

## 1. Markup & Data Contracts

LoopAware ships the footer alongside vanilla Bootstrap 5.3 and Bootstrap Icons. To reproduce the experience you must load:

- `https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css`
- `https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js`
- `https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css` (for optional glyphs)

The Go helper `internal/httpapi/footer.go` renders the footer through `pkg/footer.Render`. For the landing page variant the configuration resolves to the following identifiers and classes:

| Config Field              | Value                                                            | Purpose |
|---------------------------|------------------------------------------------------------------|---------|
| `elementId`               | `landing-footer`                                                 | DOM anchor (`<footer id="landing-footer">`) so CSS can target the surface. |
| `innerElementId`          | `landing-footer-inner`                                           | Wraps the layout container for padding control. |
| `baseClass`               | `landing-footer border-top mt-auto py-2`                         | `landing-footer` drives the dark/light palette; the other Bootstrap classes add the top border, spacing, and allow flex layouts to push the footer down. |
| `innerClass`              | `container py-2`                                                 | Centers the content and applies vertical padding (Bootstrap container semantics). |
| `wrapperClass`            | `footer-layout w-100 d-flex flex-column flex-md-row align-items-start align-items-md-center justify-content-between gap-3` | Flexbox orchestration: column on small screens, row on ≥768 px, with spacing and alignment consistent with the rest of the site. |
| `brandWrapperClass`       | `footer-brand d-inline-flex align-items-center gap-2 text-body-secondary small` | Holds the theme toggle + “Built by” prefix in a compact inline flex row. |
| `menuWrapperClass`        | `footer-menu dropup`                                             | Required for the drop-up animation; Bootstrap reads `dropup` and adds positioning to the dropdown menu. |
| `prefixClass`             | `text-body-secondary fw-semibold`                                | Styles the “Built by” copy. |
| `toggleButtonClass`       | `btn btn-link dropdown-toggle text-decoration-none px-0 fw-semibold text-body-secondary` | The product selector trigger — semantically still a button but visually presented as inline text with the dropdown chevron. |
| `menuClass`               | `dropdown-menu dropdown-menu-end shadow`                         | Bootstrap classes to right-align and add elevation. |
| `menuItemClass`           | `dropdown-item`                                                  | Ensures each link inherits the Bootstrap dropdown item spacing. |
| `privacyLinkClass`        | `footer-privacy-link text-body-secondary text-decoration-none small` | Places the “Privacy • Terms” link on the opposite side of the layout. |
| `themeToggleWrapperClass` | `footer-theme-toggle form-check form-switch m-0`                 | Renders the theme toggle using Bootstrap’s “form switch” pattern. |
| `themeToggleInputClass`   | `form-check-input`                                               | Applies the pill-track plus thumb styling to the checkbox input. |
| `themeToggleId`           | `public-theme-toggle`                                            | Consumed by the public theme persistence script. |

Rendered markup (abridged) looks like:

```html
<footer id="landing-footer" class="landing-footer border-top mt-auto py-2" data-mpr-footer="root" …>
  <div id="landing-footer-inner" class="container py-2" data-mpr-footer="inner">
    <div class="footer-layout w-100 d-flex flex-column flex-md-row align-items-start align-items-md-center justify-content-between gap-3" data-mpr-footer="layout">
      <a class="footer-privacy-link text-body-secondary text-decoration-none small" data-mpr-footer="privacy-link" href="/privacy">Privacy • Terms</a>
      <div class="footer-brand d-inline-flex align-items-center gap-2 text-body-secondary small" data-mpr-footer="brand">
        <div class="footer-theme-toggle form-check form-switch m-0" data-mpr-footer="theme-toggle" data-bs-theme="light">
          <input class="form-check-input" type="checkbox" id="public-theme-toggle" aria-label="Toggle theme" data-mpr-footer="theme-toggle-input" />
        </div>
        <span class="text-body-secondary fw-semibold" data-mpr-footer="prefix">Built by</span>
        <div class="footer-menu dropup" data-mpr-footer="menu-wrapper">
          <button id="landing-footer-toggle" class="btn btn-link dropdown-toggle text-decoration-none px-0 fw-semibold text-body-secondary" type="button" data-mpr-footer="toggle-button" data-bs-toggle="dropdown" aria-expanded="false">
            Marco Polo Research Lab
          </button>
          <ul class="dropdown-menu dropdown-menu-end shadow" data-mpr-footer="menu" aria-labelledby="landing-footer-toggle">
            <li><a class="dropdown-item" data-mpr-footer="menu-link" href="https://mprlab.com" target="_blank" rel="noopener noreferrer">Marco Polo Research Lab</a></li>
            <!-- Additional products… -->
          </ul>
        </div>
      </div>
    </div>
  </div>
</footer>
```

### Link Catalogue

`footerLinks` emits ten product links (`mprlab.com`, `Gravity Notes`, `LoopAware`, `Allergy Wheel`, `Social Threader`, `RSVP`, `Countdown Calendar`, `LLM Crossword`, `Prompt Bubbles`, `Wallpapers`). Every entry uses `_blank` and `noopener noreferrer`.

## 2. Visual Design & Theme Behaviour

LoopAware relies on Bootstrap’s utility classes for flexbox, spacing, colours, and dropdown behaviour. Additional palette logic lives in `publicSharedStylesCSS`:

- `.landing-footer` background and text colours switch based on `body[data-bs-theme="light"|"dark"]`.
- `.landing-footer .form-check-input` receives different track borders in light vs dark themes.
- Theme toggle is a Bootstrap “form-switch” styled checkbox; the site’s public theme script (`publicThemeToggleID = "public-theme-toggle"`) synchronises the checkbox with `localStorage` and toggles `data-bs-theme` at the document level.

The footer is meant to be fixed to the bottom of the viewport (`landing-footer` is combined with `mt-auto` to support flex layouts on pages that push the footer down). In practice the landing page uses a flex column body with `min-vh-100` so the footer hugs the bottom. Bootstrap’s `dropup` class causes the dropdown menu to expand upward instead of downward, aligning with the sticky footer.

## 3. Behavioural Expectations

1. **Theme Toggle**
   - Checkbox ID: `public-theme-toggle`.
   - Checked state indicates the dark theme.
   - Changing the switch dispatches a change event that the shared theme script handles (`publicThemeToggleID`), updating `localStorage` and applying `data-bs-theme`.

2. **Dropup Menu**
   - Toggle button has `data-bs-toggle="dropdown"` and `aria-expanded="false"` initially.
   - The closed/open state is reflected via the Bootstrap `is-open` class on the `.footer-menu` container when the dropdown is toggled.
   - Menu contents are `li > a.dropdown-item`, with right alignment from `dropdown-menu-end`.

3. **Accessibility**
   - Toggle button maintains `aria-expanded`.
   - Theme toggle input includes `aria-label="Toggle theme"`.
   - The privacy link remains first in DOM order for keyboard users (LoopAware places it before the brand stack).

## 4. Implications for the TAuth Demo

- We must reproduce the class names verbatim so the existing `mprFooter` Alpine factory can enrich the DOM identically and so our CSS mirrors the LoopAware look.
- Because the demo does not load Bootstrap, we have to implement a minimal, semantic equivalent for:
  - Flex utilities (`d-flex`, `flex-column`, `flex-md-row`, `gap-*`, etc.).
  - Spacing utilities (`py-2`, `px-0`, `m-0`, `mt-auto`).
  - Dropdown mechanics (positioning, animation, accessibility).
  - Form-switch styling (track + thumb).
- The theme toggle still needs to dispatch `mpr-footer:theme-change` events; the demo should consume that event and translate it into `document.documentElement.dataset.theme = …` to remain consistent with the existing Alpine integration.
- The product list, privacy link copy, and brand text must match LoopAware exactly to keep parity across properties.

With this reference we can rebuild the demo footer from scratch, modularising the styling/behaviour while preserving the precise structure LoopAware expects.
