# MPR-UI assets

The workspace uses an unreleased MPR UI candidate for B080, GitHub issue #238.
Source: <https://github.com/MarcoPoloResearchLab/mpr-ui/tree/d29f43b96991ff409db968f56e6b3fc57b6d20e0> plus local changes for the theme storage error event.
The adjacent license contains the repository MIT license.
Application code is outside this directory.
The Pages artifact includes these assets. Browser acceptance uses the same files.

SHA-256 identifies the copied files:

- `mpr-ui.js`: `80e6109539f335b11e3caa533b4af9807434a22bf44a1208d7b5edfd02e3758a`
- `mpr-ui.css`: `b6ee455076512890aedddfd249ba8d73ec8e67c69cdfe8ad127fc412dc809db7`

The console uses an explicit quadrant control with four named palette selections.
The shared theme manager owns writes to `tauth.console.palette`.
The application reads this key to synchronize open pages and restored pages.
A storage write failure keeps the active palette and shows the error in the console notice.
