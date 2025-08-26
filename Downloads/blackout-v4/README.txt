
Blackout • Lock Gate v4 (redirect build)

Flow:
  index.html (lock) -> correct PIN -> redirect to blackoutv1.9.2.html

How to run:
  python3 -m http.server 8080
  # open http://localhost:8080/index.html

Notes:
  • PIN set on file:// does not carry to http://localhost; set once per origin.
  • Service worker cache bumped to v4; if you change files, also bump the '?v=' or CACHE name.
  • Put any future main-page updates into blackoutv1.9.2.html.
