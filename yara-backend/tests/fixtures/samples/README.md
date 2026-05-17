# Synthetic test samples

This directory used to ship binary fixture files. We switched to generating
them inside the test code so the repo stays text-only and reviewers do not
have to inspect raw bytes.

The helpers in `tests/*.rs` produce three shapes:

- `make_mz_buffer(size)` returns a buffer whose first two bytes are `4D 5A`
  (MZ header) and the rest are zero. Used to exercise the `mz_header` rule.
- `make_pdf_buffer(size)` returns a buffer whose first four bytes are
  `25 50 44 46` (`%PDF`). Used to exercise the `pdf_header` rule.
- `make_zip_buffer(size)` returns a buffer whose first four bytes are
  `50 4B 03 04` (PK\x03\x04). Used to exercise the `zip_header` rule.

A deterministic LCG is used for any larger filler bytes so two runs of the
same test see the same bytes. No malware bytes are present in any sample,
ever. The samples are byte shapes that match the rule's pattern, not
executable code.
