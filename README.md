# advisories

Tooling for the [OCaml security advisories](https://github.com/ocaml/security-advisories). Including parsing metadata-enhanced markdown, and OSV export.

## File format

The file format is mostly markdown, but there is a metadata header. This header is using the opam file syntax, since it is well known, and a parser exists in the ecosystem. This metadata must be the first chunk in the markdown, and surrounded by `` ``` ``.
