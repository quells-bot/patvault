# Superpowers skills (vendored)

This directory contains the skills library from [obra/superpowers](https://github.com/obra/superpowers),
vendored in as repo-local Claude Code skills so they're available automatically
in this repository without a plugin marketplace install.

- Source: https://github.com/obra/superpowers
- Vendored at commit: `d884ae04edebef577e82ff7c4e143debd0bbec99` (2026-07-02)
- License: MIT (see `LICENSE` in this directory)

Start with `using-superpowers/SKILL.md` for how the skill set is meant to be used.

## Updating

Re-sync by cloning the upstream repo and copying its `skills/` directory over
this one (excluding this README), then reviewing the diff:

```bash
git clone --depth 1 https://github.com/obra/superpowers.git /tmp/superpowers-src
rsync -a --delete --exclude README.md --exclude LICENSE \
  /tmp/superpowers-src/skills/ .claude/skills/
cp /tmp/superpowers-src/LICENSE .claude/skills/LICENSE
```
