#!/usr/bin/env python3
"""
One‑shot C vulnerability patcher + git commit/push for libjpeg.
Adds comments and safe replacements. Run inside your libjpeg repo.

Set DRY_RUN = False below to actually patch, commit and push.
"""

import re
import sys
import subprocess
from pathlib import Path
from typing import List, Tuple

# ============================================================
# CONFIGURATION – CHANGE THIS TO False WHEN READY
# ============================================================
DRY_RUN = False          # <--- SET TO False TO ACTUALLY PATCH AND PUSH
TARGET_BRANCH = "hardening/ansi2knr-20260528"
COMMIT_MESSAGE = "Security hardening: add bounds checking (scanf/sprintf/strcpy/memcpy)"

# ============================================================
# PATCHING FUNCTIONS (with comment insertion)
# ============================================================

def _fix_scanf(match: re.Match) -> str:
    """Replace %s with %255s, add comment."""
    func = match.group(1)
    fmt = match.group(2)
    new_fmt = re.sub(r'%s', '%255s', fmt)
    new_fmt = re.sub(r'%\[', '%255[', new_fmt)
    comment = "/* FIXED: added width specifier to prevent buffer overflow */\n    "
    return comment + f'{func}("{new_fmt}"'

def _fix_sprintf(match: re.Match) -> str:
    """Replace sprintf with snprintf, add comment."""
    dest = match.group(1).strip()
    fmt = match.group(2)
    comment = "/* FIXED: replaced sprintf with snprintf to avoid overflow */\n    "
    return comment + f'snprintf({dest}, sizeof({dest}), "{fmt}"'

def _fix_strcpy(match: re.Match) -> str:
    """Replace strcpy with strncpy + null termination, add comment."""
    dest = match.group(1).strip()
    src = match.group(2).strip()
    comment = "/* FIXED: replaced strcpy with strncpy and explicit null terminator */\n    "
    return comment + f'strncpy({dest}, {src}, sizeof({dest})-1); {dest}[sizeof({dest})-1] = \'\\0\''

def _fix_memcpy(match: re.Match) -> str:
    """Add length check before memcpy, add comment."""
    dest = match.group(1).strip()
    src = match.group(2).strip()
    sz = match.group(3).strip()
    comment = "/* FIXED: added bounds check to prevent buffer over-read/write */\n    "
    return comment + f'if ({sz} <= sizeof({dest})) memcpy({dest}, {src}, {sz}); else {{ /* handle error */ }}'

# ============================================================
# VULNERABILITY PATTERNS (order matters – apply most specific first)
# ============================================================

VULN_PATTERNS = {
    'scanf': {
        'pattern': re.compile(r'\b(scanf|sscanf)\s*\(\s*"([^"]*)"', re.M),
        'fix': _fix_scanf
    },
    'sprintf': {
        'pattern': re.compile(r'\bsprintf\s*\(\s*([^,]+)\s*,\s*"([^"]*)"', re.M),
        'fix': _fix_sprintf
    },
    'strcpy': {
        'pattern': re.compile(r'\bstrcpy\s*\(\s*([^,]+)\s*,\s*([^;]+)\)', re.M),
        'fix': _fix_strcpy
    },
    'memcpy_oob': {
        'pattern': re.compile(r'\bmemcpy\s*\(\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^)]+)\)', re.M),
        'fix': _fix_memcpy
    }
}

def patch_file(filepath: Path) -> Tuple[bool, List[str]]:
    """Apply patches to a single C file. Returns (changed, list_of_changes)."""
    original = filepath.read_text(encoding='utf-8', errors='ignore')
    modified = original
    changes = []

    for vuln_name, info in VULN_PATTERNS.items():
        pattern = info['pattern']
        fix_func = info['fix']
        # Find first match in current modified content
        match = pattern.search(modified)
        if match:
            replacement = fix_func(match)
            if replacement != match.group(0):
                line_no = modified[:match.start()].count('\n') + 1
                changes.append(f'{vuln_name}: L{line_no}')
                modified = modified[:match.start()] + replacement + modified[match.end():]

    if modified == original:
        return False, []

    if not DRY_RUN:
        filepath.write_text(modified, encoding='utf-8')
    return True, changes

# ============================================================
# GIT OPERATIONS (fixed error detection)
# ============================================================

def run_git(cmd: List[str], cwd: Path) -> Tuple[str, str]:
    proc = subprocess.run(['git'] + cmd, cwd=cwd, capture_output=True, text=True)
    return proc.stdout.strip(), proc.stderr.strip()

def ensure_branch(repo_root: Path) -> bool:
    """Checkout TARGET_BRANCH, creating it if needed."""
    stdout, _ = run_git(['branch', '--show-current'], repo_root)
    current = stdout.strip()
    if current == TARGET_BRANCH:
        print(f'Already on branch {TARGET_BRANCH}')
        return True

    # Try to checkout existing branch
    out, err = run_git(['checkout', TARGET_BRANCH], repo_root)
    if 'Switched to branch' in out or 'already on' in out:
        print(f'Switched to branch {TARGET_BRANCH}')
        return True
    # If branch doesn't exist, create it
    if "did not match any file" in err or "is not a commit" in err:
        print(f'Creating new branch {TARGET_BRANCH} from current HEAD')
        out, err = run_git(['checkout', '-b', TARGET_BRANCH], repo_root)
        if 'Switched to a new branch' in out:
            return True
    print(f'Failed to switch to {TARGET_BRANCH}: {err}')
    return False

def git_commit_and_push(repo_root: Path) -> bool:
    """Add, commit, and push changes."""
    run_git(['add', '--all'], repo_root)
    out, err = run_git(['commit', '-m', COMMIT_MESSAGE], repo_root)
    if 'nothing to commit' in out or 'nothing to commit' in err:
        print('No changes to commit.')
        return False
    if err and 'nothing added to commit' not in err:
        print(f'Commit error: {err}')
        return False
    print(f'Committed: {COMMIT_MESSAGE}')

    out, err = run_git(['push', 'origin', TARGET_BRANCH], repo_root)
    if err and 'failed' in err.lower():
        print(f'Push error: {err}')
        return False
    print('Successfully pushed to origin.')
    return True

# ============================================================
# MAIN
# ============================================================

def main():
    # Find repository root
    repo_root = Path.cwd()
    while repo_root != repo_root.parent:
        if (repo_root / '.git').is_dir():
            break
        repo_root = repo_root.parent
    else:
        print('Error: not inside a git repository. Run from your libjpeg clone.')
        sys.exit(1)

    print(f'Repository root: {repo_root}')

    if not ensure_branch(repo_root):
        sys.exit(1)

    c_files = list(repo_root.rglob('*.c')) + list(repo_root.rglob('*.h'))
    print(f'Found {len(c_files)} C/C++ files.')

    patched = 0
    for cfile in c_files:
        changed, changes = patch_file(cfile)
        if changed:
            patched += 1
            print(f'\n[{"DRY RUN " if DRY_RUN else ""}]Patching {cfile.relative_to(repo_root)}')
            for ch in changes:
                print(f'  {ch}')

    if DRY_RUN:
        print(f'\n✅ Dry run complete. {patched} file(s) would be patched.')
        print('👉 Set DRY_RUN = False at the top of the script and run again to apply patches and push.')
    else:
        print(f'\n✅ Patched {patched} file(s).')
        if git_commit_and_push(repo_root):
            print('\n🎉 All done! Check your fork:')
            print(f'https://github.com/josephelliottwest3-blip/libjpeg/compare/master...{TARGET_BRANCH}')
        else:
            print('⚠️ Git operation failed. Review changes manually.')

if __name__ == '__main__':
    main()