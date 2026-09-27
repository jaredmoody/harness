import os
import re

from . import PASS, deny
from .review_brevity import commands_in, flag_values, read_file, unwrap
from .shell_text import heredoc_bodies, segments, strip_prefixes

EXTRA_NAMES = [
    name.strip()
    for name in os.environ.get("GUARDRAILS_ATTRIBUTION_NAMES", "").split(",")
    if name.strip()
]
NAMES = [
    "claude", "anthropic", "codex", "openai", "chatgpt", "gpt-?[45]", "copilot",
    "cursor", "gemini", "grok", "kimi", "devin", "aider", "windsurf", "codeium",
    "llm", "ai agent", "ai assistant",
] + [re.escape(name) for name in EXTRA_NAMES]

AGENT = re.compile(r"\b(?:%s)\b" % "|".join(NAMES), re.IGNORECASE)
CO_AUTHOR = re.compile(r"^[ \t>]*co[-_ ]?authored[-_ ]?by[ \t]*:", re.IGNORECASE)
CREDIT_TRAILER = re.compile(
    r"^[ \t>]*(?:signed[-_ ]?off[-_ ]?by|assisted[-_ ]?by|generated[-_ ]?by"
    r"|written[-_ ]?by|created[-_ ]?by|on[-_ ]?behalf[-_ ]?of)[ \t]*:",
    re.IGNORECASE,
)
CREDIT = re.compile(
    r"\b(?:generated|authored|written|created|produced|assisted|crafted|powered)\b"
    r"[^\n]{0,24}?\b(?:with|by|using|w/)\b",
    re.IGNORECASE,
)
DASH_SIGNOFF = re.compile(r"^[ \t]*(?:-{1,3}|—|–|\*|via)[ \t]*(?:%s)\b" % "|".join(NAMES),
                          re.IGNORECASE)
ROBOT = "\U0001f916"

GLOBAL_VALUE_FLAGS = ("-c", "-C", "--git-dir", "--work-tree", "--namespace", "--exec-path")

DENIAL = """DENIED - no co-author trailer and no tool signature in a commit message.

{lines}

`git blame`, `git shortlog`, release notes and the contributor graph all read the trailer block
as a claim about people. A tool that typed the diff is not a second author, and a "Generated
with ..." line is advertising written into a record that outlives the session: it survives every
log, every backport and every cherry-pick of this commit, and no reader can remove it without
rewriting history.

Commit as yourself. The message says what changed and why; where it came from belongs in the
pull request or the session log, not in the trailer block.

Override when a human genuinely co-wrote the change: GUARDRAILS_ALLOW_COMMIT_ATTRIBUTION=1"""


def subcommand(argv):
    index = 1
    while index < len(argv):
        token = argv[index]
        if not token.startswith("-"):
            return token
        if token in GLOBAL_VALUE_FLAGS:
            index += 2
            continue
        index += 1
    return ""


def commits(command):
    found = []
    for argv in segments(command):
        argv = strip_prefixes(argv)
        if not argv or argv[0].rsplit("/", 1)[-1] != "git":
            continue
        if subcommand(argv) == "commit":
            found.append(argv)
    return found


def reads_stdin(argvs):
    return any(
        value == "-"
        for argv in argvs
        for value in flag_values(argv, "-F", "--file", "-t", "--template")
    )


def message_texts(command, argvs):
    texts = heredoc_bodies(command) if reads_stdin(argvs) else []
    authors = []
    for argv in commands_in(command):
        argv = unwrap(argv)
        if not argv or argv[0].rsplit("/", 1)[-1] != "git":
            continue
        texts += flag_values(argv, "-m", "--message", "--trailer")
        authors += flag_values(argv, "--author")
        for reference in flag_values(argv, "-F", "--file", "-t", "--template"):
            body = read_file(reference)
            if body is not None:
                texts.append(body)
    return texts, authors


def fault(line):
    if CO_AUTHOR.match(line):
        return "adds a co-author trailer"
    if CREDIT_TRAILER.match(line) and AGENT.search(line):
        return "signs the commit with a tool name"
    if ROBOT in line:
        return "carries a tool signature"
    if CREDIT.search(line) and AGENT.search(line):
        return "credits the tool that wrote it"
    if DASH_SIGNOFF.match(line):
        return "signs off as the tool"
    return None


def quote(line):
    line = line.strip()
    return line[:69] + "..." if len(line) > 72 else line


def offences(texts, authors):
    found = []
    for author in authors:
        if AGENT.search(author):
            found.append("  --author=%s   <- commits under the tool's name" % quote(author))
    for text in texts:
        for line in (text or "").split("\n"):
            reason = fault(line)
            if reason is None:
                continue
            entry = "  %s   <- %s" % (quote(line), reason)
            if entry not in found:
                found.append(entry)
    return found


def check_command(command):
    command = command or ""
    if os.environ.get("GUARDRAILS_ALLOW_COMMIT_ATTRIBUTION"):
        return PASS
    argvs = commits(command)
    if not argvs:
        return PASS

    texts, authors = message_texts(command, argvs)
    found = offences(texts, authors)
    if not found:
        return PASS
    return deny(DENIAL.format(lines="\n".join(found[:5])))
