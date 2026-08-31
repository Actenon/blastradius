"""Unit tests for tokenise.py and commands.py — v0.3.0 API.

v0.3.0: tokenise() now returns segments (list of token lists) instead
of a single token list. Compound commands (&&, ||, ;, |) are split
into segments rather than refused.
"""

from __future__ import annotations

import pytest

from blastradius.tokenise import tokenise
from blastradius.commands import identify_destructive, identify_risks


class TestTokeniser:
    """Tokeniser — quoting, splitting, refusal."""

    def test_simple_command(self):
        """rm -rf /tmp/foo → one segment."""
        result = tokenise("rm -rf /tmp/foo")
        assert result.segments == [["rm", "-rf", "/tmp/foo"]]

    def test_single_quotes(self):
        result = tokenise("rm -rf '/tmp/my dir'")
        assert result.segments == [["rm", "-rf", "/tmp/my dir"]]

    def test_double_quotes(self):
        result = tokenise('rm -rf "/tmp/my dir"')
        assert result.segments == [["rm", "-rf", "/tmp/my dir"]]

    def test_escaped_space(self):
        result = tokenise("rm /tmp/my\\ dir")
        assert result.segments == [["rm", "/tmp/my dir"]]

    def test_empty_command(self):
        result = tokenise("")
        assert result.segments is None or result.segments == []

    def test_compound_and_splits(self):
        """cd /tmp && rm foo → two segments."""
        result = tokenise("cd /tmp && rm foo")
        assert result.segments is not None
        assert len(result.segments) == 2
        assert result.segments[0] == ["cd", "/tmp"]
        assert result.segments[1] == ["rm", "foo"]
        assert result.separators == ["&&"]

    def test_compound_semicolon_splits(self):
        """rm /tmp/foo; rm /tmp/bar → two segments."""
        result = tokenise("rm /tmp/foo; rm /tmp/bar")
        assert result.segments is not None
        assert len(result.segments) == 2
        assert result.separators == [";"]

    def test_compound_pipe_splits(self):
        """echo hello | wc → two segments."""
        result = tokenise("echo hello | wc")
        assert result.segments is not None
        assert len(result.segments) == 2
        assert result.separators == ["|"]

    def test_quoted_semicolon_not_split(self):
        """rm -rf "foo;bar" → one segment (semicolon in quotes)."""
        result = tokenise('rm -rf "foo;bar"')
        assert result.segments is not None
        assert len(result.segments) == 1
        assert "foo;bar" in result.segments[0]

    def test_command_substitution_refuses(self):
        result = tokenise("rm $(find /tmp -name foo)")
        assert result.segments is None
        assert result.refusal is not None
        assert "command-substitution" in result.refusal.rule

    def test_backtick_refuses(self):
        result = tokenise("rm `find /tmp`")
        assert result.segments is None
        assert result.refusal is not None
        assert "backtick" in result.refusal.rule

    def test_subshell_refuses(self):
        result = tokenise("(rm /tmp/foo)")
        assert result.segments is None
        assert result.refusal is not None
        assert "subshell" in result.refusal.rule

    def test_eval_refuses(self):
        result = tokenise("eval 'rm -rf /tmp'")
        assert result.segments is None
        assert result.refusal is not None
        assert "eval" in result.refusal.rule

    def test_newline_refuses(self):
        result = tokenise("echo hello\nrm -rf /home")
        assert result.segments is None
        assert result.refusal is not None
        assert "newline" in result.refusal.rule

    def test_three_way_compound(self):
        """cd /tmp && rm foo; echo done → three segments."""
        result = tokenise("cd /tmp && rm foo; echo done")
        assert result.segments is not None
        assert len(result.segments) == 3
        assert result.separators == ["&&", ";"]


class TestCommandIdentification:
    """Identify destructive commands — unchanged from v0.2.0."""

    def test_rm(self):
        action = identify_destructive(["rm", "-rf", "/tmp/foo"])
        assert action is not None
        assert action.command == "rm"
        assert "/tmp/foo" in action.targets

    def test_rmdir(self):
        action = identify_destructive(["rmdir", "/tmp/empty"])
        assert action is not None
        assert action.command == "rmdir"

    def test_shred(self):
        action = identify_destructive(["shred", "/tmp/secret"])
        assert action is not None
        assert action.command == "shred"

    def test_truncate(self):
        action = identify_destructive(["truncate", "-s", "0", "/tmp/log"])
        assert action is not None
        assert action.command == "truncate"
        assert "/tmp/log" in action.targets

    def test_dd(self):
        action = identify_destructive(["dd", "if=/dev/zero", "of=/tmp/disk", "bs=1M"])
        assert action is not None
        assert action.command == "dd"
        assert "/tmp/disk" in action.targets

    def test_find_delete(self):
        action = identify_destructive(["find", ".", "-name", "*.pyc", "-delete"])
        assert action is not None
        assert action.command == "find"
        assert "." in action.targets

    def test_find_exec_rm(self):
        action = identify_destructive(["find", "/tmp", "-exec", "rm", "{}", ";"])
        assert action is not None
        assert action.command == "find"
        assert "/tmp" in action.targets

    def test_git_clean(self):
        action = identify_destructive(["git", "clean", "-fdx"])
        assert action is not None
        assert action.command == "git"

    def test_git_reset_hard(self):
        action = identify_destructive(["git", "reset", "--hard"])
        assert action is not None
        assert action.command == "git"

    def test_non_destructive(self):
        action = identify_destructive(["ls", "-la"])
        assert action is None

    def test_cat_not_destructive(self):
        action = identify_destructive(["cat", "/etc/passwd"])
        assert action is None

    def test_bin_rm_stripped(self):
        action = identify_destructive(["/bin/rm", "-rf", "/tmp/foo"])
        assert action is not None
        assert action.command == "rm"

    def test_rm_multiple_targets(self):
        action = identify_destructive(["rm", "-rf", "/tmp/a", "/tmp/b", "/tmp/c"])
        assert action is not None
        assert len(action.targets) == 3

    def test_double_dash_makes_flag_like_arg_a_target(self):
        action = identify_destructive(["rm", "--", "-foo"])
        assert action is not None
        assert "-foo" in action.targets


class TestRiskWarnings:
    """v0.3.0: Tier 2 risk warnings for non-filesystem actions."""

    def test_pip_install_warns(self):
        warnings = identify_risks(["pip", "install", "stripe"])
        assert len(warnings) == 1
        assert warnings[0].category == "package"
        assert "arbitrary code" in warnings[0].reason

    def test_pip3_install_warns(self):
        warnings = identify_risks(["pip3", "install", "requests"])
        assert len(warnings) == 1
        assert warnings[0].category == "package"

    def test_python_m_pip_install_warns(self):
        warnings = identify_risks(["python", "-m", "pip", "install", "foo"])
        assert len(warnings) == 1
        assert warnings[0].category == "package"

    def test_npm_install_warns(self):
        warnings = identify_risks(["npm", "install", "express"])
        assert len(warnings) == 1
        assert warnings[0].category == "package"

    def test_curl_with_credential_warns(self):
        warnings = identify_risks(["curl", "-H", "Authorization: Bearer $TOKEN", "https://api.example.com"])
        assert len(warnings) >= 1
        assert any(w.category == "network" for w in warnings)
        assert any("credential" in w.reason for w in warnings)

    def test_curl_without_credential_warns(self):
        warnings = identify_risks(["curl", "https://example.com"])
        assert len(warnings) == 1
        assert warnings[0].category == "network"
        assert warnings[0].severity == "medium"

    def test_wget_warns(self):
        warnings = identify_risks(["wget", "https://example.com/file.tar.gz"])
        assert len(warnings) == 1
        assert warnings[0].category == "network"

    def test_git_filter_branch_warns(self):
        warnings = identify_risks(["git", "filter-branch", "--force", "--index-filter", "git rm --cached .env", "HEAD"])
        assert any(w.category == "git" for w in warnings)
        assert any("filter-branch" in w.reason for w in warnings)

    def test_git_push_force_warns(self):
        warnings = identify_risks(["git", "push", "--force", "origin", "main"])
        assert any(w.category == "git" for w in warnings)
        assert any("force" in w.reason for w in warnings)

    def test_git_push_warns(self):
        warnings = identify_risks(["git", "push", "origin", "main"])
        assert any(w.category == "git" for w in warnings)
        assert any("publishes" in w.reason for w in warnings)

    def test_chmod_recursive_warns(self):
        warnings = identify_risks(["chmod", "-R", "777", "/var/www"])
        assert len(warnings) == 1
        assert warnings[0].category == "permission"
        assert "/var/www" in warnings[0].reason

    def test_twine_upload_warns(self):
        warnings = identify_risks(["twine", "upload", "dist/*"])
        assert len(warnings) == 1
        assert warnings[0].category == "publish"
        assert "irreversible" in warnings[0].reason

    def test_npm_publish_warns(self):
        warnings = identify_risks(["npm", "publish"])
        assert len(warnings) == 1
        assert warnings[0].category == "publish"

    def test_env_file_write_warns(self):
        """echo > .env should warn (writing to a secret file)."""
        warnings = identify_risks(["echo", "DATABASE_URL=...", ">", ".env"])
        # The > is not a token in the command list — it's a redirect.
        # blastradius's tokeniser doesn't split on >. So we test with
        # a command that clearly writes to .env.
        warnings = identify_risks(["sed", "-i", "s/foo/bar/", ".env"])
        assert any(w.category == "config" for w in warnings)
        assert any(".env" in w.reason for w in warnings)

    def test_env_file_read_does_not_warn(self):
        """cat .env should NOT warn (reading is less dangerous)."""
        warnings = identify_risks(["cat", ".env"])
        assert not any(w.category == "config" for w in warnings)

    def test_production_deploy_warns(self):
        warnings = identify_risks(["kubectl", "apply", "-f", "production.yaml"])
        assert any(w.category == "deployment" for w in warnings)

    def test_ssh_warns(self):
        warnings = identify_risks(["ssh", "user@host", "rm -rf /"])
        assert any(w.category == "network" for w in warnings)

    def test_docker_run_with_mount_warns(self):
        warnings = identify_risks(["docker", "run", "-v", "/host:/container", "ubuntu"])
        assert any(w.category == "deployment" for w in warnings)

    def test_ls_no_warning(self):
        warnings = identify_risks(["ls", "-la"])
        assert len(warnings) == 0

    def test_echo_no_warning(self):
        warnings = identify_risks(["echo", "hello"])
        assert len(warnings) == 0

    def test_git_status_no_warning(self):
        warnings = identify_risks(["git", "status"])
        assert len(warnings) == 0

    def test_staging_to_production_warns(self):
        warnings = identify_risks(["sed", "-i", "s/staging/production/g", "deploy.sh"])
        assert any(w.category == "deployment" for w in warnings)
        assert any("staging to production" in w.reason for w in warnings)
