# ZS-PY-009: assert used for security check
# NOTE: will not fire in Sprint 3 — tree-sitter emits assert_statement, not call
def delete_resource(user):
    assert user.is_admin()
