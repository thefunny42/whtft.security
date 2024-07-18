import pytest

import whtft.security


@pytest.mark.asyncio
async def test_print_generated_token(capsys, checker):
    await whtft.security.print_generated_token("yourole")
    capured = capsys.readouterr()

    roles = await checker.authenticate(capured.out.strip())
    assert roles == ["yourole"]


@pytest.mark.asyncio
async def test_auth_jwks_generate(jwks_checker, mocked_jwks):
    token = await jwks_checker.generate_token("myrole")
    assert token.token != ""

    roles = await jwks_checker.authenticate(token.token)
    assert roles == ["myrole"]


@pytest.mark.asyncio
async def test_auth_jwks_generate_failed_fetch(
    jwks_checker, mocked_jwks_failed
):
    token = await jwks_checker.generate_token()
    assert token.token == ""
    assert mocked_jwks_failed.called


@pytest.mark.asyncio
async def test_auth_token(checker, token):
    roles = await checker.authenticate(token.token)
    assert roles == []


@pytest.mark.asyncio
async def test_auth_jwks_token_failed_fetch(
    jwks_checker, jwks_token, mocked_jwks_failed
):
    roles = await jwks_checker.authenticate(jwks_token.token)
    assert roles is None
    assert mocked_jwks_failed.called


@pytest.mark.asyncio
async def test_auth_jwks_token(jwks_checker, jwks_token):
    roles = await jwks_checker.authenticate(jwks_token.token)
    assert roles == []


@pytest.mark.asyncio
async def test_auth_admin_token(checker, admin_token):
    roles = await checker.authenticate(admin_token.token)
    assert roles == ["admin"]


@pytest.mark.asyncio
async def test_auth_jwks_admin_token(jwks_checker, jwks_admin_token):
    roles = await jwks_checker.authenticate(jwks_admin_token.token)
    assert roles == ["admin"]
