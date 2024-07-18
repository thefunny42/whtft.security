import pytest

import whtft.security


@pytest.mark.asyncio
async def test_print_generated_token(capsys, settings):
    await whtft.security.print_generated_token("yourole")
    capured = capsys.readouterr()

    auth = whtft.security.Checker(settings)
    roles = await auth.authenticate(capured.out.strip())
    assert roles == ["yourole"]


@pytest.mark.asyncio
async def test_auth_jwks_generate(jwks_settings, mocked_jwks):
    auth = whtft.security.Checker(jwks_settings)
    token = await auth.generate_token("myrole")
    assert token != ""

    roles = await auth.authenticate(token)
    assert roles == ["myrole"]


@pytest.mark.asyncio
async def test_auth_jwks_generate_failed_fetch(
    jwks_settings, mocked_jwks_failed
):
    auth = whtft.security.Checker(jwks_settings)
    token = await auth.generate_token()
    assert token == ""
    assert mocked_jwks_failed.called


@pytest.mark.asyncio
async def test_auth_token(settings, token):
    auth = whtft.security.Checker(settings)
    roles = await auth.authenticate(token.token)
    assert roles == []


@pytest.mark.asyncio
async def test_auth_jwks_token_failed_fetch(
    jwks_settings, jwks_token, mocked_jwks_failed
):
    auth = whtft.security.Checker(jwks_settings)
    roles = await auth.authenticate(jwks_token.token)
    assert roles is None
    assert mocked_jwks_failed.called


@pytest.mark.asyncio
async def test_auth_jwks_token(jwks_settings, jwks_token):
    auth = whtft.security.Checker(jwks_settings)
    roles = await auth.authenticate(jwks_token.token)
    assert roles == []


@pytest.mark.asyncio
async def test_auth_admin_token(settings, admin_token):
    auth = whtft.security.Checker(settings)
    roles = await auth.authenticate(admin_token.token)
    assert roles == ["admin"]


@pytest.mark.asyncio
async def test_auth_jwks_admin_token(jwks_settings, jwks_admin_token):
    auth = whtft.security.Checker(jwks_settings)
    roles = await auth.authenticate(jwks_admin_token.token)
    assert roles == ["admin"]
