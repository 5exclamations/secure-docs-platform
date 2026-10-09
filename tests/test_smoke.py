async def test_health(client):
    assert (await client.get("/health")).json() == {"status": "ok"}


async def test_ready(client):
    r = await client.get("/health/ready")
    assert r.status_code == 200, r.text
