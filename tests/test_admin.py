def test_task_detail_unknown_user(client):
    resp = client.get("/tasks/user/nonexistent")
    assert resp.status_code == 404


def test_task_detail_unknown_injection(client):
    resp = client.get("/tasks/injection/nonexistent")
    assert resp.status_code == 404
