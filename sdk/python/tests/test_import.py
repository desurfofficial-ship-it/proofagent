def test_import():
    from proofagent import Agent, Client
    assert Client is not None
    assert Agent is not None
