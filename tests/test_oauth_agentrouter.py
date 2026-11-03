from unittest.mock import patch

import httpx

from utils.oauth_agentrouter import AgentRouterOAuthClient


def test_fetch_oauth_state_reads_state_from_payload():
	client = httpx.Client()
	oauth = AgentRouterOAuthClient(domain='https://example.com')

	with patch.object(client, 'get') as mock_get:
		mock_get.return_value = httpx.Response(200, json={'success': True, 'data': {'state': 'state_123'}})
		assert oauth.fetch_oauth_state(client) == 'state_123'


def test_authorize_github_extracts_code_from_service_response():
	oauth = AgentRouterOAuthClient(domain='https://example.com')

	with patch('utils.oauth_agentrouter.httpx.post') as mock_post:
		mock_post.return_value = httpx.Response(200, json={'success': True, 'data': {'code': 'oauth_code_abc'}})
		assert oauth.authorize_github('gh_token', 'state_xyz') == 'oauth_code_abc'


def test_callback_login_parses_success_and_checked_in():
	client = httpx.Client()
	oauth = AgentRouterOAuthClient(domain='https://example.com')

	with patch.object(client, 'post') as mock_post:
		mock_post.return_value = httpx.Response(
			200,
			json={
				'success': True,
				'message': '登录成功',
				'data': {'id': 123, 'quota': 500000, 'checked_in': True},
			},
		)
		success, user_data, checked_in, message = oauth.callback_login(
			client,
			provider='github',
			code='oauth_code_abc',
			state='state_xyz',
		)
		assert success is True
		assert checked_in is True
		assert user_data['id'] == 123
		assert message == '登录成功'
