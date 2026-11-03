from urllib.parse import parse_qs, urlparse

import httpx

from utils.headers import get_browser_headers


class AgentRouterOAuthClient:
	"""AgentRouter OAuth helper."""

	def __init__(self, domain: str):
		self.domain = domain.rstrip('/')

	def fetch_oauth_state(self, client: httpx.Client) -> str:
		"""获取 OAuth state（不同部署路径存在差异，逐个尝试）。"""
		last_error = 'unknown error'
		headers = get_browser_headers(domain=self.domain)

		for path in ('/api/user/oauth/state', '/api/oauth/state', '/api/auth/state'):
			url = f'{self.domain}{path}'
			try:
				resp = client.get(url, headers=headers, timeout=30)
			except Exception as e:
				last_error = str(e)
				continue

			state = self._extract_state(resp)
			if state:
				return state
			last_error = self._extract_error(resp) or f'HTTP {resp.status_code}'

		raise RuntimeError(f'Unable to fetch oauth state: {last_error}')

	def authorize_github(self, github_session: str, state: str, *, proxy_url: str | None = None) -> str:
		"""使用 GitHub 会话获取 OAuth code。"""
		return self._authorize_via_service_or_redirect(
			provider='github',
			session_token=github_session,
			session_cookie_name='user_session',
			state=state,
			proxy_url=proxy_url,
		)

	def authorize_linuxdo(self, linuxdo_session: str, state: str, *, proxy_url: str | None = None) -> str:
		"""使用 Linux.do 会话获取 OAuth code。"""
		return self._authorize_via_service_or_redirect(
			provider='linuxdo',
			session_token=linuxdo_session,
			session_cookie_name='_forum_session',
			state=state,
			proxy_url=proxy_url,
		)

	def callback_login(
		self,
		client: httpx.Client,
		*,
		provider: str,
		code: str,
		state: str,
	) -> tuple[bool, dict, bool, str]:
		"""回调服务端完成登录并返回签到结果。"""
		payload = {'provider': provider, 'code': code, 'state': state}
		headers = get_browser_headers(domain=self.domain)
		headers['Content-Type'] = 'application/json'

		last_error = 'unknown error'
		for path in ('/api/user/oauth/callback', '/api/oauth/callback', '/api/auth/callback'):
			url = f'{self.domain}{path}'
			try:
				resp = client.post(url, headers=headers, json=payload, timeout=30)
			except Exception as e:
				last_error = str(e)
				continue

			success, user_data, checked_in, msg = self._parse_callback_response(resp)
			if success:
				return True, user_data, checked_in, msg
			last_error = msg

		return False, {}, False, last_error

	def _authorize_via_service_or_redirect(
		self,
		*,
		provider: str,
		session_token: str,
		session_cookie_name: str,
		state: str,
		proxy_url: str | None,
	) -> str:
		"""优先调用服务端授权端点，失败后再尝试直连 OAuth 重定向。"""
		headers = get_browser_headers(domain=self.domain)
		headers['Content-Type'] = 'application/json'

		for path in ('/api/user/oauth/authorize', '/api/oauth/authorize'):
			url = f'{self.domain}{path}'
			try:
				resp = httpx.post(
					url,
					headers=headers,
					json={
						'provider': provider,
						'state': state,
						'session': session_token,
					},
					timeout=30,
					proxy=proxy_url,
				)
			except Exception:
				continue

			code = self._extract_code_from_json(resp)
			if code:
				return code

		# 兼容部分部署仅支持 GET 重定向授权
		redirect_url = f'{self.domain}/auth/{provider}?state={state}'
		resp = httpx.get(
			redirect_url,
			headers=get_browser_headers(domain=redirect_url),
			cookies={session_cookie_name: session_token},
			follow_redirects=False,
			timeout=30,
			proxy=proxy_url,
		)
		location = resp.headers.get('location', '')
		code = self._extract_code_from_url(location)
		if code:
			return code

		raise RuntimeError(f'Unable to get OAuth code for {provider}')

	@staticmethod
	def _extract_state(resp: httpx.Response) -> str | None:
		if resp.status_code != 200:
			return None
		try:
			data = resp.json()
		except Exception:
			return None

		candidates = []
		if isinstance(data, dict):
			candidates.extend(
				[
					data.get('state'),
					(data.get('data') or {}).get('state') if isinstance(data.get('data'), dict) else None,
					(data.get('data') or {}).get('oauth_state') if isinstance(data.get('data'), dict) else None,
					(data.get('data') or {}).get('signature') if isinstance(data.get('data'), dict) else None,
				]
			)

		for item in candidates:
			if isinstance(item, str) and item.strip():
				return item.strip()
		return None

	@staticmethod
	def _extract_error(resp: httpx.Response) -> str:
		try:
			data = resp.json()
		except Exception:
			return f'HTTP {resp.status_code}'

		if not isinstance(data, dict):
			return f'HTTP {resp.status_code}'
		return str(
			data.get('message')
			or data.get('msg')
			or data.get('error')
			or data.get('detail')
			or f'HTTP {resp.status_code}'
		)

	@staticmethod
	def _extract_code_from_json(resp: httpx.Response) -> str | None:
		if resp.status_code != 200:
			return None
		try:
			data = resp.json()
		except Exception:
			return None

		if not isinstance(data, dict):
			return None
		if isinstance(data.get('code'), str) and data['code']:
			return data['code']
		payload = data.get('data')
		if isinstance(payload, dict) and isinstance(payload.get('code'), str) and payload['code']:
			return payload['code']
		return None

	@staticmethod
	def _extract_code_from_url(url: str) -> str | None:
		if not url:
			return None
		try:
			query = parse_qs(urlparse(url).query)
		except Exception:
			return None
		values = query.get('code')
		return values[0] if values and values[0] else None

	def _parse_callback_response(self, resp: httpx.Response) -> tuple[bool, dict, bool, str]:
		if resp.status_code != 200:
			return False, {}, False, f'HTTP {resp.status_code}'

		try:
			data = resp.json()
		except Exception:
			return False, {}, False, 'Invalid callback response'

		if not isinstance(data, dict):
			return False, {}, False, 'Invalid callback response payload'

		success = bool(data.get('success') or data.get('ret') == 1 or data.get('code') == 0)
		msg = str(data.get('message') or data.get('msg') or '')
		payload = data.get('data')
		user_data = payload if isinstance(payload, dict) else {}
		checked_in = bool(user_data.get('checked_in'))
		if not checked_in and msg:
			msg_lower = msg.lower()
			checked_in = any(word in msg_lower for word in ('签到成功', 'check-in', 'checked in', 'signed in'))

		if not success:
			return False, user_data, checked_in, msg or 'OAuth callback failed'
		return True, user_data, checked_in, msg or 'ok'
