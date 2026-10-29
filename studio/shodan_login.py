"""Credential submission is restricted to Shodan's own top-level login form."""
import json
from .shodan_accounts import credentials
from .browser_session import facet_url

LOGIN_URL = 'https://account.shodan.io/login'

# Values are assigned as data, never interpreted as selectors or JavaScript.
# Keep the server-rendered form and hidden CSRF fields intact.
LOGIN_FUNCTION = r'''(data) => {
  if (window !== window.top || location.origin !== 'https://account.shodan.io' ||
      !['/login','/login/'].includes(location.pathname)) return 'not_login_page';
  const candidates = [...document.forms].filter(form => {
    const u = form.querySelector('input[name="username"]');
    const p = form.querySelector('input[name="password"][type="password"]');
    return u && p && !u.disabled && !p.disabled && !u.readOnly && !p.readOnly &&
           u.getClientRects().length && p.getClientRects().length;
  });
  if (candidates.length !== 1) return 'verification_required';
  const form = candidates[0], target = new URL(form.action || location.href, location.href);
  if (target.origin !== location.origin || !['/login','/login/'].includes(target.pathname) ||
      target.username || target.password || form.method.toLowerCase() !== 'post' ||
      (form.target && form.target !== '_self')) return 'unsafe_form';
  for (const name of ['username','password']) {
    const input = form.querySelector(`input[name="${name}"]`);
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, data[name]);
    input.dispatchEvent(new Event('input', {bubbles:true}));
    input.dispatchEvent(new Event('change', {bubbles:true}));
  }
  if (!form.checkValidity()) return 'verification_required';
  // No submitter override (formaction/formmethod/formtarget) may redirect secrets.
  HTMLFormElement.prototype.requestSubmit.call(form);
  return 'submitted';
}'''


def login_payload(data):
    if not isinstance(data, dict) or set(data) != {'action','username','password','return_url'} or data['action'] != 'login':
        raise ValueError('طلب تسجيل الدخول غير صالح.')
    username, password = credentials(data['username'], data['password'])
    facet_url(data['return_url'])
    return {'username':username, 'password':password}


def login_expression(data):
    return '(' + LOGIN_FUNCTION + ')(' + json.dumps(login_payload(data)) + ')'
