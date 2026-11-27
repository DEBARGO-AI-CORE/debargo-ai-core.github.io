// site/passkey/client.js
//
//	Open the passkey page on a phone and tap Register, Approve, or Start session.
//
//***HEADER **********************************************************************************
//
//	PURPOSE:	RUN THE PHONE PAGE: REGISTER A
//			DEVICE, APPROVE ONE ACTIVITY, OR
//			START A VERIFIED SESSION.
//
//	NOTES:		THIS FILE IS THE STATIC PAGE ON
//			GITHUB PAGES. IT CALLS THE PUBLIC
//			PASSKEY FUNCTION FOR JSON ONLY.
//			IT DOES NOT HOLD A SERVICE KEY,
//			AN ADMIN TOKEN, OR AN ANON KEY.
//			A FINGERPRINT NEVER LEAVES THE
//			PHONE. REF REQ-20261126-PASSKEY.
//			REF REQ-20261127-PASSKEY-PAGES.
//
//********************************************************************************************

//	STEP 1	THE PUBLIC FUNCTION URL. THIS IS NOT A SECRET.

const PASSKEY_API_URL = 'https://wozqvuyjrgixijhpcbzu.supabase.co/functions/v1/passkey';

//	STEP 2	CONVERT BASE64URL FOR THE BROWSER WEBAUTHN CALLS

function bytesToBase64Url(bytes) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = '';
  for (let index = 0; index < view.length; index += 1) {
    binary += String.fromCharCode(view[index]);
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

function base64UrlToBytes(value) {
  const text = String(value || '');
  const padded = text + '='.repeat((4 - (text.length % 4)) % 4);
  const binary = atob(padded.replaceAll('-', '+').replaceAll('_', '/'));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function friendlyReason(reason) {
  switch (reason) {
    case 'expired':
      return 'This request timed out. Ask for a new link.';
    case 'used':
      return 'This request was already used.';
    case 'missing':
      return 'This link is not one we issued.';
    case 'counter':
      return 'This phone key did not match the one we have. Try the phone you registered.';
    case 'purpose':
      return 'This link is for a different action.';
    case 'session_required':
      return 'Start a session on a phone that already has a key, then add this phone as a backup.';
    case 'no_credential':
      return 'Register this phone first.';
    case 'credential':
      return 'This phone is not registered, or it was turned off.';
    case 'decision':
      return 'Choose approve or reject.';
    case 'label':
      return 'Give this phone a short name.';
    case 'summary':
      return 'Say what is being approved, in a short sentence.';
    case 'transport':
      return 'This phone sent a connection type we do not use.';
    case 'session':
      return 'That session is no longer active.';
    default:
      return 'We could not finish that. Try again.';
  }
}

const SESSION_KEY = 'debargo_passkey_session';

function readSession() {
  try {
    return sessionStorage.getItem(SESSION_KEY) || '';
  } catch (_error) {
    return '';
  }
}

function writeSession(value) {
  try {
    if (value) {
      sessionStorage.setItem(SESSION_KEY, value);
    } else {
      sessionStorage.removeItem(SESSION_KEY);
    }
  } catch (_error) {
    // The page still works for a single approval without storing a session.
  }
}

//	STEP 3	CALL THE EDGE FUNCTION AND THE PHONE AUTHENTICATOR

async function postAction(body) {
  const response = await fetch(PASSKEY_API_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const payload = await response.json();
  if (!response.ok || payload.ok === false) {
    const message = payload.message || 'We hit a problem and we\'re on it.';
    const error = new Error(message);
    error.payload = payload;
    throw error;
  }
  if (payload.accepted === false) {
    const error = new Error(friendlyReason(payload.reason));
    error.payload = payload;
    throw error;
  }
  return payload;
}

function creationRequest(options) {
  const publicKey = {
    ...options,
    challenge: base64UrlToBytes(options.challenge),
    user: {
      ...options.user,
      id: base64UrlToBytes(options.user.id),
    },
    excludeCredentials: (options.excludeCredentials || []).map((item) => ({
      ...item,
      id: base64UrlToBytes(item.id),
    })),
  };
  return navigator.credentials.create({ publicKey });
}

function requestRequest(options) {
  const publicKey = {
    ...options,
    challenge: base64UrlToBytes(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((item) => ({
      ...item,
      id: base64UrlToBytes(item.id),
    })),
  };
  return navigator.credentials.get({ publicKey });
}

function credentialToJson(credential) {
  const response = credential.response;
  const json = {
    id: credential.id,
    rawId: bytesToBase64Url(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults
      ? credential.getClientExtensionResults()
      : {},
    response: {},
  };
  if (credential.authenticatorAttachment) {
    json.authenticatorAttachment = credential.authenticatorAttachment;
  }
  if (response.attestationObject) {
    json.response = {
      clientDataJSON: bytesToBase64Url(response.clientDataJSON),
      attestationObject: bytesToBase64Url(response.attestationObject),
    };
    if (response.getTransports) {
      json.response.transports = response.getTransports();
    }
  } else {
    json.response = {
      clientDataJSON: bytesToBase64Url(response.clientDataJSON),
      authenticatorData: bytesToBase64Url(response.authenticatorData),
      signature: bytesToBase64Url(response.signature),
    };
    if (response.userHandle) {
      json.response.userHandle = bytesToBase64Url(response.userHandle);
    }
  }
  return json;
}

//	STEP 4	WIRE THE THREE ACTIONS ON THE PAGE

function setStatus(text, isError) {
  const node = document.querySelector('#status');
  node.textContent = text;
  node.className = isError ? 'status error' : 'status';
}

function show(id) {
  document.querySelector(id).hidden = false;
}

async function registerDevice(challenge) {
  //	STEP 1	ASK FOR OPTIONS, THEN THE FINGERPRINT PROMPT
  const label = document.querySelector('#device-label').value.trim();
  const options = await postAction({
    action: 'register-options',
    device_label: label,
    challenge: challenge || undefined,
    session_id: readSession() || undefined,
  });
  const credential = await creationRequest(options.options);
  await postAction({
    action: 'register-verify',
    device_label: label,
    challenge: options.challenge,
    response: credentialToJson(credential),
  });
  setStatus('This phone is registered. You can approve requests and start a session with it.');
}

async function approve(decision) {
  const params = new URLSearchParams(location.search);
  const activityId = params.get('activity_id');
  const challenge = params.get('challenge');
  const options = await postAction({
    action: 'approve-options',
    activity_id: Number(activityId),
    challenge,
  });
  const credential = await requestRequest(options.options);
  await postAction({
    action: 'approve-verify',
    activity_id: Number(activityId),
    challenge,
    decision,
    response: credentialToJson(credential),
  });
  setStatus(decision === 'approve'
    ? 'Approved. You can close this page.'
    : 'Rejected. You can close this page.');
}

async function startSession() {
  const options = await postAction({ action: 'session-options' });
  const credential = await requestRequest(options.options);
  const result = await postAction({
    action: 'session-verify',
    challenge: options.challenge,
    response: credentialToJson(credential),
  });
  writeSession(result.session_id);
  const until = result.expires_at
    ? new Date(result.expires_at).toLocaleString('en-US', { timeZone: 'America/Chicago' })
    : 'later today';
  setStatus(`Session started on this phone until ${until} Central. You can add a backup phone from here.`);
  show('#backup');
}

async function backupLink() {
  const result = await postAction({
    action: 'backup-link',
    session_id: readSession(),
  });
  const link = document.querySelector('#backup-link');
  link.href = result.url;
  link.textContent = result.url;
  show('#backup-result');
  setStatus('Open that link on the other phone within 5 minutes.');
}

async function endSession() {
  const sessionId = readSession();
  if (!sessionId) {
    setStatus('There is no session on this phone.');
    return;
  }
  await postAction({ action: 'session-revoke', session_id: sessionId });
  writeSession('');
  setStatus('Session ended.');
}

function boot() {
  const params = new URLSearchParams(location.search);
  const purpose = params.get('purpose') || 'home';
  document.querySelector('#register').addEventListener('click', () => {
    registerDevice(params.get('challenge')).catch((error) => setStatus(error.message, true));
  });
  document.querySelector('#approve').addEventListener('click', () => {
    approve('approve').catch((error) => setStatus(error.message, true));
  });
  document.querySelector('#reject').addEventListener('click', () => {
    approve('reject').catch((error) => setStatus(error.message, true));
  });
  document.querySelector('#session').addEventListener('click', () => {
    startSession().catch((error) => setStatus(error.message, true));
  });
  document.querySelector('#backup-button').addEventListener('click', () => {
    backupLink().catch((error) => setStatus(error.message, true));
  });
  document.querySelector('#end-session').addEventListener('click', () => {
    endSession().catch((error) => setStatus(error.message, true));
  });

  if (purpose === 'approve') {
    show('#approve-panel');
    document.querySelector('#home-actions').hidden = true;
    postAction({
      action: 'approve-preview',
      activity_id: Number(params.get('activity_id')),
      challenge: params.get('challenge'),
    }).then((result) => {
      document.querySelector('#approve-summary').textContent = result.summary || 'A request is waiting.';
      const when = result.requested_at
        ? new Date(result.requested_at).toLocaleString('en-US', { timeZone: 'America/Chicago' })
        : '';
      document.querySelector('#approve-meta').textContent = [
        result.function_name ? `Action: ${result.function_name}` : '',
        result.activity_id ? `Activity ${result.activity_id}` : '',
        when ? `Logged ${when} Central` : '',
      ].filter(Boolean).join(' · ');
    }).catch((error) => setStatus(error.message, true));
  } else if (purpose === 'register') {
    document.querySelector('#device-label').value = 'Backup phone';
    setStatus('Name this phone, then use your fingerprint or Face ID.');
  } else if (readSession()) {
    show('#backup');
  }
}

if (typeof document !== 'undefined') {
  boot();
}

export {
  PASSKEY_API_URL,
  base64UrlToBytes,
  bytesToBase64Url,
  credentialToJson,
  friendlyReason,
};

//***HISTORY **********************************************************************************
//
//	DATE		REF #			CHANGE REASON
//	----------	----------		-----------------------------------------------------------------
//	2026-11-26	REQ-20261126-PASSKEY	INITIAL CREATION. PHONE PAGE FOR REGISTER, APPROVE, AND SESSION.
//	2026-11-27	REQ-20261127-PASSKEY-PAGES	CALL THE FUNCTION JSON API FROM THE
//						STATIC GITHUB PAGES PAGE.
//
//********************************************************************************************
