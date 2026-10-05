// Samba Conductor: the only script of the application. It is loaded only
// by the second-factor pages (sign-in 2FA, enrollment, security keys,
// re-authentication) and the page that shows a generated password once,
// with a per-response CSP nonce and Subresource Integrity. It makes no
// network request of its own: it reads the ceremony options the server
// rendered into the form (data-options), calls the browser's WebAuthn API,
// writes the result into the form's hidden "response" field and submits
// the form like any other. On the password page it only shows a copy
// button (data-copy names the field; hidden without the script) that puts
// the field's value on the clipboard.
(function () {
  'use strict';

  function b64uToBuf(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) {
      s += '=';
    }
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out.buffer;
  }

  function bufToB64u(buf) {
    if (!buf) {
      return null;
    }
    var b = new Uint8Array(buf);
    var s = '';
    for (var i = 0; i < b.length; i++) {
      s += String.fromCharCode(b[i]);
    }
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function creationOptions(o) {
    var p = o.publicKey;
    p.challenge = b64uToBuf(p.challenge);
    p.user.id = b64uToBuf(p.user.id);
    (p.excludeCredentials || []).forEach(function (c) { c.id = b64uToBuf(c.id); });
    return { publicKey: p };
  }

  function requestOptions(o) {
    var p = o.publicKey;
    p.challenge = b64uToBuf(p.challenge);
    (p.allowCredentials || []).forEach(function (c) { c.id = b64uToBuf(c.id); });
    return { publicKey: p };
  }

  function attestationJSON(c) {
    var r = c.response;
    return {
      id: c.id,
      rawId: bufToB64u(c.rawId),
      type: c.type,
      authenticatorAttachment: c.authenticatorAttachment || undefined,
      clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {},
      response: {
        clientDataJSON: bufToB64u(r.clientDataJSON),
        attestationObject: bufToB64u(r.attestationObject),
        transports: r.getTransports ? r.getTransports() : []
      }
    };
  }

  function assertionJSON(c) {
    var r = c.response;
    return {
      id: c.id,
      rawId: bufToB64u(c.rawId),
      type: c.type,
      authenticatorAttachment: c.authenticatorAttachment || undefined,
      clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {},
      response: {
        clientDataJSON: bufToB64u(r.clientDataJSON),
        authenticatorData: bufToB64u(r.authenticatorData),
        signature: bufToB64u(r.signature),
        userHandle: bufToB64u(r.userHandle)
      }
    };
  }

  function showError(form) {
    var el = form.querySelector('[data-webauthn-error]');
    if (el) {
      el.hidden = false;
    }
  }

  function start(form) {
    var mode = form.getAttribute('data-webauthn');
    var options = JSON.parse(form.getAttribute('data-options'));
    var field = form.querySelector('input[name="response"]');
    var name = form.querySelector('input[name="name"]');
    if (name && !name.reportValidity()) {
      return;
    }
    var pass = form.querySelector('input[name="password"]');
    if (pass && !pass.reportValidity()) {
      return;
    }
    var p = mode === 'register'
      ? navigator.credentials.create(creationOptions(options)).then(attestationJSON)
      : navigator.credentials.get(requestOptions(options)).then(assertionJSON);
    p.then(function (result) {
      field.value = JSON.stringify(result);
      form.submit();
    }, function () {
      showError(form);
    });
  }

  function setupCopy(btn) {
    var field = document.getElementById(btn.getAttribute('data-copy'));
    if (!field || !navigator.clipboard) {
      return;
    }
    btn.hidden = false;
    btn.addEventListener('click', function () {
      navigator.clipboard.writeText(field.value).then(function () {
        btn.textContent = btn.getAttribute('data-copied');
      }, function () {
        field.select();
      });
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    var copies = document.querySelectorAll('button[data-copy]');
    for (var c = 0; c < copies.length; c++) {
      setupCopy(copies[c]);
    }
    var forms = document.querySelectorAll('form[data-webauthn]');
    for (var i = 0; i < forms.length; i++) {
      (function (form) {
        var btn = form.querySelector('[data-webauthn-start]');
        if (!btn) {
          return;
        }
        if (!window.PublicKeyCredential || !navigator.credentials) {
          var un = form.querySelector('[data-webauthn-unsupported]');
          if (un) {
            un.hidden = false;
          }
          btn.disabled = true;
          return;
        }
        btn.disabled = false;
        btn.addEventListener('click', function () { start(form); });
      })(forms[i]);
    }
  });
})();
