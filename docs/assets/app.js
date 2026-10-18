(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const form = $('result-form');
  const alertBox = $('alert');
  const result = $('result');
  const data = window.ENCRYPTED_RESULTS;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const digits = (value) => String(value || '').replace(/\D/g, '');
  const showMessage = (message) => { alertBox.textContent = message; alertBox.hidden = !message; };
  const bytesToHex = (bytes) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  const fromBase64 = (value) => Uint8Array.from(atob(value), c => c.charCodeAt(0));
  const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));

  $('student-id').addEventListener('input', () => {
    $('student-id').value = digits($('student-id').value).slice(0, 10);
  });

  const lookup = async (id) => {
    const base = await crypto.subtle.importKey('raw', encoder.encode(id), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', iterations: data.iterations, salt: fromBase64(data.salt) },
      base, 256
    );
    const seed = new Uint8Array(bits);
    const concatenated = (prefix) => {
      const a = encoder.encode(prefix);
      const out = new Uint8Array(a.length + seed.length);
      out.set(a);
      out.set(seed, a.length);
      return out;
    };
    const index = bytesToHex(await sha256(concatenated('HEBREW-ACA-LOOKUP-2026|')));
    const match = data.entries[index];
    if (!match) return null;
    const keyBytes = await sha256(concatenated('HEBREW-ACA-AES-2026|'));
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
    try {
      const plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: fromBase64(match.iv) }, key, fromBase64(match.ct)
      );
      const student = JSON.parse(decoder.decode(plain));
      if (student.id !== id || !['בתכנית', 'לא בתכנית'].includes(student.status)) return null;
      return student;
    } catch (_) { return null; }
  };

  const showResult = (student) => {
    $('out-name').textContent = student.name;
    $('out-id').textContent = student.id;
    const enrolled = student.status === 'בתכנית';
    $('out-status').textContent = student.status;
    $('out-status').className = 'status-pill ' + (enrolled ? 'accepted' : 'not-accepted');
    result.hidden = false;
    showMessage('');
    result.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  };

  $('reset-btn').addEventListener('click', () => {
    result.hidden = true;
    form.reset();
    $('student-id').focus();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    result.hidden = true;
    showMessage('');
    const id = digits($('student-id').value);
    if (!/^\d{9,10}$/.test(id)) {
      showMessage('יש להזין מספר זהות מלא בן 9 או 10 ספרות.');
      return;
    }
    if (!data || data.version !== 2 || !data.entries || !globalThis.crypto?.subtle) {
      showMessage('לא ניתן לפתוח את המידע בדפדפן זה. יש לפתוח את האתר ב-HTTPS בדפדפן עדכני.');
      return;
    }
    const button = $('submit-btn');
    button.disabled = true;
    button.querySelector('span').textContent = 'בודק/ת פרטים...';
    try {
      const student = await lookup(id);
      if (!student) {
        showMessage('לא נמצאה תוצאה למספר הזהות שהוזן. יש לבדוק את המספר או לפנות לבית הספר.');
        return;
      }
      showResult(student);
    } catch (_) {
      showMessage('אירעה תקלה בפתיחת התוצאה. נא לרענן את הדף ולנסות שוב.');
    } finally {
      button.disabled = false;
      button.querySelector('span').textContent = 'הצגת התוצאה';
    }
  });
})();
