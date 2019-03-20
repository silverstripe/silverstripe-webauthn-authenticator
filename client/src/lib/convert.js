export const base64ToByteArray = string =>
  Uint8Array.from(atob(string), c => c.charCodeAt(0));

export const byteArrayToBase64 = byteArray =>
  btoa(String.fromCharCode(...(new Uint8Array(byteArray))));
